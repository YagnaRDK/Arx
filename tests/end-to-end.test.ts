import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";

/*
 * The whole path, over HTTP, in-process.
 *
 * Everything else in this suite tests a control in isolation. This file tests
 * the ordering: an agent authenticates, an operator grants authority, a
 * transaction is authorized, a device signs it once, and the approval is spent.
 * Fastify's `inject` is used rather than a listening port so the test is
 * hermetic — no free port to find, no process to reap.
 *
 * The server is configured the way production should be, not the way the demo
 * runs: agent HMAC enforced, a control-plane token set, and SIGNER_MODE=sim so
 * the signature is a real secp256k1 signature that must recover to the device
 * address (a MOCK signature would make the signing assertions meaningless).
 */
process.env.NODE_ENV = "test";
process.env.DATABASE_PATH ??= "./.test-data/arx-suite.sqlite";
process.env.ARX_ADMIN_TOKEN ??= "e2e-operator-token";
process.env.ARX_REQUIRE_AGENT_AUTH ??= "1";
process.env.SIGNER_MODE ??= "sim";
process.env.ARX_DASHBOARD ??= "0";

const ADMIN_TOKEN = "e2e-operator-token";

const { env } = await import("../src/config/env");

/*
 * `bun test` shares one module registry across files, so another test file may
 * already have evaluated `src/config/env` from a different environment. These
 * four values are read when `buildServer()` constructs its authenticators and
 * its signer, so overriding the object immediately before that call is what
 * actually configures this server. Applied in `beforeAll` and undone in
 * `afterAll`, so the override is confined to this file's own window.
 */
const OVERRIDES = {
  adminToken: ADMIN_TOKEN,
  requireAgentAuth: true,
  signerMode: "sim",
  dashboardEnabled: false,
} as const;

const originalEnv = {
  adminToken: env.adminToken,
  requireAgentAuth: env.requireAgentAuth,
  signerMode: env.signerMode,
  dashboardEnabled: env.dashboardEnabled,
};

const { resetDatabaseForTests } = await import("../src/db/database");
const { buildServer } = await import("../src/api/server");
const { ADMIN_HEADER } = await import("../src/auth/admin-auth");
const { AGENT_HEADERS, signRequestWithSecret } = await import(
  "../src/auth/agent-auth"
);
const { CapabilitySchema } = await import("../src/types/capability");

type App = Awaited<ReturnType<typeof buildServer>>;

let app: App;

const PAYEE = "0x1111111111111111111111111111111111111111";
/** The address an injected instruction would try to substitute. */
const ATTACKER = "0x2222222222222222222222222222222222222222";

const AGENT_ID = "e2e-agent";
const OTHER_AGENT_ID = "e2e-other-agent";

let agentSecret = "";
let otherAgentSecret = "";

const nowSeconds = () => Math.floor(Date.now() / 1000);

/** 0.01 ETH. $32.00 at the static table's $3,200/ETH. */
const TRANSFER = {
  chainId: 11_155_111,
  to: PAYEE,
  value: "10000000000000000",
  data: "0x",
  gasLimit: "21000",
  maxFeePerGas: "30000000000",
  maxPriorityFeePerGas: "1000000000",
  nonce: 0,
  type: "eip1559" as const,
};

function capabilityBody(overrides: Record<string, unknown> = {}) {
  return CapabilitySchema.parse({
    capabilityId: `cap-${crypto.randomUUID()}`,
    agentId: AGENT_ID,

    allowedActions: ["TRANSFER"],
    allowedProtocols: ["NATIVE"],
    allowedChains: [11_155_111],
    allowedTokens: { input: ["ETH"], output: ["ETH"] },

    maxAmountUsd: 1_000,
    maxSlippageBps: 0,

    expiresAt: nowSeconds() + 3_600,
    nonce: 1,

    status: "ACTIVE",
    usage: "REUSABLE",

    recipients: { mode: "ALLOWLIST", allow: [PAYEE], deny: [] },
    contracts: { mode: "ALLOWLIST", allow: [], deny: [] },
    methods: { mode: "ALLOWLIST", allow: [], deny: [] },
    limits: {
      maxValueWei: "1000000000000000000",
      maxGasLimit: "500000",
      maxFeePerGasWei: "500000000000",
    },

    ...overrides,
  });
}

function intentBody(
  capabilityId: string,
  overrides: Record<string, unknown> = {},
) {
  return {
    capabilityId,
    agentId: AGENT_ID,
    action: "TRANSFER",
    protocol: "NATIVE",
    chainId: 11_155_111,
    inputToken: "ETH",
    outputToken: "ETH",
    amountUsd: 32,
    slippageBps: 0,
    nonce: 2,
    timestamp: nowSeconds(),
    transaction: TRANSFER,
    ...overrides,
  };
}

/** An admin-authenticated request. */
async function asOperator(
  method: "POST" | "GET",
  url: string,
  payload?: unknown,
  token: string = ADMIN_TOKEN,
) {
  return app.inject({
    method,
    url,
    headers: {
      [ADMIN_HEADER]: token,
      // Only when there is a body: Fastify rejects an empty body that claims to
      // be JSON, and that rejection is not an ArxError.
      ...(payload === undefined ? {} : { "content-type": "application/json" }),
    },
    ...(payload === undefined ? {} : { payload: payload as object }),
  });
}

/** An HMAC-signed agent request against exactly the documented signing string. */
async function asAgent(
  method: "POST" | "GET",
  url: string,
  body: unknown,
  credentials: { agentId: string; secret: string } = {
    agentId: AGENT_ID,
    secret: agentSecret,
  },
) {
  const timestamp = nowSeconds();
  const nonce = `n-${crypto.randomUUID()}`;

  const signature = signRequestWithSecret(
    credentials.agentId,
    credentials.secret,
    { method, path: url, timestamp, nonce, body },
  );

  return app.inject({
    method,
    url,
    headers: {
      "content-type": "application/json",
      [AGENT_HEADERS.agent]: credentials.agentId,
      [AGENT_HEADERS.timestamp]: String(timestamp),
      [AGENT_HEADERS.nonce]: nonce,
      [AGENT_HEADERS.signature]: signature,
    },
    ...(body === undefined ? {} : { payload: body as object }),
  });
}

function json(response: { body: string }): Record<string, unknown> {
  return JSON.parse(response.body) as Record<string, unknown>;
}

beforeAll(async () => {
  Object.assign(env as unknown as Record<string, unknown>, OVERRIDES);

  app = await buildServer();
  await app.ready();
});

afterAll(async () => {
  await app.close();
  Object.assign(env as unknown as Record<string, unknown>, originalEnv);
});

beforeEach(async () => {
  resetDatabaseForTests();

  const registered = json(
    await asOperator("POST", "/agents", { agentId: AGENT_ID, label: "e2e" }),
  ) as { secret: string };
  agentSecret = registered.secret;

  const other = json(
    await asOperator("POST", "/agents", { agentId: OTHER_AGENT_ID }),
  ) as { secret: string };
  otherAgentSecret = other.secret;
});

/** Creates a capability and returns its id. */
async function grant(overrides: Record<string, unknown> = {}): Promise<string> {
  const body = capabilityBody(overrides);
  const response = await asOperator("POST", "/capabilities", body);

  expect(response.statusCode).toBe(201);

  return body.capabilityId;
}

describe("the full path: create capability, approve, sign, refuse the replay", () => {
  it("walks it end to end", async () => {
    const capabilityId = await grant();

    // --- authorize -------------------------------------------------------
    const authorization = await asAgent(
      "POST",
      "/approvals",
      intentBody(capabilityId),
    );

    expect(authorization.statusCode).toBe(201);

    const authorized = json(authorization) as {
      status: string;
      decision: string;
      approval: { approvalId: string; transactionHash: string };
      valueUsd: number;
      declaredValueUsd: number;
    };

    expect(authorized.status).toBe("APPROVED");
    expect(authorized.decision).toBe("ALLOW");
    // The USD figure that was checked came from the oracle, not the claim.
    expect(authorized.valueUsd).toBeCloseTo(32, 6);
    expect(authorized.declaredValueUsd).toBe(32);

    const approvalId = authorized.approval.approvalId;

    // --- sign ------------------------------------------------------------
    const signing = await asAgent("POST", "/sign", {
      approvalId,
      transaction: TRANSFER,
    });

    expect(signing.statusCode).toBe(200);

    const signed = json(signing) as {
      status: string;
      signatureType: string;
      signatureVerified: boolean;
      signedTransaction: string;
      signer: { address: string; mode: string };
    };

    expect(signed.status).toBe("SIGNED");
    // `sim` produces a real secp256k1 signature over the real RLP; the signer
    // service refuses to return one that does not recover to the device address.
    expect(signed.signatureType).toBe("REAL");
    expect(signed.signatureVerified).toBe(true);
    expect(signed.signedTransaction).toMatch(/^0x02/);

    // --- replay ----------------------------------------------------------
    const replay = await asAgent("POST", "/sign", {
      approvalId,
      transaction: TRANSFER,
    });

    expect(replay.statusCode).toBe(409);
    expect(json(replay).code).toBe("APPROVAL_ALREADY_CONSUMED");

    // --- the trail -------------------------------------------------------
    const audit = json(await asOperator("GET", "/audit/verify"));

    expect(audit.valid).toBe(true);

    const approval = json(
      await asOperator("GET", `/approvals/${approvalId}`),
    ) as { approval: { status: string }; trail: Array<{ event_type?: string }> };

    expect(approval.approval.status).toBe("CONSUMED");
    expect(approval.trail.length).toBeGreaterThan(0);
  });

  it("refuses a transaction whose bytes were mutated after approval", async () => {
    // Invariant 3: the transaction signed is byte-identical to the one approved.
    const capabilityId = await grant();

    const authorized = json(
      await asAgent("POST", "/approvals", intentBody(capabilityId)),
    ) as { approval: { approvalId: string } };

    const mutated = await asAgent("POST", "/sign", {
      approvalId: authorized.approval.approvalId,
      transaction: { ...TRANSFER, to: ATTACKER },
    });

    expect(mutated.statusCode).toBe(403);
    expect(json(mutated).code).toBe("TRANSACTION_HASH_MISMATCH");
  });

  it("refuses to sign once the granting capability is revoked", async () => {
    // The approval is still valid on its own terms; the authority behind it is
    // not.
    const capabilityId = await grant();

    const authorized = json(
      await asAgent("POST", "/approvals", intentBody(capabilityId)),
    ) as { approval: { approvalId: string } };

    expect(
      (await asOperator("POST", `/capabilities/${capabilityId}/revoke`))
        .statusCode,
    ).toBe(200);

    const refused = await asAgent("POST", "/sign", {
      approvalId: authorized.approval.approvalId,
      transaction: TRANSFER,
    });

    expect(refused.statusCode).toBe(403);
    expect(json(refused).code).toBe("CAPABILITY_REVOKED");
  });

  it("replays one decision for a retried intentId instead of authorizing twice", async () => {
    const capabilityId = await grant();
    const intent = intentBody(capabilityId, { intentId: "invoice-2291" });

    const first = await asAgent("POST", "/approvals", intent);
    const retry = await asAgent("POST", "/approvals", intent);

    expect(first.statusCode).toBe(201);
    expect(retry.headers["x-arx-idempotent-replay"]).toBe("true");

    const firstBody = json(first) as { approval: { approvalId: string } };
    const retryBody = json(retry) as {
      approval: { approvalId: string };
      idempotentReplay: boolean;
    };

    expect(retryBody.idempotentReplay).toBe(true);
    expect(retryBody.approval.approvalId).toBe(firstBody.approval.approvalId);
  });

  it("refuses a reused intentId carrying a different payment", async () => {
    const capabilityId = await grant();

    await asAgent(
      "POST",
      "/approvals",
      intentBody(capabilityId, { intentId: "invoice-2291" }),
    );

    const conflicting = await asAgent(
      "POST",
      "/approvals",
      intentBody(capabilityId, {
        intentId: "invoice-2291",
        nonce: 3,
        amountUsd: 320,
        transaction: { ...TRANSFER, value: "100000000000000000" },
      }),
    );

    expect(conflicting.statusCode).toBe(409);
    expect(json(conflicting).code).toBe("INTENT_ID_CONFLICT");
  });

  it("refuses a replayed intent nonce", async () => {
    const capabilityId = await grant();

    expect(
      (await asAgent("POST", "/approvals", intentBody(capabilityId)))
        .statusCode,
    ).toBe(201);

    const replayed = await asAgent("POST", "/approvals", intentBody(capabilityId));

    expect(replayed.statusCode).toBe(409);
    expect(json(replayed).code).toBe("REPLAY_DETECTED");
  });
});

describe("prompt injection is refused at the authorization layer", () => {
  it("denies a well-formed payment to an address nobody authorized", async () => {
    /*
     * This is the headline case. The agent is behaving exactly as a
     * prompt-injected agent behaves: it proposes a syntactically perfect
     * transaction with every other field legitimate, and only the recipient
     * comes from the injected instruction. Nothing about the request looks
     * wrong; it is refused because the authority was never granted.
     */
    const capabilityId = await grant();

    const response = await asAgent(
      "POST",
      "/approvals",
      intentBody(capabilityId, {
        transaction: { ...TRANSFER, to: ATTACKER },
      }),
    );

    expect(response.statusCode).toBe(403);

    const body = json(response) as {
      code: string;
      reason: string;
      allowed: boolean;
      findings?: Array<{ severity: string; code: string }>;
    };

    expect(body.allowed).toBe(false);
    expect(body.code).toBe("RECIPIENT_NOT_ALLOWED");
    expect(body.reason).toContain(ATTACKER);

    // No approval was minted from the denial.
    const approvals = json(await asOperator("GET", "/approvals")) as {
      approvals: unknown[];
    };

    expect(approvals.approvals).toHaveLength(0);

    // And the denial is on the record, with its reason.
    const audit = json(await asOperator("GET", "/audit?limit=100")) as {
      entries: Array<{ code?: string; decision?: string }>;
    };

    expect(
      audit.entries.some((entry) => entry.code === "RECIPIENT_NOT_ALLOWED"),
    ).toBe(true);
    expect(json(await asOperator("GET", "/audit/verify")).valid).toBe(
      true,
    );
  });

  it("denies the same payment smuggled inside calldata", async () => {
    // Same attack, one layer down: `to` is an allowlisted token and the real
    // payee is the first calldata argument.
    const capabilityId = await grant({
      contracts: {
        mode: "ALLOWLIST",
        allow: ["0x1c7d4b196cb0c7b01d743fbc6116a902379c7238"],
        deny: [],
      },
      methods: {
        mode: "ALLOWLIST",
        allow: ["transfer(address,uint256)"],
        deny: [],
      },
    });

    const response = await asAgent(
      "POST",
      "/approvals",
      intentBody(capabilityId, {
        amountUsd: 25,
        transaction: {
          ...TRANSFER,
          to: "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238",
          value: "0",
          gasLimit: "120000",
          // transfer(ATTACKER, 25_000_000)
          data: `0xa9059cbb${ATTACKER.slice(2).padStart(64, "0")}${(25_000_000).toString(16).padStart(64, "0")}`,
        },
      }),
    );

    expect(response.statusCode).toBe(403);
    expect(json(response).code).toBe("CALLDATA_RECIPIENT_NOT_ALLOWED");
  });

  it("denies a declared value that the bytes do not support", async () => {
    const capabilityId = await grant();

    const response = await asAgent(
      "POST",
      "/approvals",
      intentBody(capabilityId, {
        amountUsd: 1,
        transaction: { ...TRANSFER, value: "900000000000000000" },
      }),
    );

    expect(response.statusCode).toBe(403);
    expect(json(response).code).toBe("VALUE_DECLARATION_MISMATCH");
  });
});

describe("the escalation path needs a human decision", () => {
  async function escalate(): Promise<{
    capabilityId: string;
    approvalId: string;
  }> {
    const capabilityId = await grant({
      humanApproval: { alwaysRequired: true },
    });

    const response = await asAgent(
      "POST",
      "/approvals",
      intentBody(capabilityId),
    );

    expect(response.statusCode).toBe(202);

    const body = json(response) as {
      status: string;
      decision: string;
      approval: { approvalId: string; approvalType: string };
    };

    expect(body.status).toBe("PENDING_HUMAN");
    expect(body.decision).toBe("ESCALATE");
    expect(body.approval.approvalType).toBe("HUMAN");

    return { capabilityId, approvalId: body.approval.approvalId };
  }

  it("refuses to sign a pending escalation, then signs once an operator grants it", async () => {
    const { approvalId } = await escalate();

    const early = await asAgent("POST", "/sign", {
      approvalId,
      transaction: TRANSFER,
    });

    expect(early.statusCode).toBe(202);
    expect(json(early).code).toBe("APPROVAL_PENDING_HUMAN");

    const queue = json(await asOperator("GET", "/approvals/pending")) as {
      approvals: Array<{ approvalId: string; summary?: { to: string } }>;
    };

    expect(queue.approvals.map((item) => item.approvalId)).toContain(approvalId);
    // An operator must be able to see who is being paid, not just a digest.
    expect(queue.approvals[0]?.summary?.to).toBe(PAYEE);

    const granted = await asOperator(
      "POST",
      `/approvals/${approvalId}/approve`,
      { decidedBy: "operator-e2e" },
    );

    expect(granted.statusCode).toBe(200);
    expect(
      (json(granted) as { approval: { status: string; decidedBy: string } })
        .approval,
    ).toMatchObject({ status: "APPROVED", decidedBy: "operator-e2e" });

    const signing = await asAgent("POST", "/sign", {
      approvalId,
      transaction: TRANSFER,
    });

    expect(signing.statusCode).toBe(200);
    expect(json(signing).signatureVerified).toBe(true);
  });

  it("refuses to sign an escalation an operator rejected", async () => {
    const { approvalId } = await escalate();

    const rejected = await asOperator(
      "POST",
      `/approvals/${approvalId}/reject`,
      { decidedBy: "operator-e2e", reason: "not a known supplier" },
    );

    expect(rejected.statusCode).toBe(200);

    const refused = await asAgent("POST", "/sign", {
      approvalId,
      transaction: TRANSFER,
    });

    expect(refused.statusCode).toBe(403);
    expect(json(refused).code).toBe("APPROVAL_REJECTED");
  });

  it("will not let the proposing agent resolve its own escalation", async () => {
    /*
     * Two independent layers. The route sits behind `requireAdmin`, so the
     * agent's HMAC credential is not accepted at all — and even a caller who
     * holds the admin token cannot record the agent as the decider.
     */
    const { approvalId } = await escalate();

    const asTheAgent = await asAgent(
      "POST",
      `/approvals/${approvalId}/approve`,
      { decidedBy: AGENT_ID },
    );

    expect(asTheAgent.statusCode).toBe(401);
    expect(json(asTheAgent).code).toBe("UNAUTHENTICATED");

    const selfNamed = await asOperator(
      "POST",
      `/approvals/${approvalId}/approve`,
      { decidedBy: AGENT_ID },
    );

    expect(selfNamed.statusCode).toBe(403);
    expect(json(selfNamed).code).toBe("FORBIDDEN");

    // Still parked, still unsigned.
    const still = await asAgent("POST", "/sign", {
      approvalId,
      transaction: TRANSFER,
    });

    expect(json(still).code).toBe("APPROVAL_PENDING_HUMAN");
  });
});

describe("one approval authorizes exactly one signature", () => {
  it("yields a single 200 from eight parallel signing requests", async () => {
    const capabilityId = await grant();

    const authorized = json(
      await asAgent("POST", "/approvals", intentBody(capabilityId)),
    ) as { approval: { approvalId: string } };

    const responses = await Promise.all(
      Array.from({ length: 8 }, async () =>
        asAgent("POST", "/sign", {
          approvalId: authorized.approval.approvalId,
          transaction: TRANSFER,
        }),
      ),
    );

    const statuses = responses.map((response) => response.statusCode);

    expect(statuses.filter((status) => status === 200)).toHaveLength(1);
    expect(statuses.filter((status) => status === 409)).toHaveLength(7);

    // Exactly one signature exists on the record.
    const audit = json(await asOperator("GET", "/audit?limit=200")) as {
      entries: Array<{ event_type?: string; eventType?: string }>;
    };

    const succeeded = audit.entries.filter(
      (entry) =>
        (entry.event_type ?? entry.eventType) === "SIGNING_SUCCEEDED",
    );

    expect(succeeded).toHaveLength(1);
    expect(json(await asOperator("GET", "/audit/verify")).valid).toBe(
      true,
    );
  });
});

describe("a rolling budget under parallel authorization", () => {
  it("admits only what the window has room for", async () => {
    /*
     * Sixteen authorization requests, each worth $32, against a window that
     * allows $40 and one transaction. Exactly one may be approved.
     *
     * Worth being precise about what this proves and what it does not. The
     * headroom comparison in `checkSpendWindows` happens earlier in the request
     * than `spendStore.reserve`, so the property depends on the second request
     * observing the first one's reservation. It holds here — and at 2, 4, 8 and
     * 16 parallel requests — because every await in the authorization path
     * resolves in a microtask with the static oracle. It is *not* guaranteed by
     * a database constraint, so a price oracle doing real network I/O is the
     * case to re-measure.
     */
    const capabilityId = await grant({
      limits: {
        maxValueWei: "1000000000000000000",
        maxGasLimit: "500000",
        maxFeePerGasWei: "500000000000",
        maxAmountUsdPerWindow: 40,
        maxTxPerWindow: 1,
        windowSeconds: 86_400,
      },
    });

    const responses = await Promise.all(
      Array.from({ length: 16 }, async (_, index) =>
        asAgent(
          "POST",
          "/approvals",
          intentBody(capabilityId, {
            nonce: index + 2,
            transaction: { ...TRANSFER, nonce: index + 2 },
          }),
        ),
      ),
    );

    expect(
      responses.filter((response) => response.statusCode === 201),
    ).toHaveLength(1);

    const spend = json(
      await asOperator("GET", `/capabilities/${capabilityId}`),
    ) as { spendWindow: { amountUsd: number; transactionCount: number } };

    expect(spend.spendWindow).toMatchObject({
      amountUsd: 32,
      transactionCount: 1,
    });

    // Every refusal names the budget rather than something vague.
    for (const response of responses.filter(
      (candidate) => candidate.statusCode !== 201,
    )) {
      expect(["SPEND_WINDOW_EXCEEDED", "TX_COUNT_WINDOW_EXCEEDED"]).toContain(
        String(json(response).code),
      );
    }
  });
});

describe("plane separation over HTTP", () => {
  it("refuses a control-plane route to a fully authenticated agent", async () => {
    /*
     * The agent's HMAC credential is valid — it is simply not a credential the
     * control plane accepts. Without this, a compromised agent would mint itself
     * a capability with unlimited authority and least privilege would be
     * decoration.
     */
    const minted = await asAgent(
      "POST",
      "/capabilities",
      capabilityBody({ maxAmountUsd: 1_000_000 }),
    );

    expect(minted.statusCode).toBe(401);
    expect(json(minted).code).toBe("UNAUTHENTICATED");

    expect(
      (json(await asOperator("GET", "/capabilities")) as {
        capabilities: unknown[];
      }).capabilities,
    ).toHaveLength(0);
  });

  it("refuses agent registration to an agent", async () => {
    const response = await asAgent("POST", "/agents", {
      agentId: "self-registered",
    });

    expect(response.statusCode).toBe(401);
  });

  it("refuses a wrong admin token", async () => {
    const response = await asOperator(
      "POST",
      "/capabilities",
      capabilityBody(),
      "not-the-token",
    );

    expect(response.statusCode).toBe(403);
    expect(json(response).code).toBe("FORBIDDEN");
  });

  it("refuses an unauthenticated data-plane request", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/approvals",
      headers: { "content-type": "application/json" },
      payload: intentBody("cap-does-not-exist"),
    });

    expect(response.statusCode).toBe(401);
    expect(json(response).code).toBe("UNAUTHENTICATED");
  });

  it("refuses agent A exercising agent B's capability", async () => {
    // Signed correctly as the other agent, but naming this agent in the body.
    const capabilityId = await grant();

    const response = await asAgent(
      "POST",
      "/approvals",
      intentBody(capabilityId),
      { agentId: OTHER_AGENT_ID, secret: otherAgentSecret },
    );

    expect(response.statusCode).toBe(403);
    expect(json(response).code).toBe("FORBIDDEN");
  });

  it("refuses an agent's capability being exercised by its own credentials for another agent's grant", async () => {
    // The capability belongs to OTHER_AGENT_ID; AGENT_ID authenticates as
    // itself and names itself, so the transport check passes and the
    // *capability* check is what refuses.
    const capabilityId = await grant({ agentId: OTHER_AGENT_ID });

    const response = await asAgent(
      "POST",
      "/approvals",
      intentBody(capabilityId),
    );

    expect(response.statusCode).toBe(403);
    expect(json(response).code).toBe("AGENT_MISMATCH");
  });

  it("refuses a replayed HTTP request verbatim", async () => {
    const capabilityId = await grant();
    const body = intentBody(capabilityId);
    const timestamp = nowSeconds();
    const nonce = "fixed-transport-nonce";

    const headers = {
      "content-type": "application/json",
      [AGENT_HEADERS.agent]: AGENT_ID,
      [AGENT_HEADERS.timestamp]: String(timestamp),
      [AGENT_HEADERS.nonce]: nonce,
      [AGENT_HEADERS.signature]: signRequestWithSecret(AGENT_ID, agentSecret, {
        method: "POST",
        path: "/approvals",
        timestamp,
        nonce,
        body,
      }),
    };

    const first = await app.inject({
      method: "POST",
      url: "/approvals",
      headers,
      payload: body,
    });
    const second = await app.inject({
      method: "POST",
      url: "/approvals",
      headers,
      payload: body,
    });

    expect(first.statusCode).toBe(201);
    expect(second.statusCode).toBe(409);
    expect(json(second).code).toBe("REPLAY_DETECTED");
  });
});

describe("the dry run consumes nothing", () => {
  it("reports the verdict without minting an approval or spending a nonce", async () => {
    const capabilityId = await grant();

    const preview = await asAgent(
      "POST",
      "/firewall/submit",
      intentBody(capabilityId),
    );

    expect(preview.statusCode).toBe(200);

    const body = json(preview) as { status: string; note: string };

    expect(body.status).toBe("READY_FOR_APPROVAL");
    expect(body.note).toContain("No approval was created");

    expect(
      (json(await asOperator("GET", "/approvals")) as {
        approvals: unknown[];
      }).approvals,
    ).toHaveLength(0);

    // The same nonce is still spendable, so the preview really cost nothing.
    expect(
      (await asAgent("POST", "/approvals", intentBody(capabilityId)))
        .statusCode,
    ).toBe(201);
  });

  it("reaches the same verdict as the committing route on the same input", async () => {
    // The two routes drifted once — one checked the transaction's chain against
    // the intent and the other did not. They now share one pipeline.
    const capabilityId = await grant();
    const injected = intentBody(capabilityId, {
      transaction: { ...TRANSFER, to: ATTACKER },
    });

    const preview = await asAgent("POST", "/firewall/submit", injected);
    const commit = await asAgent("POST", "/approvals", {
      ...injected,
      nonce: 3,
    });

    expect(json(preview).code).toBe(json(commit).code);
    expect(json(preview).decision).toBe("DENY");
  });
});

describe("the signer boundary labels itself honestly", () => {
  it("reports the signer mode and that the signature is real", async () => {
    const info = json(await app.inject({ method: "GET", url: "/signer" })) as {
      mode: string;
      signatureType: string;
      emulated?: boolean;
      warning?: string;
    };

    expect(info.mode).toBe("sim");
    expect(info.signatureType).toBe("REAL");
    // `sim` is honest about being an in-process emulation of the device.
    expect(info.emulated).toBe(true);
    expect(info.warning).toBeUndefined();
  });

  it("reports a verifiable audit chain on /health", async () => {
    const health = json(await app.inject({ method: "GET", url: "/health" })) as {
      status: string;
      signerMode: string;
      auditChain: { valid: boolean };
    };

    expect(health.status).toBe("ok");
    expect(health.signerMode).toBe("sim");
    expect(health.auditChain.valid).toBe(true);
  });
});
