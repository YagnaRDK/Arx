import { beforeEach, describe, expect, it } from "bun:test";

/*
 * The two planes.
 *
 * The data plane (agents, HMAC-signed requests) may exercise the authority an
 * operator granted. The control plane (a bearer token) is where authority is
 * granted. Keeping them on separate credentials is what makes invariant 11 —
 * an agent cannot mint or widen its own capability — enforceable rather than
 * aspirational, so the tests here are as much about the boundary between the two
 * as about the cryptography.
 */
process.env.NODE_ENV = "test";
process.env.DATABASE_PATH ??= "./.test-data/arx-suite.sqlite";

const { resetDatabaseForTests } = await import("../src/db/database");
const {
  AGENT_HEADERS,
  AgentAuthenticator,
  SIGNING_SCHEME,
  buildSigningString,
  hashRequestBody,
  signRequestWithKey,
  signRequestWithSecret,
} = await import("../src/auth/agent-auth");
const { ADMIN_HEADER, AdminAuthenticator } = await import(
  "../src/auth/admin-auth"
);
const { createAuthMiddleware } = await import("../src/auth/middleware");
const { AgentStore, deriveAgentKey } = await import(
  "../src/storage/agent-store"
);
const { canonicalize } = await import("../src/crypto/canonical");
const { safeEqual, sha256Hex } = await import("../src/crypto/hash");
const { isArxError } = await import("../src/core/errors");

const MAX_SKEW = 300;
const NOW = 1_700_000_000;

const agentStore = new AgentStore();
const authenticator = new AgentAuthenticator(agentStore, MAX_SKEW);

type Credentials = { agentId: string; secret: string };

let alice: Credentials;
let bob: Credentials;

beforeEach(() => {
  resetDatabaseForTests();

  const a = agentStore.register({ agentId: "agent-alice", now: NOW });
  const b = agentStore.register({ agentId: "agent-bob", now: NOW });

  alice = { agentId: a.agent.agentId, secret: a.secret };
  bob = { agentId: b.agent.agentId, secret: b.secret };
});

type RequestShape = {
  method?: string;
  path?: string;
  body?: unknown;
  timestamp?: number;
  nonce?: string;
};

/** Builds a correctly signed request for an agent. */
function signed(
  credentials: Credentials,
  request: RequestShape = {},
): {
  method: string;
  path: string;
  body: unknown;
  headers: Record<string, string>;
} {
  const method = request.method ?? "POST";
  const path = request.path ?? "/approvals";
  const body = request.body ?? { agentId: credentials.agentId, amountUsd: 10 };
  const timestamp = request.timestamp ?? NOW;
  const nonce = request.nonce ?? `nonce-${crypto.randomUUID()}`;

  const signature = signRequestWithSecret(
    credentials.agentId,
    credentials.secret,
    { method, path, timestamp, nonce, body },
  );

  return {
    method,
    path,
    body,
    headers: {
      [AGENT_HEADERS.agent]: credentials.agentId,
      [AGENT_HEADERS.timestamp]: String(timestamp),
      [AGENT_HEADERS.nonce]: nonce,
      [AGENT_HEADERS.signature]: signature,
    },
  };
}

function authenticate(
  request: ReturnType<typeof signed>,
  now = NOW,
): ReturnType<typeof authenticator.authenticate> {
  return authenticator.authenticate({
    method: request.method,
    path: request.path,
    headers: request.headers,
    body: request.body,
    now,
  });
}

/** Runs `authenticate` and returns the decision code of the rejection. */
function codeOf(run: () => unknown): string {
  try {
    run();
  } catch (error) {
    if (isArxError(error)) {
      return error.code;
    }

    throw error;
  }

  throw new Error("expected the request to be rejected");
}

describe("the canonical signing string", () => {
  it("is exactly six newline-joined fields in the documented order", () => {
    // This string is the contract a client is written against. If it changes
    // shape, every client breaks silently — so its shape is pinned here.
    const string = buildSigningString({
      method: "post",
      path: "/approvals?dry=1",
      timestamp: NOW,
      nonce: "n-1",
      body: { b: 2, a: 1 },
    });

    const lines = string.split("\n");

    expect(lines).toHaveLength(6);
    expect(lines[0]).toBe(SIGNING_SCHEME);
    expect(lines[0]).toBe("ARX-HMAC-SHA256-V1");
    // Uppercased, so a client sending `post` and signing `POST` still verifies.
    expect(lines[1]).toBe("POST");
    // The path includes the query string exactly as received.
    expect(lines[2]).toBe("/approvals?dry=1");
    expect(lines[3]).toBe(String(NOW));
    expect(lines[4]).toBe("n-1");
    expect(lines[5]).toBe(sha256Hex(canonicalize({ a: 1, b: 2 })));
  });

  it("hashes an absent body as sha256 of the empty string", () => {
    expect(hashRequestBody(undefined)).toBe(sha256Hex(""));
    expect(hashRequestBody(null)).toBe(sha256Hex(""));
    expect(hashRequestBody("")).toBe(sha256Hex(""));
  });

  it("commits to the semantic body, not to its formatting", () => {
    // Canonical JSON rather than raw bytes is deliberate: a proxy reformatting
    // whitespace or reordering keys must not break authentication.
    expect(hashRequestBody({ a: 1, b: [2, 3] })).toBe(
      hashRequestBody({ b: [2, 3], a: 1 }),
    );
  });

  it("changes when any consequential field changes", () => {
    const base = {
      method: "POST",
      path: "/approvals",
      timestamp: NOW,
      nonce: "n-1",
      body: { amountUsd: 10 },
    };

    const variants = [
      { ...base, method: "GET" },
      { ...base, path: "/sign" },
      { ...base, path: "/approvals?x=1" },
      { ...base, timestamp: NOW + 1 },
      { ...base, nonce: "n-2" },
      { ...base, body: { amountUsd: 11 } },
    ];

    const strings = new Set(
      [base, ...variants].map((material) => buildSigningString(material)),
    );

    expect(strings.size).toBe(variants.length + 1);
  });

  it("derives the stored key from the secret rather than storing the secret", () => {
    // The database holds no plaintext secret, and the agent id is mixed in so
    // one secret enrolled under two ids yields two unrelated keys.
    const key = deriveAgentKey(alice.agentId, alice.secret);

    expect(agentStore.signingKey(alice.agentId)).toBe(key);
    expect(deriveAgentKey("someone-else", alice.secret)).not.toBe(key);

    const material = {
      method: "POST",
      path: "/approvals",
      timestamp: NOW,
      nonce: "n-1",
      body: { a: 1 },
    };

    expect(signRequestWithSecret(alice.agentId, alice.secret, material)).toBe(
      signRequestWithKey(key, material),
    );
  });
});

describe("HMAC verification", () => {
  it("accepts a correctly signed request", () => {
    const identity = authenticate(signed(alice));

    expect(identity).toMatchObject({
      agentId: alice.agentId,
      method: "HMAC",
    });
  });

  it("refuses a request with no credentials at all", () => {
    expect(
      codeOf(() =>
        authenticator.authenticate({
          method: "POST",
          path: "/approvals",
          headers: {},
          now: NOW,
        }),
      ),
    ).toBe("UNAUTHENTICATED");
  });

  for (const header of Object.values(AGENT_HEADERS)) {
    it(`refuses a request missing ${header}`, () => {
      // All four are required, and a partial credential set is never a partial
      // identity — it is no identity.
      const request = signed(alice);
      delete request.headers[header];

      expect(codeOf(() => authenticate(request))).toBe("UNAUTHENTICATED");
    });
  }

  it("refuses a forged signature", () => {
    const request = signed(alice);
    request.headers[AGENT_HEADERS.signature] = "f".repeat(64);

    expect(codeOf(() => authenticate(request))).toBe("SIGNATURE_INVALID");
  });

  it("refuses a body swapped after signing", () => {
    // The signature covers the body hash, so the payload an agent authorized is
    // the payload Arx acts on.
    const request = signed(alice, { body: { agentId: alice.agentId, amountUsd: 10 } });
    request.body = { agentId: alice.agentId, amountUsd: 10_000 };

    expect(codeOf(() => authenticate(request))).toBe("SIGNATURE_INVALID");
  });

  it("refuses a path swapped after signing", () => {
    const request = signed(alice, { path: "/firewall/submit" });
    request.path = "/sign";

    expect(codeOf(() => authenticate(request))).toBe("SIGNATURE_INVALID");
  });

  it("refuses a method swapped after signing", () => {
    const request = signed(alice, { method: "GET" });
    request.method = "POST";

    expect(codeOf(() => authenticate(request))).toBe("SIGNATURE_INVALID");
  });

  it("refuses an unknown agent", () => {
    expect(
      codeOf(() => authenticate(signed({ agentId: "ghost", secret: "x" }))),
    ).toBe("AGENT_NOT_FOUND");
  });

  it("refuses a disabled agent", () => {
    // Disabling must revoke the ability to authenticate everywhere at once,
    // not only on the paths that remembered to check `enabled`.
    agentStore.setEnabled(alice.agentId, false, NOW);

    expect(codeOf(() => authenticate(signed(alice)))).toBe("AGENT_DISABLED");
  });

  it("refuses a rotated-away secret and accepts the new one", () => {
    const stale = signed(alice);
    const rotated = agentStore.rotateSecret(alice.agentId, NOW);

    expect(codeOf(() => authenticate(stale))).toBe("SIGNATURE_INVALID");
    expect(
      authenticate(signed({ agentId: alice.agentId, secret: rotated.secret }))
        .agentId,
    ).toBe(alice.agentId);
  });

  it("compares the signature in constant time", () => {
    // A `===` on a hex digest leaks, through response latency, how many leading
    // bytes of a guess were right. Asserted structurally: a timing measurement
    // in a test suite is noise, but a `safeEqual` call site is a fact.
    const source = require("node:fs").readFileSync(
      "src/auth/agent-auth.ts",
      "utf8",
    ) as string;

    expect(source).toContain("safeEqual(signature.trim().toLowerCase()");
    expect(safeEqual("abc", "abd")).toBe(false);
    expect(safeEqual("abc", "abcd")).toBe(false);
    expect(safeEqual("abc", "abc")).toBe(true);
  });
});

describe("clock skew", () => {
  it("accepts a timestamp exactly at the positive skew bound", () => {
    expect(
      authenticate(signed(alice, { timestamp: NOW + MAX_SKEW }), NOW).agentId,
    ).toBe(alice.agentId);
  });

  it("accepts a timestamp exactly at the negative skew bound", () => {
    expect(
      authenticate(signed(alice, { timestamp: NOW - MAX_SKEW }), NOW).agentId,
    ).toBe(alice.agentId);
  });

  it("refuses a timestamp one second past the positive bound", () => {
    expect(
      codeOf(() =>
        authenticate(signed(alice, { timestamp: NOW + MAX_SKEW + 1 }), NOW),
      ),
    ).toBe("TIMESTAMP_SKEWED");
  });

  it("refuses a timestamp one second past the negative bound", () => {
    // This is what bounds the useful life of a captured request.
    expect(
      codeOf(() =>
        authenticate(signed(alice, { timestamp: NOW - MAX_SKEW - 1 }), NOW),
      ),
    ).toBe("TIMESTAMP_SKEWED");
  });

  it("refuses a non-integer timestamp", () => {
    const request = signed(alice);
    request.headers[AGENT_HEADERS.timestamp] = "not-a-time";

    expect(codeOf(() => authenticate(request))).toBe("TIMESTAMP_SKEWED");
  });

  it("refuses a timestamp of zero", () => {
    const request = signed(alice);
    request.headers[AGENT_HEADERS.timestamp] = "0";

    expect(codeOf(() => authenticate(request))).toBe("TIMESTAMP_SKEWED");
  });
});

describe("request nonce replay", () => {
  it("accepts a nonce once and refuses it thereafter", () => {
    const request = signed(alice, { nonce: "fixed-nonce" });

    expect(authenticate(request).agentId).toBe(alice.agentId);
    expect(codeOf(() => authenticate(request))).toBe("REPLAY_DETECTED");
  });

  it("scopes a nonce to its agent", () => {
    // Two agents legitimately pick the same nonce string; that must not make
    // one of them unauthenticatable.
    expect(authenticate(signed(alice, { nonce: "shared" })).agentId).toBe(
      alice.agentId,
    );
    expect(authenticate(signed(bob, { nonce: "shared" })).agentId).toBe(
      bob.agentId,
    );
  });

  it("does not consume a nonce when the signature fails", () => {
    /*
     * The nonce is claimed only after the signature verifies. Claiming first
     * would let an unauthenticated observer burn the nonces of requests it
     * merely watched, turning replay protection into a denial-of-service
     * primitive against the legitimate agent.
     */
    const good = signed(alice, { nonce: "contested" });
    const forged = {
      ...good,
      headers: { ...good.headers, [AGENT_HEADERS.signature]: "0".repeat(64) },
    };

    expect(codeOf(() => authenticate(forged))).toBe("SIGNATURE_INVALID");
    expect(authenticate(good).agentId).toBe(alice.agentId);
  });

  it("does not consume a nonce when the timestamp is skewed", () => {
    const skewed = signed(alice, { nonce: "early", timestamp: NOW - 10_000 });

    expect(codeOf(() => authenticate(skewed, NOW))).toBe("TIMESTAMP_SKEWED");
    expect(authenticate(signed(alice, { nonce: "early" }), NOW).agentId).toBe(
      alice.agentId,
    );
  });

  it("lets exactly one of eight copies of one captured request through", async () => {
    const request = signed(alice, { nonce: "burst" });

    const outcomes = await Promise.all(
      Array.from({ length: 8 }, async () => {
        try {
          authenticate(request);
          return "accepted";
        } catch {
          return "refused";
        }
      }),
    );

    expect(outcomes.filter((outcome) => outcome === "accepted")).toHaveLength(
      1,
    );
  });

  it("prunes only nonces that are already unusable", () => {
    // A request that old is rejected as skewed before its nonce is consulted,
    // so dropping it cannot reopen a replay window.
    authenticate(signed(alice, { nonce: "old" }));

    expect(authenticator.pruneNonces(NOW)).toBe(0);
    expect(authenticator.pruneNonces(NOW + MAX_SKEW + 2)).toBe(1);
  });
});

describe("agent A cannot exercise agent B's capability", () => {
  const middleware = createAuthMiddleware({
    agentAuthenticator: authenticator,
    adminAuthenticator: new AdminAuthenticator("admin-token"),
  });

  /**
   * The middleware calls the authenticator without an injected clock, so these
   * requests are signed against the real one rather than the fixture NOW.
   */
  function liveSigned(
    credentials: Credentials,
    request: RequestShape = {},
  ): ReturnType<typeof signed> {
    return signed(credentials, {
      ...request,
      timestamp: request.timestamp ?? Math.floor(Date.now() / 1000),
    });
  }

  /** The smallest shape `requireAgent` reads off a Fastify request. */
  function fakeRequest(request: ReturnType<typeof signed>) {
    return {
      method: request.method,
      url: request.path,
      headers: request.headers,
      body: request.body,
    } as never;
  }

  it("accepts a request whose body names the authenticated agent", async () => {
    const preHandler = middleware.requireAgent({ enforce: true });
    const request = fakeRequest(
      liveSigned(alice, { body: { agentId: alice.agentId, nonce: 1 } }),
    );

    await preHandler(request, {} as never);

    expect((request as { arxAgent?: { agentId: string } }).arxAgent?.agentId).toBe(
      alice.agentId,
    );
  });

  it("refuses a request that authenticates as A and acts as B", async () => {
    /*
     * The attack without this check: Alice signs correctly as herself, then
     * submits an intent naming Bob's agentId and Bob's capability. Per-agent
     * least privilege would be decorative.
     */
    const preHandler = middleware.requireAgent({ enforce: true });
    const request = fakeRequest(
      liveSigned(alice, { body: { agentId: bob.agentId, nonce: 1 } }),
    );

    let code: string | undefined;

    try {
      await preHandler(request, {} as never);
    } catch (error) {
      if (isArxError(error)) {
        code = error.code;
      }
    }

    expect(code).toBe("FORBIDDEN");
  });

  it("refuses an enforced request whose body names no agent at all", async () => {
    // Fail closed: a request that cannot be bound to its caller must not run.
    const preHandler = middleware.requireAgent({ enforce: true });
    const request = fakeRequest(liveSigned(alice, { body: { nonce: 1 } }));

    let code: string | undefined;

    try {
      await preHandler(request, {} as never);
    } catch (error) {
      if (isArxError(error)) {
        code = error.code;
      }
    }

    expect(code).toBe("FORBIDDEN");
  });

  it("refuses an unauthenticated request when enforcement is on", async () => {
    const preHandler = middleware.requireAgent({ enforce: true });

    let code: string | undefined;

    try {
      await preHandler(
        { method: "POST", url: "/approvals", headers: {}, body: {} } as never,
        {} as never,
      );
    } catch (error) {
      if (isArxError(error)) {
        code = error.code;
      }
    }

    expect(code).toBe("UNAUTHENTICATED");
  });

  it("still verifies credentials that are presented in open mode", async () => {
    // Open mode tolerates the *absence* of credentials. It never tolerates bad
    // ones.
    const preHandler = middleware.requireAgent({ enforce: false });
    const good = liveSigned(alice);
    const forged = fakeRequest({
      ...good,
      headers: { ...good.headers, [AGENT_HEADERS.signature]: "0".repeat(64) },
    });

    let code: string | undefined;

    try {
      await preHandler(forged, {} as never);
    } catch (error) {
      if (isArxError(error)) {
        code = error.code;
      }
    }

    expect(code).toBe("SIGNATURE_INVALID");
  });

  it("still refuses a cross-agent body in open mode", async () => {
    const preHandler = middleware.requireAgent({ enforce: false });
    const request = fakeRequest(
      liveSigned(alice, { body: { agentId: bob.agentId } }),
    );

    let code: string | undefined;

    try {
      await preHandler(request, {} as never);
    } catch (error) {
      if (isArxError(error)) {
        code = error.code;
      }
    }

    expect(code).toBe("FORBIDDEN");
  });
});

describe("the control-plane token", () => {
  const token = "s3cret-operator-token";
  const admin = new AdminAuthenticator(token);

  it("accepts the token in the X-Arx-Admin-Token header", () => {
    expect(admin.authenticate({ [ADMIN_HEADER]: token })).toMatchObject({
      plane: "CONTROL",
      mode: "TOKEN",
      authenticated: true,
    });
  });

  it("accepts the token as a bearer credential", () => {
    expect(
      admin.authenticate({ authorization: `Bearer ${token}` }),
    ).toMatchObject({ mode: "TOKEN", authenticated: true });
  });

  it("refuses a missing token", () => {
    expect(codeOf(() => admin.authenticate({}))).toBe("UNAUTHENTICATED");
  });

  it("refuses a wrong token of the same length", () => {
    const nearMiss = `${token.slice(0, -1)}X`;

    expect(nearMiss).toHaveLength(token.length);
    expect(codeOf(() => admin.authenticate({ [ADMIN_HEADER]: nearMiss }))).toBe(
      "FORBIDDEN",
    );
  });

  it("refuses a token that is a prefix of the real one", () => {
    expect(
      codeOf(() => admin.authenticate({ [ADMIN_HEADER]: token.slice(0, -1) })),
    ).toBe("FORBIDDEN");
  });

  it("compares the token in constant time", () => {
    // Same reasoning as the agent signature: asserted at the call site rather
    // than by timing, which a test runner cannot measure reliably.
    const source = require("node:fs").readFileSync(
      "src/auth/admin-auth.ts",
      "utf8",
    ) as string;

    expect(source).toContain("safeEqual(presented, this.token)");
    expect(source).not.toContain("presented === this.token");
  });

  it("reports an unconfigured control plane as OPEN rather than authenticated", () => {
    // Allowed for local development, but never silently: the response and the
    // audit trail both have to show the action was taken with no credential.
    const open = new AdminAuthenticator("");

    expect(open.configured).toBe(false);
    expect(open.warning()).toContain("UNAUTHENTICATED");
    expect(open.authenticate({})).toMatchObject({
      mode: "OPEN",
      authenticated: false,
      subject: "operator:unauthenticated",
    });
  });

  it("emits no warning once a token is configured", () => {
    expect(admin.warning()).toBeNull();
    expect(admin.configured).toBe(true);
  });

  it("does not accept an agent's HMAC credentials as an admin token", () => {
    /*
     * The plane separation, at its narrowest point: a complete, valid set of
     * agent headers carries nothing the control plane will take. The
     * route-level version of this test — an HMAC-signed request against
     * `POST /capabilities` — is in `tests/end-to-end.test.ts`.
     */
    const request = signed(alice);

    expect(codeOf(() => admin.authenticate(request.headers))).toBe(
      "UNAUTHENTICATED",
    );

    // Nor the agent's own secret, nor its derived signing key.
    expect(
      codeOf(() => admin.authenticate({ [ADMIN_HEADER]: alice.secret })),
    ).toBe("FORBIDDEN");
    expect(
      codeOf(() =>
        admin.authenticate({
          [ADMIN_HEADER]: deriveAgentKey(alice.agentId, alice.secret),
        }),
      ),
    ).toBe("FORBIDDEN");
  });
});
