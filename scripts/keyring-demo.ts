#!/usr/bin/env bun
/**
 * The capability-broker demonstration.
 *
 *   bun run scripts/keyring-demo.ts
 *   bun run scripts/keyring-demo.ts --json
 *
 * Ledger's Track 01 names this pattern verbatim: "Agents that use secrets they
 * cannot leak: a broker hands out scoped capabilities, never the API key."
 *
 * This script is the runnable form of that claim. It seals an upstream
 * credential, issues an agent a scoped token, lets the agent complete a real
 * authorized action, and then shows four ways the same token stops working.
 *
 * Why a script and not just the test suite: the assertions in
 * `tests/capability-broker.test.ts` prove the controls hold, but they do not
 * show *what the agent can see*. That is the whole argument, so it is shown.
 *
 * The exit code is the contract. Any outcome other than the documented one —
 * including a refusal arriving with the wrong DecisionCode, or the secret
 * appearing anywhere the agent can read — exits non-zero.
 *
 * No device and no network are required: with no Ledger Key Ring provisioned,
 * the seal falls back to a local development seal, and the script says so on
 * screen and in every line of its output. It never pretends a local seal is
 * hardware-rooted.
 */

import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  CapabilityBroker,
  capabilityPolicyHash,
  type IssuedToken,
} from "../src/broker/capability-broker";
import { ringCli, type RingStatus } from "../src/broker/ring-cli";
import {
  SealedSecretStore,
  type SealBackend,
} from "../src/broker/sealed-secret-store";
import { ArxError, isArxError } from "../src/core/errors";
import type { DecisionCode } from "../src/core/codes";
import { CapabilitySchema, type Capability } from "../src/types/capability";
import {
  banner,
  field,
  kv,
  rule,
  setColorEnabled,
  statusBadge,
  style,
  write,
} from "./lib/term";

/*
 * A deliberately obvious fake. It is scanned for verbatim across everything the
 * agent can see, so it must be a string that could not occur by coincidence.
 */
const UPSTREAM_SECRET = "sk_live_arx_demo_51NotARealKey_do_not_use_9f2c";
const SECRET_NAME = "invoice-api-key";
const OTHER_SECRET_NAME = "payroll-api-key";
const OTHER_SECRET = "sk_live_arx_demo_payroll_7b41_also_fake";

/** Fixed clock: a demo that drifts with wall time is a demo that flakes. */
const NOW = 1_800_000_000;

type Check = {
  label: string;
  status: "PASS" | "FAIL";
  detail: string;
};

const checks: Check[] = [];

/** `--json` must emit one parseable document, so the narrative is silenced. */
let quiet = false;

function record(label: string, ok: boolean, detail: string): void {
  checks.push({ label, status: ok ? "PASS" : "FAIL", detail });

  if (quiet) {
    return;
  }

  write(
    `  ${statusBadge(ok ? "PASS" : "FAIL")}  ${label}${detail ? style.grey(` — ${detail}`) : ""}`,
  );
}

/** Asserts and records in one step, so a check can never be silently skipped. */
function expect(label: string, ok: boolean, detail = ""): void {
  record(label, ok, detail);
}

/**
 * Asserts that a call is refused with a specific DecisionCode.
 *
 * "It threw" is not the property worth proving — a refusal that arrives with
 * the wrong code would still stop the action but would misreport why, and the
 * reason is what an operator acts on.
 */
async function expectRefusal(
  label: string,
  expectedCode: DecisionCode,
  expectedPhrase: string,
  action: () => Promise<unknown>,
): Promise<void> {
  try {
    await action();
    record(label, false, "the call succeeded; it must have been refused");
    return;
  } catch (error) {
    if (!isArxError(error)) {
      record(
        label,
        false,
        `threw a bare ${error instanceof Error ? error.name : typeof error}, not an ArxError`,
      );
      return;
    }

    const codeMatches = error.code === expectedCode;
    const phraseMatches = error.message
      .toLowerCase()
      .includes(expectedPhrase.toLowerCase());

    record(
      label,
      codeMatches && phraseMatches,
      codeMatches && phraseMatches
        ? `${error.code}: ${error.message}`
        : `expected ${expectedCode} containing "${expectedPhrase}", got ${error.code}: ${error.message}`,
    );
  }
}

/** Every string in a value, so a secret cannot hide inside nesting. */
function containsSecret(value: unknown, secret: string): boolean {
  return JSON.stringify(value ?? null).includes(secret);
}

function makeCapability(overrides: Record<string, unknown> = {}): Capability {
  return CapabilitySchema.parse({
    capabilityId: "cap-invoice-broker",
    agentId: "agent-accounts-payable",
    label: "Invoice reconciliation",
    allowedActions: ["CALL_API"],
    allowedProtocols: ["HTTP"],
    allowedChains: [11155111],
    allowedTokens: { input: ["USDC"], output: ["USDC"] },
    maxAmountUsd: 250,
    maxSlippageBps: 0,
    expiresAt: NOW + 86_400,
    nonce: 0,
    status: "ACTIVE",
    usage: "REUSABLE",
    ...overrides,
  });
}

/**
 * The upstream service. It authenticates with the credential and nothing else,
 * which is exactly why handing that credential to an agent is the problem.
 */
function upstreamInvoiceApi(
  apiKey: string,
  invoiceId: string,
): { invoiceId: string; supplier: string; amountUsd: number } {
  if (apiKey !== UPSTREAM_SECRET) {
    throw new Error("upstream rejected the credential");
  }

  return { invoiceId, supplier: "Northwind Components Ltd", amountUsd: 128.4 };
}

/**
 * Arx's brokered endpoint — the only path from the agent to the upstream call.
 *
 * The `use` closure lives here, on Arx's side of the boundary. The agent passes
 * a bearer and an invoice id and receives a result; the plaintext exists only
 * inside this function's stack frame.
 */
async function brokeredInvoiceLookup(
  broker: CapabilityBroker,
  input: {
    bearer: string;
    capability: Capability;
    invoiceId: string;
    secretName?: string;
    now?: number;
  },
) {
  return broker.withSecret({
    bearer: input.bearer,
    capability: input.capability,
    secretName: input.secretName ?? SECRET_NAME,
    now: input.now ?? NOW,
    use: async (secret) => upstreamInvoiceApi(secret, input.invoiceId),
  });
}

function describeRingStatus(status: RingStatus): void {
  kv([
    ["wallet-cli reachable", status.available ? style.green("yes") : style.red("no")],
    [
      "key ring provisioned",
      status.initialized ? style.green("yes") : style.amber("no"),
    ],
    ["keys on this machine", (status.keys ?? []).join(", ") || style.grey("none")],
    ["reason", status.reason ? style.grey(status.reason) : style.grey("—")],
  ]);
}

function describeBackend(backend: SealBackend, reason?: string): void {
  if (backend === "ledger-keyring") {
    field(
      "SEAL",
      style.green(
        "ledger-keyring — sealed under the Ledger Key Ring (LKRP). hardwareRooted: true",
      ),
    );
    return;
  }

  field("SEAL", [
    style.amber("local-dev — scrypt + AES-256-GCM from a local passphrase."),
    style.amber("This is NOT hardware-rooted. hardwareRooted: false everywhere."),
    style.grey(reason ?? ""),
  ]);
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  const asJson = argv.includes("--json");
  setColorEnabled(!asJson && !argv.includes("--no-color"));

  if (asJson) {
    // JSON mode suppresses the narrative but not the assertions.
    setColorEnabled(false);
    quiet = true;
  }

  const dir = mkdtempSync(join(tmpdir(), "arx-keyring-demo-"));
  const storePath = join(dir, "sealed-secrets.json");

  const store = new SealedSecretStore({
    path: storePath,
    /*
     * Only ever used when the Key Ring is absent. It is a literal here because
     * this is a demo of the *broker*, not of passphrase management — and Ledger
     * is explicit that a real ring password must come from the operator's
     * keychain and never from an agent (see docs/KEYRING.md).
     */
    localPassphrase: "arx-keyring-demo-passphrase-not-a-real-secret",
  });

  const broker = new CapabilityBroker(store);

  if (!asJson) {
    banner(
      "Arx capability broker — scoped capabilities, never the API key",
      "Ledger Track 01: agents that use secrets they cannot leak",
    );
  }

  // ── 0. Key Ring status, stated before anything depends on it ──────────────
  if (!asJson) {
    write();
    write(style.bold("0. Ledger Key Ring status"));
    write(
      style.grey(
        "   Probing `wallet-cli ring keys`. A first run downloads wallet-cli;",
      ),
    );
    write(style.grey("   the probe gives up after 20s and reports it."));
    write();
  }

  const probeStarted = Date.now();
  const ringStatus = await ringCli.status();
  const probeMs = Date.now() - probeStarted;

  if (!asJson) {
    describeRingStatus(ringStatus);
    write(style.grey(`${" ".repeat(11)}probe took ${probeMs}ms`));
    write();
  }

  const { backend, reason } = await store.activeBackend();

  if (!asJson) {
    describeBackend(backend, reason);
    write();
    rule();
  }

  expect(
    "seal backend is reported, never assumed",
    backend === "ledger-keyring" || backend === "local-dev",
    `backend=${backend}`,
  );

  // ── 1. The operator seals the upstream credential ─────────────────────────
  if (!asJson) {
    write();
    write(style.bold("1. The operator seals the upstream credential"));
    write(
      style.grey(
        "   A human does this once. The agent is not present and never will be.",
      ),
    );
    write();
  }

  const sealed = await store.seal({ name: SECRET_NAME, secret: UPSTREAM_SECRET });
  await store.seal({ name: OTHER_SECRET_NAME, secret: OTHER_SECRET });

  if (!asJson) {
    kv([
      ["name", sealed.name],
      ["backend", sealed.backend],
      ["hardwareRooted", String(sealed.backend === "ledger-keyring")],
      ["ring key name", sealed.keyName],
      ["plaintext digest", sealed.plaintextDigest],
    ]);
    write();
  }

  expect(
    "the seal records which backend produced it",
    sealed.backend === backend,
    `${sealed.backend}`,
  );

  expect(
    "listed metadata carries neither plaintext nor ciphertext",
    !containsSecret(store.list(), UPSTREAM_SECRET) &&
      !JSON.stringify(store.list()).includes("ciphertext"),
  );

  const onDisk = readFileSync(storePath, "utf8");

  expect(
    "the plaintext is nowhere in the store file on disk",
    !onDisk.includes(UPSTREAM_SECRET),
    `${storePath}`,
  );

  // ── 2. The agent is issued a scoped token ─────────────────────────────────
  if (!asJson) {
    write();
    write(style.bold("2. The agent is issued a scoped capability token"));
    write(
      style.grey(
        "   Short-lived, one capability, bound to a hash of the policy in force.",
      ),
    );
    write();
  }

  const capability = makeCapability();

  const issued: IssuedToken = broker.issue({
    capability,
    grants: [SECRET_NAME],
    ttlSeconds: 300,
    now: NOW,
  });

  if (!asJson) {
    kv([
      ["bearer", issued.bearer],
      ["grants", issued.token.grants.join(", ")],
      ["policy hash", issued.token.policyHash],
      ["ttl", `${issued.token.expiresAt - issued.token.issuedAt}s`],
      ["signed by", issued.token.keyId],
    ]);
    write();
  }

  expect(
    "the token the agent receives contains no secret material",
    !containsSecret(issued, UPSTREAM_SECRET) &&
      !containsSecret(issued, OTHER_SECRET),
  );

  expect(
    "the token grants exactly one named secret",
    issued.token.grants.length === 1 && issued.token.grants[0] === SECRET_NAME,
    issued.token.grants.join(", "),
  );

  expect(
    "the token is bound to the policy in force",
    issued.token.policyHash === capabilityPolicyHash(capability),
  );

  // ── 3. The agent completes an authorized action ───────────────────────────
  if (!asJson) {
    write();
    write(style.bold("3. The agent completes the action — without the secret"));
    write(
      style.grey(
        "   Arx unseals just-in-time inside its own stack frame and returns the result.",
      ),
    );
    write();
  }

  const { result, provenance } = await brokeredInvoiceLookup(broker, {
    bearer: issued.bearer,
    capability,
    invoiceId: "INV-2026-0912",
  });

  if (!asJson) {
    kv([
      ["agent sees", JSON.stringify(result)],
      ["secret used", provenance.secretName],
      ["backend", provenance.backend],
      ["hardwareRooted", String(provenance.hardwareRooted)],
    ]);
    write();
  }

  expect(
    "the upstream call succeeded with the real credential",
    result.supplier === "Northwind Components Ltd" &&
      result.invoiceId === "INV-2026-0912",
  );

  expect(
    "the result handed back to the agent contains no secret",
    !containsSecret(result, UPSTREAM_SECRET),
  );

  expect(
    "the provenance record contains no secret",
    !containsSecret(provenance, UPSTREAM_SECRET),
  );

  expect(
    "hardwareRooted reflects the backend that actually sealed it",
    provenance.hardwareRooted === (backend === "ledger-keyring"),
    `hardwareRooted=${provenance.hardwareRooted} backend=${provenance.backend}`,
  );

  expect(
    "no secret appears in the broker's own history",
    !containsSecret(broker.history(), UPSTREAM_SECRET),
  );

  // ── 4. Four refusals ──────────────────────────────────────────────────────
  if (!asJson) {
    rule();
    write();
    write(style.bold("4. Four ways the same token stops working"));
    write();
  }

  // (a) A secret the token does not grant.
  if (!asJson) {
    write(style.grey("   (a) a secret the token does not grant"));
  }

  await expectRefusal(
    "refuses a secret outside the token's grants",
    "FORBIDDEN",
    "does not grant",
    () =>
      brokeredInvoiceLookup(broker, {
        bearer: issued.bearer,
        capability,
        invoiceId: "INV-2026-0912",
        secretName: OTHER_SECRET_NAME,
      }),
  );

  // (b) An expired token.
  if (!asJson) {
    write(style.grey("   (b) a token past its expiry"));
  }

  const shortLived = broker.issue({
    capability,
    grants: [SECRET_NAME],
    ttlSeconds: 60,
    now: NOW,
  });

  await expectRefusal(
    "refuses an expired token",
    "FORBIDDEN",
    "expired",
    () =>
      brokeredInvoiceLookup(broker, {
        bearer: shortLived.bearer,
        capability,
        invoiceId: "INV-2026-0912",
        // One second past expiry. Time is injected, so this is exact.
        now: NOW + 61,
      }),
  );

  // (c) A token minted under a wider policy, presented after narrowing.
  if (!asJson) {
    write(
      style.grey(
        "   (c) a token minted under the old policy, after the operator narrowed it",
      ),
    );
  }

  const wideToken = broker.issue({
    capability,
    grants: [SECRET_NAME],
    now: NOW,
  });

  const narrowed = makeCapability({ maxAmountUsd: 25 });

  expect(
    "narrowing the policy changes the policy hash",
    capabilityPolicyHash(narrowed) !== capabilityPolicyHash(capability),
  );

  await expectRefusal(
    "refuses a token issued before the policy was narrowed",
    "FORBIDDEN",
    "policy changed",
    () =>
      brokeredInvoiceLookup(broker, {
        bearer: wideToken.bearer,
        capability: narrowed,
        invoiceId: "INV-2026-0912",
      }),
  );

  // (d) A revoked token.
  if (!asJson) {
    write(style.grey("   (d) a token after revocation"));
  }

  const doomed = broker.issue({
    capability,
    grants: [SECRET_NAME],
    now: NOW,
  });

  expect(
    "revocation reports that it removed a live token",
    broker.revoke(doomed.token.tokenId),
  );

  await expectRefusal(
    "refuses a revoked token",
    "UNAUTHENTICATED",
    "unknown capability token",
    () =>
      brokeredInvoiceLookup(broker, {
        bearer: doomed.bearer,
        capability,
        invoiceId: "INV-2026-0912",
      }),
  );

  // ── 5. Summary ────────────────────────────────────────────────────────────
  const failed = checks.filter((check) => check.status === "FAIL");

  if (asJson) {
    write(
      JSON.stringify(
        {
          keyRing: ringStatus,
          sealBackend: backend,
          hardwareRooted: backend === "ledger-keyring",
          sealBackendReason: reason ?? null,
          checks,
          passed: checks.length - failed.length,
          failed: failed.length,
        },
        null,
        2,
      ),
    );
  } else {
    write();
    rule();
    write();
    write(
      `${style.bold("Result")}  ${checks.length - failed.length}/${checks.length} checks passed`,
    );

    if (failed.length > 0) {
      write();
      for (const check of failed) {
        write(`  ${statusBadge("FAIL")}  ${check.label} — ${check.detail}`);
      }
    }

    write();
    field(
      "CLAIM",
      backend === "ledger-keyring"
        ? style.green(
            "The secret was sealed under the Ledger Key Ring and the agent never held it.",
          )
        : [
            style.amber(
              "The secret was sealed with the LOCAL DEVELOPMENT seal, not the Key Ring.",
            ),
            style.amber(
              "The broker's controls are fully exercised; the seal is not hardware-rooted.",
            ),
            style.grey(
              "For a hardware-rooted seal run `wallet-cli ring init` with a device attached.",
            ),
          ],
    );
    write();
  }

  rmSync(dir, { recursive: true, force: true });

  return failed.length === 0 ? 0 : 1;
}

main()
  .then((code) => process.exit(code))
  .catch((error) => {
    // A thrown error here is an unexpected outcome, which is itself a failure.
    write();
    write(
      style.red(
        `keyring-demo failed: ${
          error instanceof ArxError
            ? `${error.code}: ${error.message}`
            : error instanceof Error
              ? error.message
              : String(error)
        }`,
      ),
    );

    if (error instanceof Error && error.stack) {
      write(style.grey(error.stack));
    }

    process.exit(1);
  });
