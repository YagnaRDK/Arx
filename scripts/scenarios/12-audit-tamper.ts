import { AuditDatabase } from "../lib/audit-db";
import { BlockedError, type Scenario } from "../lib/scenario";
import { kv, style } from "../lib/term";

type Verification = {
  valid: boolean | null;
  entries: number | null;
  brokenAtSeq: number | null;
  problem: string | null;
  headHash: string | null;
};

function readVerification(body: unknown): Verification {
  if (typeof body !== "object" || body === null) {
    return {
      valid: null,
      entries: null,
      brokenAtSeq: null,
      problem: null,
      headHash: null,
    };
  }

  const record = body as Record<string, any>;
  const chain = record.chain ?? record.verification ?? record;

  return {
    valid: typeof chain.valid === "boolean" ? chain.valid : null,
    entries: typeof chain.entries === "number" ? chain.entries : null,
    brokenAtSeq:
      typeof chain.brokenAtSeq === "number"
        ? chain.brokenAtSeq
        : typeof chain.brokenAt === "number"
          ? chain.brokenAt
          : null,
    problem: typeof chain.problem === "string" ? chain.problem : null,
    headHash:
      typeof chain.headHash === "string"
        ? chain.headHash
        : typeof chain.head === "string"
          ? chain.head
          : null,
  };
}

/**
 * Tamper-evidence, demonstrated the only way it can be.
 *
 * The threat this control exists for is an attacker — or an operator covering
 * their tracks — with write access to the audit store. So the tamper happens out
 * of band: this scenario opens the SQLite file directly and edits the `reason`
 * of a historical entry. No endpoint consents to it; nothing in the request path
 * is involved.
 *
 * Then it asks `GET /audit/verify` whether Arx notices, and expects the exact
 * sequence number to be named. The edit is reverted afterwards and the chain
 * re-verified, so the run leaves the audit trail intact — and the revert itself
 * proves the detection was about the content, not a one-way flag.
 *
 * Invariant 12.
 */
export const auditTamper: Scenario = {
  name: "audit-tamper",
  title: "Audit tamper: edit a historical entry, watch the chain break",
  kind: "FORENSICS",
  story: [
    "An attacker with database access rewrites the reason on a past decision",
    "to hide it. Each entry commits to the previous entry's hash, so every",
    "entry after the edit stops verifying.",
  ],
  expectation:
    "GET /audit/verify reports valid:false and names the broken sequence number; intact again after revert",

  async run(ctx, trace): Promise<void> {
    const before = trace.requireRoute(
      await trace.call("GET /audit/verify (baseline)", [], () =>
        ctx.client.get("/audit/verify"),
      ),
    );

    const baseline = readVerification(before.body);

    trace.assert(
      "the chain is intact before tampering",
      baseline.valid === true,
      "valid: true",
      baseline.valid === null ? "no valid flag in response" : String(baseline.valid),
    );

    const databasePath = ctx.databasePath;

    if (!databasePath) {
      throw new BlockedError(
        "The audit database path is unknown (the server did not report it and DATABASE_PATH is unset), so the tamper cannot be performed out of band",
      );
    }

    let opened: AuditDatabase;

    try {
      opened = new AuditDatabase(databasePath);
    } catch (error) {
      throw new BlockedError(
        `Cannot open the audit database at ${databasePath}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }

    const database = opened;

    try {
      const target = database.middleRow();

      if (!target) {
        throw new BlockedError(
          "Fewer than three audit entries exist, so there is no historical entry to tamper with; run the full suite rather than --only audit-tamper",
        );
      }

      const originalReason = target.reason;

      if (!ctx.quiet) {
        kv([
          ["target seq", String(target.seq)],
          ["original reason", originalReason ?? "(null)"],
          ["written instead", "Routine internal maintenance"],
          ["method", `direct UPDATE on ${databasePath}`],
        ]);
      }

      database.setReason(target.seq, "Routine internal maintenance");

      const tampered = trace.requireRoute(
        await trace.call("GET /audit/verify (after tamper)", [], () =>
          ctx.client.get("/audit/verify"),
        ),
      );

      const broken = readVerification(tampered.body);

      trace.assert(
        "the tamper is detected",
        broken.valid === false,
        "valid: false",
        broken.valid === null ? "no valid flag in response" : String(broken.valid),
      );

      trace.assert(
        "the broken entry is named by sequence number",
        broken.brokenAtSeq === target.seq,
        `brokenAtSeq ${target.seq}`,
        broken.brokenAtSeq === null ? "not reported" : String(broken.brokenAtSeq),
      );

      if (broken.problem && !ctx.quiet) {
        trace.note(`reported problem: ${style.amber(broken.problem)}`);
      }

      database.setReason(target.seq, originalReason);

      const restored = trace.requireRoute(
        await trace.call("GET /audit/verify (after revert)", [], () =>
          ctx.client.get("/audit/verify"),
        ),
      );

      const restoredState = readVerification(restored.body);

      trace.assert(
        "reverting the edit restores the chain",
        restoredState.valid === true,
        "valid: true",
        restoredState.valid === null
          ? "no valid flag in response"
          : String(restoredState.valid),
      );
    } finally {
      database.close();
    }
  },
};
