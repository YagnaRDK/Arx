import { db } from "../db/database";
import { canonicalize } from "../crypto/canonical";
import { sha256Hex } from "../crypto/hash";
import type { DecisionCode } from "../core/codes";
import type { EvaluationResult } from "../types/evaluation";
import type { Intent } from "../types/intent";

/** The lifecycle events Arx records. Ordering here mirrors the pipeline. */
export const AUDIT_EVENTS = [
  "INTENT_RECEIVED",
  "CAPABILITY_RESOLVED",
  "POLICY_EVALUATED",
  "FIREWALL_CHECKED",
  "RISK_SCORED",
  "HUMAN_APPROVAL_REQUESTED",
  "HUMAN_APPROVAL_GRANTED",
  "HUMAN_APPROVAL_DENIED",
  "APPROVAL_CREATED",
  "APPROVAL_EXPIRED",
  "APPROVAL_REVOKED",
  "SIGNING_STARTED",
  "SIGNING_SUCCEEDED",
  /**
   * Arx declined to pass the request to the signer at all — an invalid or
   * pending approval, or a revoked capability. The signer was never invoked.
   *
   * Kept distinct from `SIGNING_FAILED`, which means the signer *was* invoked
   * and did not produce an acceptable signature. An operator reading the log
   * has to be able to tell "my device misbehaved" from "Arx stopped this", and
   * one event type for both answers neither question.
   */
  "SIGNING_REFUSED",
  "SIGNING_FAILED",
  "SIGNATURE_VERIFIED",
  "CAPABILITY_CREATED",
  "CAPABILITY_REVOKED",
  "AUTH_REJECTED",
] as const;

export type AuditEvent = (typeof AUDIT_EVENTS)[number];

export const GENESIS_HASH = `0x${"0".repeat(64)}`;

export type AuditChainEntry = {
  seq: number;
  eventType: AuditEvent;
  requestId: string | null;
  capabilityId: string | null;
  agentId: string | null;
  approvalId: string | null;
  transactionId: string | null;
  decision: string | null;
  code: string | null;
  reason: string | null;
  payload: unknown;
  prevHash: string;
  entryHash: string;
  timestamp: number;
};

type ChainRow = {
  seq: number;
  event_type: AuditEvent;
  request_id: string | null;
  capability_id: string | null;
  agent_id: string | null;
  approval_id: string | null;
  transaction_id: string | null;
  decision: string | null;
  code: string | null;
  reason: string | null;
  payload: string;
  prev_hash: string;
  entry_hash: string;
  timestamp: number;
};

/**
 * The bytes each entry's hash commits to.
 *
 * `prevHash` is included, which is what chains the entries: recomputing entry
 * N requires entry N-1's hash, so editing or deleting any historical row
 * invalidates every hash after it.
 */
function entryPreimage(input: {
  seq: number;
  eventType: string;
  requestId: string | null;
  capabilityId: string | null;
  agentId: string | null;
  approvalId: string | null;
  transactionId: string | null;
  decision: string | null;
  code: string | null;
  reason: string | null;
  payload: unknown;
  prevHash: string;
  timestamp: number;
}): string {
  return canonicalize({
    seq: input.seq,
    eventType: input.eventType,
    requestId: input.requestId,
    capabilityId: input.capabilityId,
    agentId: input.agentId,
    approvalId: input.approvalId,
    transactionId: input.transactionId,
    decision: input.decision,
    code: input.code,
    reason: input.reason,
    payload: input.payload,
    prevHash: input.prevHash,
    timestamp: input.timestamp,
  });
}

function rowToEntry(row: ChainRow): AuditChainEntry {
  return {
    seq: row.seq,
    eventType: row.event_type,
    requestId: row.request_id,
    capabilityId: row.capability_id,
    agentId: row.agent_id,
    approvalId: row.approval_id,
    transactionId: row.transaction_id,
    decision: row.decision,
    code: row.code,
    reason: row.reason,
    payload: JSON.parse(row.payload),
    prevHash: row.prev_hash,
    entryHash: row.entry_hash,
    timestamp: row.timestamp,
  };
}

export type AuditAppendInput = {
  eventType: AuditEvent;
  requestId?: string;
  capabilityId?: string;
  agentId?: string;
  approvalId?: string;
  transactionId?: string;
  decision?: string;
  code?: DecisionCode | string;
  reason?: string;
  payload?: unknown;
  timestamp?: number;
};

/** Retained shape from v0.4, so the legacy `audit_logs` table keeps filling. */
type LegacyAuditEntry = {
  requestId: string;
  intent: Intent;
  result: EvaluationResult;
};

export type ChainVerification =
  | { valid: true; entries: number; headHash: string }
  | {
      valid: false;
      entries: number;
      brokenAtSeq: number;
      expected: string;
      found: string;
      problem: "HASH_MISMATCH" | "BROKEN_LINK" | "SEQUENCE_GAP";
    };

export class AuditStore {
  private readonly legacyInsertStatement = db.prepare(`
    INSERT INTO audit_logs (
      request_id, capability_id, agent_id, action,
      decision, policy_code, reason,
      amount_usd, slippage_bps, timestamp
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  private readonly headStatement = db.prepare(`
    SELECT seq, entry_hash FROM audit_chain ORDER BY seq DESC LIMIT 1
  `);

  private readonly chainInsertStatement = db.prepare(`
    INSERT INTO audit_chain (
      seq, event_type, request_id, capability_id, agent_id,
      approval_id, transaction_id, decision, code, reason,
      payload, prev_hash, entry_hash, timestamp
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  private readonly listStatement = db.prepare(`
    SELECT * FROM audit_chain ORDER BY seq DESC LIMIT ?
  `);

  private readonly byRequestStatement = db.prepare(`
    SELECT * FROM audit_chain WHERE request_id = ? ORDER BY seq ASC
  `);

  private readonly allAscStatement = db.prepare(`
    SELECT * FROM audit_chain ORDER BY seq ASC
  `);

  /**
   * Appends one entry and links it to the current head.
   *
   * Reading the head and inserting must not interleave with another append, or
   * two entries would claim the same predecessor and the chain would fork. The
   * whole operation therefore runs inside an IMMEDIATE transaction, which takes
   * a write lock up front instead of upgrading mid-way and risking SQLITE_BUSY.
   */
  append(input: AuditAppendInput): AuditChainEntry {
    const timestamp = input.timestamp ?? Math.floor(Date.now() / 1000);

    const write = db.transaction(() => {
      const head = this.headStatement.get() as
        | { seq: number; entry_hash: string }
        | null
        | undefined;

      const seq = (head?.seq ?? 0) + 1;
      const prevHash = head?.entry_hash ?? GENESIS_HASH;

      const normalized = {
        seq,
        eventType: input.eventType,
        requestId: input.requestId ?? null,
        capabilityId: input.capabilityId ?? null,
        agentId: input.agentId ?? null,
        approvalId: input.approvalId ?? null,
        transactionId: input.transactionId ?? null,
        decision: input.decision ?? null,
        code: input.code ?? null,
        reason: input.reason ?? null,
        payload: input.payload ?? null,
        prevHash,
        timestamp,
      };

      const entryHash = `0x${sha256Hex(entryPreimage(normalized))}`;

      this.chainInsertStatement.run(
        seq,
        normalized.eventType,
        normalized.requestId,
        normalized.capabilityId,
        normalized.agentId,
        normalized.approvalId,
        normalized.transactionId,
        normalized.decision,
        normalized.code,
        normalized.reason,
        JSON.stringify(normalized.payload),
        prevHash,
        entryHash,
        timestamp,
      );

      return { ...normalized, entryHash } satisfies AuditChainEntry;
    });

    return db.transaction(write).immediate();
  }

  /** Writes the v0.4 flat audit row. Kept so existing tooling keeps working. */
  write(entry: LegacyAuditEntry): void {
    this.legacyInsertStatement.run(
      entry.requestId,
      entry.intent.capabilityId,
      entry.intent.agentId,
      entry.intent.action,
      entry.result.allowed ? "ALLOW" : (entry.result.decision ?? "DENY"),
      entry.result.code,
      entry.result.reason,
      entry.intent.amountUsd,
      entry.intent.slippageBps,
      Math.floor(Date.now() / 1000),
    );

    this.append({
      eventType: "POLICY_EVALUATED",
      requestId: entry.requestId,
      capabilityId: entry.intent.capabilityId,
      agentId: entry.intent.agentId,
      decision: entry.result.allowed
        ? "ALLOW"
        : (entry.result.decision ?? "DENY"),
      code: entry.result.code,
      reason: entry.result.reason,
      payload: {
        action: entry.intent.action,
        protocol: entry.intent.protocol,
        chainId: entry.intent.chainId,
        declaredAmountUsd: entry.intent.amountUsd,
        slippageBps: entry.intent.slippageBps,
        nonce: entry.intent.nonce,
      },
    });
  }

  list(limit = 100): AuditChainEntry[] {
    return (this.listStatement.all(limit) as ChainRow[]).map(rowToEntry);
  }

  byRequest(requestId: string): AuditChainEntry[] {
    return (this.byRequestStatement.all(requestId) as ChainRow[]).map(
      rowToEntry,
    );
  }

  head(): { seq: number; hash: string } {
    const row = this.headStatement.get() as
      | { seq: number; entry_hash: string }
      | null
      | undefined;

    return row
      ? { seq: row.seq, hash: row.entry_hash }
      : { seq: 0, hash: GENESIS_HASH };
  }

  /**
   * Recomputes the entire chain and reports the first break.
   *
   * This is what makes the audit log evidence rather than a convenience: an
   * operator — or a judge — can confirm that no decision was removed or edited
   * after the fact, without trusting the process that wrote it.
   */
  verifyChain(): ChainVerification {
    const rows = this.allAscStatement.all() as ChainRow[];

    let prevHash = GENESIS_HASH;
    let expectedSeq = 1;

    for (const row of rows) {
      if (row.seq !== expectedSeq) {
        return {
          valid: false,
          entries: rows.length,
          brokenAtSeq: row.seq,
          expected: String(expectedSeq),
          found: String(row.seq),
          problem: "SEQUENCE_GAP",
        };
      }

      if (row.prev_hash !== prevHash) {
        return {
          valid: false,
          entries: rows.length,
          brokenAtSeq: row.seq,
          expected: prevHash,
          found: row.prev_hash,
          problem: "BROKEN_LINK",
        };
      }

      const recomputed = `0x${sha256Hex(
        entryPreimage({
          seq: row.seq,
          eventType: row.event_type,
          requestId: row.request_id,
          capabilityId: row.capability_id,
          agentId: row.agent_id,
          approvalId: row.approval_id,
          transactionId: row.transaction_id,
          decision: row.decision,
          code: row.code,
          reason: row.reason,
          payload: JSON.parse(row.payload),
          prevHash: row.prev_hash,
          timestamp: row.timestamp,
        }),
      )}`;

      if (recomputed !== row.entry_hash) {
        return {
          valid: false,
          entries: rows.length,
          brokenAtSeq: row.seq,
          expected: recomputed,
          found: row.entry_hash,
          problem: "HASH_MISMATCH",
        };
      }

      prevHash = row.entry_hash;
      expectedSeq += 1;
    }

    return { valid: true, entries: rows.length, headHash: prevHash };
  }
}
