import { db } from "../db/database";
import { hashCanonical } from "../crypto/hash";

/**
 * Idempotency for authorization requests.
 *
 * A network retry must not produce a second authorization. Without this, an
 * agent whose HTTP client retries on timeout gets two approvals — two
 * signatures' worth of authority — from one decision, and the spend window is
 * charged twice for one intended action.
 *
 * The record is keyed by (capabilityId, intentId) and commits to a hash of the
 * intent body, which separates the two cases that must never be confused:
 *
 *   - same id, same body  → a retry. Replay the stored response.
 *   - same id, other body → a *different* request wearing a used id. That is
 *     `INTENT_ID_CONFLICT`, never a fresh authorization.
 */

export type IdempotencyOutcome =
  | { kind: "FRESH" }
  | {
      kind: "REPLAY";
      status: number;
      body: unknown;
      /**
       * True when the original request is still in flight, so the stored
       * response is a placeholder rather than the real outcome. Callers should
       * surface it as a conflict-style "in progress", not as a decision.
       */
      pending: boolean;
    }
  | { kind: "CONFLICT" };

type RecordRow = {
  capability_id: string;
  intent_id: string;
  intent_hash: string;
  response_status: number;
  response_body: string;
  created_at: number;
};

/** Marks a claimed-but-unfinished record. A real response never has status 0. */
const PENDING_STATUS = 0;

const PENDING_BODY = JSON.stringify({
  allowed: false,
  code: "REPLAY_DETECTED",
  reason: "A request with this intentId is already in flight",
});

/** The hash an idempotency record commits to. Canonical, never JSON.stringify. */
export function hashIntentBody(body: unknown): string {
  return hashCanonical(body);
}

export class IdempotencyStore {
  /**
   * `INSERT OR IGNORE` against the composite primary key is what makes the
   * claim atomic. Reading first and then inserting would leave a window in
   * which two concurrent retries both see "no record" and both proceed as
   * FRESH, which is exactly the duplicate authorization this table exists to
   * prevent.
   */
  private readonly claimStatement = db.prepare(`
    INSERT OR IGNORE INTO idempotency_records (
      capability_id, intent_id, intent_hash,
      response_status, response_body, created_at
    )
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  private readonly getStatement = db.prepare(`
    SELECT * FROM idempotency_records
    WHERE capability_id = ? AND intent_id = ?
  `);

  private readonly completeStatement = db.prepare(`
    UPDATE idempotency_records
    SET response_status = ?, response_body = ?
    WHERE capability_id = ? AND intent_id = ? AND response_status = ?
  `);

  private readonly abandonStatement = db.prepare(`
    DELETE FROM idempotency_records
    WHERE capability_id = ? AND intent_id = ? AND response_status = ?
  `);

  private readonly purgeStatement = db.prepare(`
    DELETE FROM idempotency_records WHERE created_at < ?
  `);

  /**
   * Claims (capabilityId, intentId) for this request, or reports what the id was
   * already used for.
   *
   * `intentHash` must be `hashIntentBody(body)` over the same body on every
   * attempt, or a genuine retry will be misread as a conflict.
   */
  begin(
    capabilityId: string,
    intentId: string,
    intentHash: string,
    now = Math.floor(Date.now() / 1000),
  ): IdempotencyOutcome {
    const claimed = this.claimStatement.run(
      capabilityId,
      intentId,
      intentHash,
      PENDING_STATUS,
      PENDING_BODY,
      now,
    );

    if (claimed.changes > 0) {
      return { kind: "FRESH" };
    }

    const existing = this.getStatement.get(capabilityId, intentId) as
      | RecordRow
      | null
      | undefined;

    if (!existing) {
      // The row was claimed by someone else and then abandoned between our
      // insert and our read. Refuse rather than guess: a retry will resolve it,
      // and treating an unknown state as fresh is the failure mode that lets a
      // duplicate authorization through.
      return { kind: "CONFLICT" };
    }

    if (existing.intent_hash !== intentHash) {
      return { kind: "CONFLICT" };
    }

    return {
      kind: "REPLAY",
      status:
        existing.response_status === PENDING_STATUS
          ? 409
          : existing.response_status,
      body: parseBody(existing.response_body),
      pending: existing.response_status === PENDING_STATUS,
    };
  }

  /**
   * Records the response for a claimed record. Returns false if the record was
   * already completed, so a late writer cannot overwrite the response a retry
   * has already been served.
   */
  complete(
    capabilityId: string,
    intentId: string,
    status: number,
    body: unknown,
  ): boolean {
    if (status === PENDING_STATUS) {
      throw new Error("Idempotency response status 0 is reserved for pending");
    }

    return (
      this.completeStatement.run(
        status,
        JSON.stringify(body ?? null),
        capabilityId,
        intentId,
        PENDING_STATUS,
      ).changes > 0
    );
  }

  /**
   * Releases a claim that never produced a response (an unhandled crash in the
   * handler). Only a still-pending record is removed, so a completed response
   * can never be erased to unlock a second authorization.
   */
  abandon(capabilityId: string, intentId: string): boolean {
    return (
      this.abandonStatement.run(capabilityId, intentId, PENDING_STATUS)
        .changes > 0
    );
  }

  get(
    capabilityId: string,
    intentId: string,
  ): {
    intentHash: string;
    status: number;
    body: unknown;
    createdAt: number;
    pending: boolean;
  } | null {
    const row = this.getStatement.get(capabilityId, intentId) as
      | RecordRow
      | null
      | undefined;

    if (!row) {
      return null;
    }

    return {
      intentHash: row.intent_hash,
      status: row.response_status,
      body: parseBody(row.response_body),
      createdAt: row.created_at,
      pending: row.response_status === PENDING_STATUS,
    };
  }

  /** Drops records older than `cutoff`. Retention is an operator decision. */
  purgeOlderThan(cutoff: number): number {
    return this.purgeStatement.run(cutoff).changes;
  }
}

function parseBody(raw: string): unknown {
  try {
    return JSON.parse(raw);
  } catch {
    return { allowed: false, code: "INTERNAL_ERROR", reason: "Corrupt record" };
  }
}
