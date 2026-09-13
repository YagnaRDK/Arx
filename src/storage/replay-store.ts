import { db } from "../db/database";

/**
 * Replay protection and nonce accounting.
 *
 * Two separate questions are answered here, and conflating them was the flaw in
 * the original design:
 *
 *   1. "Has this exact (capability, nonce) already been used?" — `processed_intents`
 *   2. "What is the highest nonce this capability has accepted?" — `capability_nonces`
 *
 * A reusable capability needs both. (1) alone cannot distinguish a fresh action
 * from a replayed one once a nonce is reused, and (2) alone would let an old
 * unused nonce below the high-water mark be replayed. Requiring a strictly
 * increasing nonce *and* recording each one used gives a reusable capability an
 * unbounded supply of future authorizations while making every past one dead.
 */
export class ReplayStore {
  private readonly existsStatement = db.prepare(`
    SELECT replay_key FROM processed_intents WHERE replay_key = ?
  `);

  /**
   * `INSERT OR IGNORE` against the primary key makes claiming a nonce atomic:
   * two concurrent requests carrying the same nonce produce one insert, and the
   * loser sees `changes === 0`. Checking-then-inserting would leave a window
   * between the two statements in which both callers believe they won.
   */
  private readonly claimStatement = db.prepare(`
    INSERT OR IGNORE INTO processed_intents (
      replay_key, capability_id, agent_id, nonce, processed_at
    )
    VALUES (?, ?, ?, ?, ?)
  `);

  private readonly highestStatement = db.prepare(`
    SELECT highest_nonce FROM capability_nonces WHERE capability_id = ?
  `);

  private readonly raiseHighestStatement = db.prepare(`
    INSERT INTO capability_nonces (capability_id, highest_nonce, updated_at)
    VALUES (?, ?, ?)
    ON CONFLICT (capability_id) DO UPDATE
      SET highest_nonce = MAX(highest_nonce, excluded.highest_nonce),
          updated_at = excluded.updated_at
  `);

  private createReplayKey(capabilityId: string, nonce: number): string {
    return `${capabilityId}:${nonce}`;
  }

  /** True when this capability has already used this nonce. */
  hasBeenProcessed(capabilityId: string, _agentId: string, nonce: number): boolean {
    const row = this.existsStatement.get(
      this.createReplayKey(capabilityId, nonce),
    ) as { replay_key: string } | null | undefined;

    return Boolean(row);
  }

  /**
   * Atomically claims a nonce. Returns false if it was already taken, which the
   * caller must treat as a replay.
   */
  claimNonce(
    capabilityId: string,
    agentId: string,
    nonce: number,
    now = Math.floor(Date.now() / 1000),
  ): boolean {
    const result = this.claimStatement.run(
      this.createReplayKey(capabilityId, nonce),
      capabilityId,
      agentId,
      nonce,
      now,
    );

    if (result.changes === 0) {
      return false;
    }

    this.raiseHighestStatement.run(capabilityId, nonce, now);

    return true;
  }

  /** The highest nonce accepted for this capability, or null if none yet. */
  highestNonce(capabilityId: string): number | null {
    const row = this.highestStatement.get(capabilityId) as
      | { highest_nonce: number }
      | null
      | undefined;

    return row ? row.highest_nonce : null;
  }

  /** Retained for compatibility; prefer `claimNonce`, which is atomic. */
  markProcessed(
    capabilityId: string,
    agentId: string,
    nonce: number,
    now = Math.floor(Date.now() / 1000),
  ): void {
    this.claimNonce(capabilityId, agentId, nonce, now);
  }
}
