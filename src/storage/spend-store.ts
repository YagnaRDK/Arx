import { db } from "../db/database";

export type SpendState = "RESERVED" | "SETTLED" | "RELEASED";

export type SpendWindowUsage = {
  amountUsd: number;
  transactionCount: number;
  windowStart: number;
};

/**
 * Spend accounting across a rolling window.
 *
 * Authority is consumed when an approval is *issued*, not when it is signed: an
 * outstanding approval is a promise Arx has already made, and ignoring it would
 * let an agent hold ten unspent approvals against a one-transaction budget and
 * redeem them all. So rows are RESERVED at approval time, SETTLED once a
 * signature exists, and RELEASED if the approval expires or signing fails — the
 * last case matters, because a device rejection must not silently burn the
 * agent's remaining budget for the day.
 */
export class SpendStore {
  private readonly reserveStatement = db.prepare(`
    INSERT OR IGNORE INTO spend_ledger (
      capability_id, agent_id, approval_id,
      amount_usd, value_wei, state, created_at, updated_at
    )
    VALUES (?, ?, ?, ?, ?, 'RESERVED', ?, ?)
  `);

  private readonly setStateStatement = db.prepare(`
    UPDATE spend_ledger
    SET state = ?, updated_at = ?
    WHERE approval_id = ? AND state = ?
  `);

  /**
   * Only RESERVED and SETTLED rows count. RELEASED rows are retained for the
   * audit trail but must not consume budget.
   */
  private readonly usageStatement = db.prepare(`
    SELECT
      COALESCE(SUM(amount_usd), 0) AS amount_usd,
      COUNT(*) AS transaction_count
    FROM spend_ledger
    WHERE capability_id = ?
      AND created_at >= ?
      AND state IN ('RESERVED', 'SETTLED')
  `);

  private readonly listStatement = db.prepare(`
    SELECT * FROM spend_ledger
    WHERE capability_id = ?
    ORDER BY created_at DESC
    LIMIT ?
  `);

  reserve(input: {
    capabilityId: string;
    agentId: string;
    approvalId: string;
    amountUsd: number;
    valueWei: string;
    now?: number;
  }): boolean {
    const now = input.now ?? Math.floor(Date.now() / 1000);

    return (
      this.reserveStatement.run(
        input.capabilityId,
        input.agentId,
        input.approvalId,
        input.amountUsd,
        input.valueWei,
        now,
        now,
      ).changes > 0
    );
  }

  settle(approvalId: string, now = Math.floor(Date.now() / 1000)): boolean {
    return (
      this.setStateStatement.run("SETTLED", now, approvalId, "RESERVED")
        .changes > 0
    );
  }

  release(approvalId: string, now = Math.floor(Date.now() / 1000)): boolean {
    return (
      this.setStateStatement.run("RELEASED", now, approvalId, "RESERVED")
        .changes > 0
    );
  }

  usage(
    capabilityId: string,
    windowSeconds: number,
    now = Math.floor(Date.now() / 1000),
  ): SpendWindowUsage {
    const windowStart = now - windowSeconds;

    const row = this.usageStatement.get(capabilityId, windowStart) as {
      amount_usd: number;
      transaction_count: number;
    };

    return {
      amountUsd: row.amount_usd,
      transactionCount: row.transaction_count,
      windowStart,
    };
  }

  list(capabilityId: string, limit = 50) {
    return this.listStatement.all(capabilityId, limit) as Array<{
      id: number;
      capability_id: string;
      agent_id: string;
      approval_id: string;
      amount_usd: number;
      value_wei: string;
      state: SpendState;
      created_at: number;
      updated_at: number;
    }>;
  }
}
