import { db } from "../db/database";
import type { EvaluationResult } from "../types/evaluation";
import type { Intent } from "../types/intent";

type AuditEntry = {
  requestId: string;
  intent: Intent;
  result: EvaluationResult;
};

export class AuditStore {
  private readonly insertStatement = db.prepare(`
    INSERT INTO audit_logs (
      request_id,
      capability_id,
      agent_id,
      action,
      decision,
      policy_code,
      reason,
      amount_usd,
      slippage_bps,
      timestamp
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  write(entry: AuditEntry): void {
    this.insertStatement.run(
      entry.requestId,
      entry.intent.capabilityId,
      entry.intent.agentId,
      entry.intent.action,
      entry.result.allowed ? "ALLOW" : "DENY",
      entry.result.code,
      entry.result.reason,
      entry.intent.amountUsd,
      entry.intent.slippageBps,
      Math.floor(Date.now() / 1000),
    );
  }
}
