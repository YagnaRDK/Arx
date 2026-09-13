import { db } from "../db/database";
import { ArxError } from "../core/errors";
import {
  ApprovalSchema,
  canTransition,
  type Approval,
  type ApprovalStatus,
  type ApprovalType,
} from "../types/approval";

type ApprovalRow = {
  approval_id: string;
  request_id: string;
  capability_id: string;
  agent_id: string;
  transaction_id: string;
  transaction_hash: string;
  chain_id: number;
  policy_code: "POLICY_APPROVED" | "HUMAN_APPROVAL_REQUIRED";
  policy_version: string;
  approval_type: ApprovalType;
  risk_score: number;
  value_usd: number;
  created_at: number;
  expires_at: number;
  status: ApprovalStatus;
  reason: string;
  authorization_signature: string | null;
  authorization_key_id: string | null;
  decided_by: string | null;
  decided_at: number | null;
  summary: string | null;
};

function rowToApproval(row: ApprovalRow): Approval {
  return ApprovalSchema.parse({
    approvalId: row.approval_id,
    requestId: row.request_id,
    capabilityId: row.capability_id,
    agentId: row.agent_id,
    transactionId: row.transaction_id,
    transactionHash: row.transaction_hash,
    chainId: row.chain_id,
    policyCode: row.policy_code,
    policyVersion: row.policy_version,
    approvalType: row.approval_type,
    riskScore: row.risk_score,
    valueUsd: row.value_usd,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    status: row.status,
    reason: row.reason,
    authorizationSignature: row.authorization_signature ?? undefined,
    authorizationKeyId: row.authorization_key_id ?? undefined,
    decidedBy: row.decided_by ?? undefined,
    decidedAt: row.decided_at ?? undefined,
    summary: row.summary ? JSON.parse(row.summary) : undefined,
  });
}

export class ApprovalStore {
  private readonly insertStatement = db.prepare(`
    INSERT INTO approvals (
      approval_id, request_id, capability_id, agent_id,
      transaction_id, transaction_hash, chain_id,
      policy_code, policy_version,
      approval_type, risk_score, value_usd,
      created_at, expires_at, status, reason,
      authorization_signature, authorization_key_id,
      decided_by, decided_at, summary
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  private readonly getStatement = db.prepare(`
    SELECT * FROM approvals WHERE approval_id = ?
  `);

  private readonly listStatement = db.prepare(`
    SELECT * FROM approvals ORDER BY created_at DESC LIMIT ?
  `);

  private readonly listByStatusStatement = db.prepare(`
    SELECT * FROM approvals WHERE status = ? ORDER BY created_at DESC LIMIT ?
  `);

  /**
   * Compare-and-swap status transition.
   *
   * The `AND status = ?` guard is what makes the transition atomic: SQLite
   * serialises the UPDATE, so of two concurrent callers attempting
   * APPROVED -> SIGNING exactly one sees `changes > 0`. This is the mechanism
   * that makes double-signing one approval impossible, and it is why nothing in
   * this codebase should ever read a status and then write it in two steps.
   */
  private readonly transitionStatement = db.prepare(`
    UPDATE approvals
    SET status = ?
    WHERE approval_id = ? AND status = ?
  `);

  private readonly decideStatement = db.prepare(`
    UPDATE approvals
    SET status = ?, decided_by = ?, decided_at = ?
    WHERE approval_id = ? AND status = ?
  `);

  private readonly expireStatement = db.prepare(`
    UPDATE approvals
    SET status = 'EXPIRED'
    WHERE expires_at <= ? AND status IN ('APPROVED', 'PENDING_HUMAN')
  `);

  create(approval: Approval): Approval {
    this.insertStatement.run(
      approval.approvalId,
      approval.requestId,
      approval.capabilityId,
      approval.agentId,
      approval.transactionId,
      approval.transactionHash,
      approval.chainId,
      approval.policyCode,
      approval.policyVersion,
      approval.approvalType,
      approval.riskScore,
      approval.valueUsd,
      approval.createdAt,
      approval.expiresAt,
      approval.status,
      approval.reason,
      approval.authorizationSignature ?? null,
      approval.authorizationKeyId ?? null,
      approval.decidedBy ?? null,
      approval.decidedAt ?? null,
      approval.summary ? JSON.stringify(approval.summary) : null,
    );

    return approval;
  }

  get(approvalId: string): Approval | null {
    const row = this.getStatement.get(approvalId) as
      | ApprovalRow
      | null
      | undefined;

    return row ? rowToApproval(row) : null;
  }

  list(limit = 100): Approval[] {
    return (this.listStatement.all(limit) as ApprovalRow[]).map(rowToApproval);
  }

  listByStatus(status: ApprovalStatus, limit = 100): Approval[] {
    return (
      this.listByStatusStatement.all(status, limit) as ApprovalRow[]
    ).map(rowToApproval);
  }

  /**
   * Returns false when the approval was not in `from`, i.e. someone else won.
   *
   * Legality is checked here as well as in `ApprovalService`. The service is
   * where the state machine is enforced and where the specific decision codes
   * come from; this is a backstop, so that a future call site added directly
   * against the store cannot write a transition the machine forbids. Belt and
   * braces on the one table whose integrity the signing guarantee rests on.
   */
  transition(
    approvalId: string,
    from: ApprovalStatus,
    to: ApprovalStatus,
  ): boolean {
    if (!canTransition(from, to)) {
      throw new ArxError(
        "APPROVAL_STATE_CONFLICT",
        `Illegal approval transition ${from} -> ${to}`,
        { details: { approvalId, from, to } },
      );
    }

    return this.transitionStatement.run(to, approvalId, from).changes > 0;
  }

  /** Records a human decision on an escalated approval. */
  decide(
    approvalId: string,
    from: ApprovalStatus,
    to: ApprovalStatus,
    decidedBy: string,
    now = Math.floor(Date.now() / 1000),
  ): boolean {
    return (
      this.decideStatement.run(to, decidedBy, now, approvalId, from).changes > 0
    );
  }

  /** Sweeps approvals whose deadline has passed. Returns how many were expired. */
  expireOverdue(now = Math.floor(Date.now() / 1000)): number {
    return this.expireStatement.run(now).changes;
  }
}
