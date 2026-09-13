import { ArxError } from "../core/errors";
import type { AuditStore } from "../storage/audit-store";
import type { ApprovalStore } from "../storage/approval-store";
import type { SpendStore } from "../storage/spend-store";
import { canTransition, type Approval } from "../types/approval";

/**
 * The escalation queue.
 *
 * When the policy layer escalates, the proposal is neither approved nor
 * rejected: it is parked as `PENDING_HUMAN` until a person resolves it. This
 * module is the only way that resolution happens.
 *
 * ## This is a control-plane surface
 *
 * Resolving an escalation *grants* authority. The agent that proposed the
 * transaction must therefore never be able to resolve it — otherwise escalation
 * is theatre: an agent tripping a risk rule would simply approve itself, and
 * invariant 10 ("any high-risk action can be routed to explicit human
 * approval") would be unenforceable.
 *
 * Two layers enforce that here:
 *
 *  1. Routes exposing these methods must sit behind `requireAdmin()` from
 *     `src/auth/middleware.ts`. Agent HMAC credentials must not reach them.
 *  2. `decidedBy` is checked at runtime against the approval's own `agentId`,
 *     so even a misrouted call cannot self-approve.
 *
 * Layer 2 is a backstop, not the control. Layer 1 is the control.
 */

/**
 * A resolved control-plane operator. Constructing one is an assertion that the
 * caller authenticated an *operator*, not an agent; take this type in any new
 * code path so the requirement is visible in the signature rather than only in
 * a comment.
 */
export type ControlPlaneOperator = {
  readonly plane: "CONTROL";
  readonly id: string;
};

export function controlPlaneOperator(id: string): ControlPlaneOperator {
  if (!id.trim()) {
    throw new ArxError("UNAUTHENTICATED", "Operator identity is required");
  }

  return { plane: "CONTROL", id: id.trim() };
}

function operatorId(decidedBy: string | ControlPlaneOperator): string {
  const id = typeof decidedBy === "string" ? decidedBy.trim() : decidedBy.id;

  if (!id) {
    throw new ArxError(
      "UNAUTHENTICATED",
      "A human decision must record who made it",
    );
  }

  return id;
}

export type HumanApprovalQueueDependencies = {
  approvalStore: ApprovalStore;
  /** Releasing a rejected escalation's reservation is not optional in practice. */
  spendStore?: SpendStore;
  auditStore?: AuditStore;
};

export class HumanApprovalQueue {
  private readonly approvalStore: ApprovalStore;
  private readonly spendStore?: SpendStore;
  private readonly auditStore?: AuditStore;

  constructor(dependencies: HumanApprovalQueueDependencies) {
    this.approvalStore = dependencies.approvalStore;
    this.spendStore = dependencies.spendStore;
    this.auditStore = dependencies.auditStore;
  }

  /** Escalations awaiting a decision, newest first. */
  listPending(limit = 100): Approval[] {
    return this.approvalStore.listByStatus("PENDING_HUMAN", limit);
  }

  /** Pending escalations that can no longer be approved, for operator display. */
  listPendingOverdue(
    now = Math.floor(Date.now() / 1000),
    limit = 100,
  ): Approval[] {
    return this.listPending(limit).filter(
      (approval) => now >= approval.expiresAt,
    );
  }

  get(approvalId: string): Approval | null {
    return this.approvalStore.get(approvalId);
  }

  /**
   * Grants an escalated approval.
   *
   * `PENDING_HUMAN -> APPROVED` only. The approval's `expiresAt` is *not*
   * extended: it is inside the signed binding payload, so moving it would
   * invalidate the authorization signature. `ARX_HUMAN_APPROVAL_TTL_SECONDS`
   * must therefore cover the review wait plus the agent's signing window.
   */
  approve(
    approvalId: string,
    decidedBy: string | ControlPlaneOperator,
    options: { now?: number } = {},
  ): Approval {
    const now = options.now ?? Math.floor(Date.now() / 1000);
    const actor = operatorId(decidedBy);
    const approval = this.requirePending(approvalId, actor);

    if (now >= approval.expiresAt) {
      // Expire it here rather than approving late: an escalation that timed out
      // has to be re-proposed, so the fresh decision is made against fresh
      // prices, risk and capability state.
      this.approvalStore.transition(approvalId, "PENDING_HUMAN", "EXPIRED");
      this.releaseReservation(approvalId, now);

      throw new ArxError(
        "APPROVAL_EXPIRED",
        "Escalation expired before it was decided",
        { details: { approvalId, expiresAt: approval.expiresAt } },
      );
    }

    this.assertTransition(approval, "APPROVED");

    const won = this.approvalStore.decide(
      approvalId,
      "PENDING_HUMAN",
      "APPROVED",
      actor,
      now,
    );

    if (!won) {
      // Another operator (or the expiry sweeper) resolved it first.
      throw new ArxError(
        "APPROVAL_STATE_CONFLICT",
        "Escalation was already resolved",
        { details: { approvalId } },
      );
    }

    this.auditStore?.append({
      eventType: "HUMAN_APPROVAL_GRANTED",
      requestId: approval.requestId,
      capabilityId: approval.capabilityId,
      agentId: approval.agentId,
      approvalId: approval.approvalId,
      transactionId: approval.transactionId,
      decision: "ALLOW",
      code: "POLICY_APPROVED",
      reason: `Escalation granted by ${actor}`,
      payload: {
        decidedBy: actor,
        riskScore: approval.riskScore,
        valueUsd: approval.valueUsd,
      },
      timestamp: now,
    });

    return this.reread(approvalId);
  }

  /**
   * Denies an escalated approval. Terminal — `REJECTED` has no outgoing
   * transitions, so a denied proposal can never be revived.
   *
   * The spend reservation taken at approval time is released, because a
   * rejected proposal must not permanently consume the agent's budget.
   */
  reject(
    approvalId: string,
    decidedBy: string | ControlPlaneOperator,
    reason: string,
    options: { now?: number } = {},
  ): Approval {
    const now = options.now ?? Math.floor(Date.now() / 1000);
    const actor = operatorId(decidedBy);
    const approval = this.requirePending(approvalId, actor);

    this.assertTransition(approval, "REJECTED");

    const won = this.approvalStore.decide(
      approvalId,
      "PENDING_HUMAN",
      "REJECTED",
      actor,
      now,
    );

    if (!won) {
      throw new ArxError(
        "APPROVAL_STATE_CONFLICT",
        "Escalation was already resolved",
        { details: { approvalId } },
      );
    }

    this.releaseReservation(approvalId, now);

    this.auditStore?.append({
      eventType: "HUMAN_APPROVAL_DENIED",
      requestId: approval.requestId,
      capabilityId: approval.capabilityId,
      agentId: approval.agentId,
      approvalId: approval.approvalId,
      transactionId: approval.transactionId,
      decision: "DENY",
      code: "APPROVAL_REJECTED",
      reason: reason || `Escalation denied by ${actor}`,
      payload: { decidedBy: actor, reason },
      timestamp: now,
    });

    return this.reread(approvalId);
  }

  private requirePending(approvalId: string, actor: string): Approval {
    const approval = this.approvalStore.get(approvalId);

    if (!approval) {
      throw new ArxError("APPROVAL_NOT_FOUND", "Approval does not exist", {
        details: { approvalId },
      });
    }

    if (approval.status !== "PENDING_HUMAN") {
      throw new ArxError(
        "APPROVAL_STATE_CONFLICT",
        `Approval is ${approval.status}, not awaiting human review`,
        { details: { approvalId, status: approval.status } },
      );
    }

    if (actor === approval.agentId) {
      throw new ArxError(
        "FORBIDDEN",
        "An agent cannot resolve its own escalation",
        { details: { approvalId, agentId: approval.agentId } },
      );
    }

    return approval;
  }

  private assertTransition(
    approval: Approval,
    to: "APPROVED" | "REJECTED",
  ): void {
    if (!canTransition(approval.status, to)) {
      throw new ArxError(
        "APPROVAL_STATE_CONFLICT",
        `Cannot move approval from ${approval.status} to ${to}`,
        { details: { approvalId: approval.approvalId } },
      );
    }
  }

  private releaseReservation(approvalId: string, now: number): void {
    this.spendStore?.release(approvalId, now);
  }

  private reread(approvalId: string): Approval {
    const updated = this.approvalStore.get(approvalId);

    if (!updated) {
      throw new ArxError(
        "INTERNAL_ERROR",
        "Approval vanished after being decided",
      );
    }

    return updated;
  }
}
