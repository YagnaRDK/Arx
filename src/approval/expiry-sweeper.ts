import type { ApprovalStore } from "../storage/approval-store";
import type { AuditStore } from "../storage/audit-store";
import type { SpendStore } from "../storage/spend-store";

/**
 * Expires overdue approvals and gives back the budget they were holding.
 *
 * Expiry has two halves and doing only the first is a real bug. Marking an
 * approval EXPIRED stops it authorizing a signature (invariant 4), but the
 * spend row reserved when it was issued still counts against the capability's
 * rolling window. Without the release, an agent that escalates three
 * transactions nobody gets round to approving has permanently burned that
 * budget, and the window limit slowly strangles an agent that did nothing
 * wrong.
 */

export type SweepResult = {
  /** Approvals moved to EXPIRED by this sweep. */
  expired: number;
  /** Spend reservations released as a result. */
  released: number;
  at: number;
};

export type ExpirySweeperDependencies = {
  approvalStore: ApprovalStore;
  spendStore: SpendStore;
  auditStore?: AuditStore;
  /** Sweep period. 30s is frequent enough that a demo shows it working. */
  intervalMs?: number;
  /** Injected for tests; production reads the wall clock each sweep. */
  clock?: () => number;
};

export class ApprovalExpirySweeper {
  private readonly approvalStore: ApprovalStore;
  private readonly spendStore: SpendStore;
  private readonly auditStore?: AuditStore;
  private readonly intervalMs: number;
  private readonly clock: () => number;

  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(dependencies: ExpirySweeperDependencies) {
    this.approvalStore = dependencies.approvalStore;
    this.spendStore = dependencies.spendStore;
    this.auditStore = dependencies.auditStore;
    this.intervalMs = dependencies.intervalMs ?? 30_000;
    this.clock = dependencies.clock ?? (() => Math.floor(Date.now() / 1000));
  }

  get running(): boolean {
    return this.timer !== null;
  }

  /** Idempotent: calling it twice does not create a second interval. */
  start(): void {
    if (this.timer) {
      return;
    }

    this.timer = setInterval(() => {
      try {
        this.sweep();
      } catch {
        // A sweep failure must not kill the interval; the next tick retries.
        // Nothing is silently permitted by a missed sweep — an overdue approval
        // still fails verification on its own expiry check.
      }
    }, this.intervalMs);

    // Never hold the process open for a janitor.
    this.timer.unref?.();
  }

  stop(): void {
    if (!this.timer) {
      return;
    }

    clearInterval(this.timer);
    this.timer = null;
  }

  /**
   * One pass. Safe to call directly, which is how tests drive it.
   *
   * Candidates are collected before the bulk expiry, then each one is re-read
   * afterwards: a request may have claimed an approval for signing in between,
   * and `expireOverdue` will have left that one alone. Releasing its
   * reservation would hand back budget for a transaction that is about to be
   * signed, so only rows that actually reached EXPIRED are released.
   */
  sweep(now = this.clock()): SweepResult {
    const candidates = [
      ...this.approvalStore.listByStatus("APPROVED", 1000),
      ...this.approvalStore.listByStatus("PENDING_HUMAN", 1000),
    ].filter((approval) => approval.expiresAt <= now);

    const expired = this.approvalStore.expireOverdue(now);

    let released = 0;

    for (const candidate of candidates) {
      const current = this.approvalStore.get(candidate.approvalId);

      if (!current || current.status !== "EXPIRED") {
        continue;
      }

      if (this.spendStore.release(candidate.approvalId, now)) {
        released += 1;
      }

      this.auditStore?.append({
        eventType: "APPROVAL_EXPIRED",
        requestId: candidate.requestId,
        capabilityId: candidate.capabilityId,
        agentId: candidate.agentId,
        approvalId: candidate.approvalId,
        transactionId: candidate.transactionId,
        decision: "DENY",
        code: "APPROVAL_EXPIRED",
        reason: `Approval expired unused after ${candidate.expiresAt - candidate.createdAt}s`,
        payload: {
          previousStatus: candidate.status,
          approvalType: candidate.approvalType,
          spendReleased: true,
        },
        timestamp: now,
      });
    }

    return { expired, released, at: now };
  }
}
