import { randomUUID } from "node:crypto";

import type { DecisionCode } from "../core/codes";
import { ArxError } from "../core/errors";
import { env } from "../config/env";
import {
  AuthorizationKey,
  authorizationKey as defaultAuthorizationKey,
} from "../crypto/authorization-key";
import { POLICY_VERSION } from "../policy/policy-engine";
import { ApprovalStore } from "../storage/approval-store";
import {
  approvalBindingPayload,
  canTransition,
  type Approval,
  type ApprovalStatus,
} from "../types/approval";
import type { EvaluationResult } from "../types/evaluation";
import type { NormalizedTransaction } from "../types/transaction";
import { hashNormalizedTransaction } from "./transaction-hash";

/**
 * The approval artifact: the only thing that authorizes a signature.
 *
 * Three properties matter, and each one is a separate defence:
 *
 *  1. It is bound to one transaction, by hash — so the bytes signed are the
 *     bytes approved (invariant 3).
 *  2. It is signed by Arx's authorization key — so a forged row in the database
 *     is not by itself sufficient to obtain a signature.
 *  3. It is claimed atomically before signing — so two concurrent requests can
 *     never both spend one approval (invariant 5).
 */

export type ApprovalVerification =
  | { valid: true; code: "POLICY_APPROVED"; reason: string }
  | { valid: false; code: DecisionCode; reason: string };

export type CreateApprovalInput = {
  requestId: string;
  capabilityId: string;
  agentId: string;
  transaction: NormalizedTransaction;

  /**
   * The decision that produced this approval — the firewall/policy result.
   * `decision: "ESCALATE"` (or code `HUMAN_APPROVAL_REQUIRED`) creates a
   * `PENDING_HUMAN` approval; an allow creates an `APPROVED` one. A denial is
   * rejected outright: nothing should be minting approvals from a denial.
   */
  decision: EvaluationResult;

  /**
   * The granting capability's expiry. An approval must never outlive its grant,
   * so this caps the TTL — otherwise a 15-minute escalation window would
   * outlive a capability with 30 seconds left and authorize a signature after
   * the authority behind it was gone.
   */
  capabilityExpiresAt: number;

  /** Oracle-derived, not agent-claimed. */
  valueUsd?: number;
  /** Risk engine output, 0-100. */
  riskScore?: number;

  /** Injected so the decision is deterministic and testable. */
  now?: number;
  policyVersion?: string;
};

/** Statuses that cannot authorize a signature, and the code each one reports. */
const NON_USABLE_STATUS_CODES: Record<
  Exclude<ApprovalStatus, "APPROVED">,
  { code: DecisionCode; reason: string }
> = {
  PENDING_HUMAN: {
    code: "APPROVAL_PENDING_HUMAN",
    reason: "Approval is awaiting human confirmation",
  },
  SIGNING: {
    code: "APPROVAL_STATE_CONFLICT",
    reason: "Approval has already been claimed for signing",
  },
  CONSUMED: {
    code: "APPROVAL_ALREADY_CONSUMED",
    reason: "Approval has already been used to obtain a signature",
  },
  SIGNING_FAILED: {
    code: "APPROVAL_STATE_CONFLICT",
    reason:
      "A signing attempt against this approval already failed; it is not retryable",
  },
  REJECTED: {
    code: "APPROVAL_REJECTED",
    reason: "Approval was rejected by a human reviewer",
  },
  REVOKED: {
    code: "APPROVAL_INVALID",
    reason: "Approval was revoked",
  },
  EXPIRED: {
    code: "APPROVAL_EXPIRED",
    reason: "Approval has expired",
  },
};

export class ApprovalService {
  constructor(
    private readonly approvalStore: ApprovalStore,
    /** Injectable so tests can verify against a key they control. */
    private readonly authorizationKey: AuthorizationKey = defaultAuthorizationKey,
  ) {}

  /** The public key an external verifier needs, plus its fingerprint. */
  authorizationKeyInfo(): {
    keyId: string;
    publicKeyPem: string;
    ephemeral: boolean;
  } {
    return {
      keyId: this.authorizationKey.keyId,
      publicKeyPem: this.authorizationKey.publicKeyPem(),
      ephemeral: this.authorizationKey.ephemeral,
    };
  }

  createApproval(input: CreateApprovalInput): Approval {
    const now = input.now ?? Math.floor(Date.now() / 1000);
    const decision = input.decision;

    const escalated =
      decision.decision === "ESCALATE" ||
      decision.code === "HUMAN_APPROVAL_REQUIRED";

    if (!escalated && !decision.allowed) {
      // Fail closed: a denial has no approval artifact. Reaching here means a
      // caller ignored the decision, which is a defect, not a request outcome.
      throw new ArxError(
        "INTERNAL_ERROR",
        "Cannot create an approval from a denied decision",
        { details: { code: decision.code } },
      );
    }

    if (input.capabilityExpiresAt <= now) {
      throw new ArxError(
        "CAPABILITY_EXPIRED",
        "Capability expired before an approval could be issued",
      );
    }

    const ttl = escalated
      ? env.humanApprovalTtlSeconds
      : env.approvalTtlSeconds;

    // An approval never outlives its grant. Note that the human TTL must cover
    // both the reviewer's wait *and* the agent's signing window: `expiresAt` is
    // inside the signed binding payload, so it cannot be extended on approval
    // without invalidating the signature.
    const expiresAt = Math.min(now + Math.max(1, Math.floor(ttl)), input.capabilityExpiresAt);

    const unsigned: Approval = {
      approvalId: randomUUID(),
      requestId: input.requestId,
      capabilityId: input.capabilityId,
      agentId: input.agentId,
      transactionId: input.transaction.transactionId,
      transactionHash: hashNormalizedTransaction(input.transaction),
      chainId: input.transaction.transaction.chainId,
      policyCode: escalated ? "HUMAN_APPROVAL_REQUIRED" : "POLICY_APPROVED",
      policyVersion: input.policyVersion ?? POLICY_VERSION,
      approvalType: escalated ? "HUMAN" : "AUTO",
      riskScore: clamp(input.riskScore ?? 0, 0, 100),
      valueUsd: Math.max(0, input.valueUsd ?? 0),
      createdAt: now,
      expiresAt,
      status: escalated ? "PENDING_HUMAN" : "APPROVED",
      reason: decision.reason,
    };

    const approval: Approval = {
      ...unsigned,
      authorizationSignature: this.authorizationKey.sign(
        approvalBindingPayload(unsigned),
      ),
      authorizationKeyId: this.authorizationKey.keyId,
    };

    return this.approvalStore.create(approval);
  }

  /**
   * Full verification of an approval against the transaction being presented.
   *
   * Every failure names a specific code. The checks are ordered cheapest-first,
   * but each is independent: none of them can be satisfied by controlling the
   * request alone.
   */
  verifyApproval(input: {
    approval: Approval;
    transaction: NormalizedTransaction;
    currentTime?: number;
  }): ApprovalVerification {
    const currentTime = input.currentTime ?? Math.floor(Date.now() / 1000);
    const { approval, transaction } = input;

    if (approval.status !== "APPROVED") {
      const outcome = NON_USABLE_STATUS_CODES[approval.status];
      return { valid: false, code: outcome.code, reason: outcome.reason };
    }

    if (currentTime >= approval.expiresAt) {
      return {
        valid: false,
        code: "APPROVAL_EXPIRED",
        reason: "Approval has expired",
      };
    }

    if (approval.agentId !== transaction.agentId) {
      return {
        valid: false,
        code: "AGENT_MISMATCH",
        reason: "Approval was issued to a different agent",
      };
    }

    if (approval.capabilityId !== transaction.capabilityId) {
      return {
        valid: false,
        code: "CAPABILITY_ID_MISMATCH",
        reason: "Approval was issued under a different capability",
      };
    }

    if (approval.transactionId !== transaction.transactionId) {
      return {
        valid: false,
        code: "TRANSACTION_HASH_MISMATCH",
        reason: "Transaction identity does not match the approval",
      };
    }

    if (approval.chainId !== transaction.transaction.chainId) {
      return {
        valid: false,
        code: "TRANSACTION_CHAIN_MISMATCH",
        reason: "Transaction chain does not match the approval",
      };
    }

    if (hashNormalizedTransaction(transaction) !== approval.transactionHash) {
      return {
        valid: false,
        code: "TRANSACTION_HASH_MISMATCH",
        reason: "Transaction does not hash to the approved transaction",
      };
    }

    if (!approval.authorizationSignature || !approval.authorizationKeyId) {
      return {
        valid: false,
        code: "APPROVAL_SIGNATURE_INVALID",
        reason: "Approval carries no authorization signature",
      };
    }

    if (approval.authorizationKeyId !== this.authorizationKey.keyId) {
      // Either the key rotated or the approval was signed by something else.
      // Both must fail: an unverifiable approval is not a valid one. With an
      // ephemeral key this is also what a restart looks like.
      return {
        valid: false,
        code: "APPROVAL_SIGNATURE_INVALID",
        reason: `Approval was signed by key ${approval.authorizationKeyId}, not the active key`,
      };
    }

    if (
      !this.authorizationKey.verify(
        approvalBindingPayload(approval),
        approval.authorizationSignature,
      )
    ) {
      return {
        valid: false,
        code: "APPROVAL_SIGNATURE_INVALID",
        reason: "Authorization signature does not verify over the approval",
      };
    }

    return {
      valid: true,
      code: "POLICY_APPROVED",
      reason: "Approval is valid and bound to this transaction",
    };
  }

  /**
   * Atomically takes exclusive ownership of an approval for one signing attempt.
   *
   * This must happen *before* any bytes reach the signer. Calling the signer
   * first and consuming afterwards — the old ordering — let two concurrent
   * requests both obtain a signature from one approval, because both passed
   * verification while the status was still APPROVED.
   *
   * Returns false when another caller won the race, or when the approval was
   * not in APPROVED at all.
   */
  claimForSigning(approvalId: string): boolean {
    return this.transition(approvalId, "APPROVED", "SIGNING");
  }

  /** Terminal success: the approval produced a signature and is now spent. */
  markSigned(approvalId: string): boolean {
    return this.transition(approvalId, "SIGNING", "CONSUMED");
  }

  /**
   * Terminal failure. Deliberately not returned to APPROVED: a failed attempt
   * may have reached the device, so the same approval must never be retryable.
   * A new authorization request is the correct recovery path.
   */
  markSigningFailed(approvalId: string): boolean {
    return this.transition(approvalId, "SIGNING", "SIGNING_FAILED");
  }

  get(approvalId: string): Approval | null {
    return this.approvalStore.get(approvalId);
  }

  private transition(
    approvalId: string,
    from: ApprovalStatus,
    to: ApprovalStatus,
  ): boolean {
    if (!canTransition(from, to)) {
      throw new ArxError(
        "INTERNAL_ERROR",
        `Illegal approval transition ${from} -> ${to}`,
      );
    }

    return this.approvalStore.transition(approvalId, from, to);
  }
}

function clamp(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) {
    return min;
  }

  return Math.min(max, Math.max(min, value));
}
