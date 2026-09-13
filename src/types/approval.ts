import { z } from "zod";

/**
 * The approval lifecycle.
 *
 * `SIGNING` exists so that claiming an approval and using it are separate,
 * atomic steps: a signer request transitions APPROVED -> SIGNING before any
 * bytes reach the device, which makes it impossible for two concurrent requests
 * to both sign against one approval. A crash mid-signing leaves the approval in
 * SIGNING, where it is unusable but still auditable.
 */
export const ApprovalStatusSchema = z.enum([
  "PENDING_HUMAN",
  "APPROVED",
  "SIGNING",
  "CONSUMED",
  "SIGNING_FAILED",
  "REJECTED",
  "REVOKED",
  "EXPIRED",
]);

export type ApprovalStatus = z.infer<typeof ApprovalStatusSchema>;

export const ApprovalTypeSchema = z.enum(["AUTO", "HUMAN"]);
export type ApprovalType = z.infer<typeof ApprovalTypeSchema>;

/** Status transitions Arx will perform. Anything absent here is rejected. */
const ALLOWED_TRANSITIONS: Record<ApprovalStatus, readonly ApprovalStatus[]> = {
  PENDING_HUMAN: ["APPROVED", "REJECTED", "EXPIRED", "REVOKED"],
  APPROVED: ["SIGNING", "EXPIRED", "REVOKED"],
  SIGNING: ["CONSUMED", "SIGNING_FAILED"],
  CONSUMED: [],
  SIGNING_FAILED: [],
  REJECTED: [],
  REVOKED: [],
  EXPIRED: [],
};

export function canTransition(
  from: ApprovalStatus,
  to: ApprovalStatus,
): boolean {
  return ALLOWED_TRANSITIONS[from].includes(to);
}

/** Statuses from which no further transition is possible. */
export function isTerminal(status: ApprovalStatus): boolean {
  return ALLOWED_TRANSITIONS[status].length === 0;
}

export const ApprovalSchema = z.object({
  approvalId: z.string().min(1),
  requestId: z.string().min(1),

  capabilityId: z.string().min(1),
  agentId: z.string().min(1),

  transactionId: z.string().min(1),
  /** The exact transaction this approval authorizes, and nothing else. */
  transactionHash: z.string().regex(/^0x[a-fA-F0-9]{64}$/),

  chainId: z.number().int().positive(),

  policyCode: z.enum(["POLICY_APPROVED", "HUMAN_APPROVAL_REQUIRED"]),
  policyVersion: z.string().min(1),

  approvalType: ApprovalTypeSchema,
  riskScore: z.number().min(0).max(100),

  /** USD value as determined by the oracle, not as claimed by the agent. */
  valueUsd: z.number().nonnegative(),

  createdAt: z.number().int().positive(),
  expiresAt: z.number().int().positive(),

  status: ApprovalStatusSchema,

  /** Why this approval exists: the firewall findings that produced it. */
  reason: z.string(),

  /**
   * Arx's own signature over the approval's binding fields. The signer boundary
   * verifies this before touching the device, so a forged approval row in the
   * database is not by itself sufficient to obtain a signature.
   */
  authorizationSignature: z.string().min(1).optional(),
  authorizationKeyId: z.string().min(1).optional(),

  /** Set once a human resolves an escalation. */
  decidedBy: z.string().min(1).optional(),
  decidedAt: z.number().int().positive().optional(),
});

export type Approval = z.infer<typeof ApprovalSchema>;

/**
 * The subset of an approval that is cryptographically bound. Mutable lifecycle
 * fields (`status`, `decidedAt`) are excluded so the signature stays valid as
 * the approval moves through its state machine.
 */
export function approvalBindingPayload(approval: Approval) {
  return {
    approvalId: approval.approvalId,
    requestId: approval.requestId,
    capabilityId: approval.capabilityId,
    agentId: approval.agentId,
    transactionId: approval.transactionId,
    transactionHash: approval.transactionHash,
    chainId: approval.chainId,
    policyCode: approval.policyCode,
    policyVersion: approval.policyVersion,
    approvalType: approval.approvalType,
    riskScore: approval.riskScore,
    valueUsd: approval.valueUsd,
    createdAt: approval.createdAt,
    expiresAt: approval.expiresAt,
  };
}
