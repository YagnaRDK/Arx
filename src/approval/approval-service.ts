import { randomUUID } from "node:crypto";

import type { Approval } from "../types/approval";
import type { NormalizedTransaction } from "../types/transaction";
import { hashNormalizedTransaction } from "./transaction-hash";
import { ApprovalStore } from "../storage/approval-store";

const POLICY_VERSION = "arx-policy-v1";

export class ApprovalService {
  constructor(private readonly approvalStore: ApprovalStore) {}

  createApproval(input: {
    requestId: string;
    capabilityId: string;
    agentId: string;
    transaction: NormalizedTransaction;
    expiresAt: number;
  }): Approval {
    const now = Math.floor(Date.now() / 1000);
    const transactionHash = hashNormalizedTransaction(input.transaction);

    const approval: Approval = {
      approvalId: randomUUID(),
      requestId: input.requestId,
      capabilityId: input.capabilityId,
      agentId: input.agentId,
      transactionId: input.transaction.transactionId,
      transactionHash,
      policyCode: "POLICY_APPROVED",
      policyVersion: POLICY_VERSION,
      createdAt: now,
      expiresAt: input.expiresAt,
      status: "APPROVED",
    };

    return this.approvalStore.create(approval);
  }

  verifyApproval(input: {
    approval: Approval;
    transaction: NormalizedTransaction;
    currentTime?: number;
  }): {
    valid: boolean;
    reason: string;
  } {
    const currentTime = input.currentTime ?? Math.floor(Date.now() / 1000);

    const { approval, transaction } = input;

    if (approval.status !== "APPROVED") {
      return {
        valid: false,
        reason: "Approval is not active",
      };
    }

    if (currentTime >= approval.expiresAt) {
      return {
        valid: false,
        reason: "Approval has expired",
      };
    }

    if (approval.transactionId !== transaction.transactionId) {
      return {
        valid: false,
        reason: "Transaction ID does not match approval",
      };
    }

    if (approval.agentId !== transaction.agentId) {
      return {
        valid: false,
        reason: "Agent ID does not match approval",
      };
    }

    if (approval.capabilityId !== transaction.capabilityId) {
      return {
        valid: false,
        reason: "Capability ID does not match approval",
      };
    }

    const transactionHash = hashNormalizedTransaction(transaction);

    if (transactionHash !== approval.transactionHash) {
      return {
        valid: false,
        reason: "Transaction hash does not match approval",
      };
    }

    return {
      valid: true,
      reason: "Approval is valid",
    };
  }
}
