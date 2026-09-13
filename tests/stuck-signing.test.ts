import { beforeEach, describe, expect, it } from "bun:test";

process.env.NODE_ENV = "test";
process.env.DATABASE_PATH = "./.test-data/stuck-signing.sqlite";

const { resetDatabaseForTests } = await import("../src/db/database");
const { ApprovalStore } = await import("../src/storage/approval-store");
const { SpendStore } = await import("../src/storage/spend-store");
const { AuditStore } = await import("../src/storage/audit-store");
const { ApprovalExpirySweeper } = await import(
  "../src/approval/expiry-sweeper"
);
const { ApprovalService } = await import("../src/approval/approval-service");
const { AuthorizationKey } = await import("../src/crypto/authorization-key");
const { TransactionNormalizer } = await import(
  "../src/normalization/transaction-normalizer"
);
const { allow } = await import("../src/types/evaluation");

const NOW = 1_700_000_000;
const GRACE = 600;

const normalizer = new TransactionNormalizer();

function transaction() {
  return normalizer.normalize({
    agentId: "agent-1",
    capabilityId: "cap-1",
    now: NOW,
    transaction: {
      chainId: 11155111,
      to: "0x1111111111111111111111111111111111111111",
      value: "10000000000000000",
      data: "0x",
      gasLimit: "21000",
      maxFeePerGas: "30000000000",
      maxPriorityFeePerGas: "1000000000",
      nonce: 0,
    },
  });
}

/**
 * An approval abandoned mid-signature.
 *
 * `claimForSigning` moves APPROVED -> SIGNING before the signer is called, so a
 * crash between the two leaves the row in SIGNING. Nothing used to reclaim it,
 * and its spend reservation was held against the rolling window forever.
 */
function abandonedApproval(store: InstanceType<typeof ApprovalStore>) {
  const service = new ApprovalService(store, new AuthorizationKey());

  const approval = service.createApproval({
    requestId: "r1",
    capabilityId: "cap-1",
    agentId: "agent-1",
    transaction: transaction(),
    decision: allow("within authority"),
    capabilityExpiresAt: NOW + 86_400,
    valueUsd: 32,
    now: NOW,
  });

  expect(service.claimForSigning(approval.approvalId)).toBe(true);
  expect(store.get(approval.approvalId)?.status).toBe("SIGNING");

  return approval;
}

describe("abandoned signing attempts", () => {
  beforeEach(() => {
    resetDatabaseForTests();
  });

  it("holds its spend reservation while the attempt is still plausibly in flight", () => {
    const approvalStore = new ApprovalStore();
    const spendStore = new SpendStore();
    const approval = abandonedApproval(approvalStore);

    spendStore.reserve({
      capabilityId: "cap-1",
      agentId: "agent-1",
      approvalId: approval.approvalId,
      amountUsd: 32,
      valueWei: "10000000000000000",
      now: NOW,
    });

    const sweeper = new ApprovalExpirySweeper({
      approvalStore,
      spendStore,
      stuckSigningGraceSeconds: GRACE,
      clock: () => NOW + 60,
    });

    // A person confirming on a device is slow; a minute is not abandonment.
    expect(sweeper.sweep().reclaimed).toBe(0);
    expect(approvalStore.get(approval.approvalId)?.status).toBe("SIGNING");
    expect(spendStore.usage("cap-1", 86_400, NOW + 60).amountUsd).toBe(32);
  });

  it("reclaims the attempt and releases the budget once the grace period passes", () => {
    const approvalStore = new ApprovalStore();
    const spendStore = new SpendStore();
    const approval = abandonedApproval(approvalStore);

    spendStore.reserve({
      capabilityId: "cap-1",
      agentId: "agent-1",
      approvalId: approval.approvalId,
      amountUsd: 32,
      valueWei: "10000000000000000",
      now: NOW,
    });

    expect(spendStore.usage("cap-1", 86_400, NOW).amountUsd).toBe(32);

    const sweeper = new ApprovalExpirySweeper({
      approvalStore,
      spendStore,
      auditStore: new AuditStore(),
      stuckSigningGraceSeconds: GRACE,
      clock: () => NOW + GRACE + 1,
    });

    const result = sweeper.sweep();

    expect(result.reclaimed).toBe(1);
    expect(result.released).toBe(1);
    // The budget is back: a crash should not cost an agent a slice of its
    // daily allowance permanently.
    expect(spendStore.usage("cap-1", 86_400, NOW + GRACE + 1).amountUsd).toBe(0);
  });

  it("reclaims to a terminal state, never back to a usable one", () => {
    // A signature may in fact have reached the device before the process died.
    // Returning the approval to APPROVED could authorize a second one.
    const approvalStore = new ApprovalStore();
    const spendStore = new SpendStore();
    const approval = abandonedApproval(approvalStore);

    new ApprovalExpirySweeper({
      approvalStore,
      spendStore,
      stuckSigningGraceSeconds: GRACE,
      clock: () => NOW + GRACE + 1,
    }).sweep();

    const reclaimed = approvalStore.get(approval.approvalId);

    expect(reclaimed?.status).toBe("SIGNING_FAILED");

    const service = new ApprovalService(approvalStore, new AuthorizationKey());

    expect(
      service.verifyApproval({
        approval: reclaimed!,
        transaction: transaction(),
        currentTime: NOW + GRACE + 2,
      }).valid,
    ).toBe(false);
  });

  it("records the abandonment in the audit chain", () => {
    const approvalStore = new ApprovalStore();
    const auditStore = new AuditStore();
    const approval = abandonedApproval(approvalStore);

    new ApprovalExpirySweeper({
      approvalStore,
      spendStore: new SpendStore(),
      auditStore,
      stuckSigningGraceSeconds: GRACE,
      clock: () => NOW + GRACE + 1,
    }).sweep();

    const entry = auditStore
      .byRequest("r1")
      .find((row) => row.approvalId === approval.approvalId);

    expect(entry?.eventType).toBe("SIGNING_FAILED");
    expect(entry?.reason).toContain("abandoned");
    expect(auditStore.verifyChain().valid).toBe(true);
  });
});
