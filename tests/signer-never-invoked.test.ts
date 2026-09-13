import { describe, expect, it } from "bun:test";

import { ArxError } from "../src/core/errors";
import { SignerService } from "../src/signer/signer-service";
import { TransactionNormalizer } from "../src/normalization/transaction-normalizer";
import { ApprovalService } from "../src/approval/approval-service";
import { AuthorizationKey } from "../src/crypto/authorization-key";
import { ApprovalStore } from "../src/storage/approval-store";
import { allow, deny, escalate } from "../src/types/evaluation";
import type { NormalizedTransaction } from "../src/types/transaction";
import type {
  SignerAdapter,
  SignerResult,
  SignerStatus,
} from "../src/signer/signer-types";

/**
 * A signer that records every invocation.
 *
 * The point of this file is a claim that cannot be made by inspecting
 * responses: not merely that a denied request returns no signature, but that
 * the signer was never reached at all. A signer that is called and whose result
 * is discarded still touched the device, still produced a signature that exists
 * somewhere, and on real hardware would still have prompted a human.
 */
class CountingSignerAdapter implements SignerAdapter {
  readonly name = "counting-spy";
  readonly signatureType = "MOCK" as const;

  calls = 0;

  async getAddress(): Promise<string> {
    return "0x0000000000000000000000000000000000000001";
  }

  async getStatus(): Promise<SignerStatus> {
    return {
      adapter: this.name,
      signatureType: "MOCK",
      available: true,
      emulated: true,
      address: await this.getAddress(),
    };
  }

  async signTransaction(
    transaction: NormalizedTransaction,
  ): Promise<SignerResult> {
    this.calls += 1;

    return {
      signedTransaction: `0xmock_spy_${transaction.transactionId}`,
      signerAddress: await this.getAddress(),
      transactionId: transaction.transactionId,
      signatureType: "MOCK",
      // `SignerResult` requires these; a MOCK adapter fills them with
      // placeholders that are never presented as a real signature.
      r: `0x${"00".repeat(32)}`,
      s: `0x${"00".repeat(32)}`,
      v: "0x00",
      verified: false,
      adapter: this.name,
    };
  }
}

const NOW = 1_700_000_000;
const normalizer = new TransactionNormalizer();

function normalize(to = "0x1111111111111111111111111111111111111111") {
  return normalizer.normalize({
    agentId: "agent-1",
    capabilityId: "cap-1",
    now: NOW,
    transaction: {
      chainId: 11155111,
      to,
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
 * Mirrors the guard order `POST /sign` uses: verify the approval, then claim it
 * atomically, and only then touch the signer. Asserting against this sequence
 * proves the ordering property independently of HTTP plumbing.
 */
async function attemptSign(input: {
  service: SignerService;
  approvalService: ApprovalService;
  approvalId: string;
  transaction: NormalizedTransaction;
}) {
  const approval = input.approvalService.get(input.approvalId);

  if (!approval) {
    return { signed: false, code: "APPROVAL_NOT_FOUND" };
  }

  const verification = input.approvalService.verifyApproval({
    approval,
    transaction: input.transaction,
    currentTime: NOW,
  });

  if (!verification.valid) {
    return { signed: false, code: verification.code };
  }

  if (!input.approvalService.claimForSigning(approval.approvalId)) {
    return { signed: false, code: "APPROVAL_ALREADY_CONSUMED" };
  }

  await input.service.sign(input.transaction);
  input.approvalService.markSigned(approval.approvalId);

  return { signed: true, code: "POLICY_APPROVED" };
}

function harness() {
  const adapter = new CountingSignerAdapter();
  const approvalService = new ApprovalService(
    new ApprovalStore(),
    new AuthorizationKey(),
  );

  return {
    adapter,
    approvalService,
    service: new SignerService(adapter),
  };
}

describe("the signer is never reached without a valid approval", () => {
  it("is not invoked for an approval that does not exist", async () => {
    const h = harness();

    const result = await attemptSign({
      ...h,
      approvalId: "no-such-approval",
      transaction: normalize(),
    });

    expect(result.signed).toBe(false);
    expect(h.adapter.calls).toBe(0);
  });

  it("is not invoked when the transaction was mutated after approval", async () => {
    const h = harness();
    const approved = normalize();

    const approval = h.approvalService.createApproval({
      requestId: "r1",
      capabilityId: "cap-1",
      agentId: "agent-1",
      transaction: approved,
      decision: allow("within authority"),
      capabilityExpiresAt: NOW + 3600,
      now: NOW,
    });

    // The attacker's substitution: a different recipient, same everything else.
    const result = await attemptSign({
      ...h,
      approvalId: approval.approvalId,
      transaction: normalize("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
    });

    expect(result.signed).toBe(false);
    expect(h.adapter.calls).toBe(0);
  });

  it("is not invoked while an escalation is pending a human", async () => {
    const h = harness();
    const transaction = normalize();

    const approval = h.approvalService.createApproval({
      requestId: "r2",
      capabilityId: "cap-1",
      agentId: "agent-1",
      transaction,
      decision: escalate("above the autonomous ceiling"),
      capabilityExpiresAt: NOW + 3600,
      now: NOW,
    });

    expect(approval.status).toBe("PENDING_HUMAN");

    const result = await attemptSign({
      ...h,
      approvalId: approval.approvalId,
      transaction,
    });

    expect(result.signed).toBe(false);
    expect(result.code).toBe("APPROVAL_PENDING_HUMAN");
    // The whole point of the human gate: nothing reached the device.
    expect(h.adapter.calls).toBe(0);
  });

  it("is invoked exactly once across concurrent attempts on one approval", async () => {
    const h = harness();
    const transaction = normalize();

    const approval = h.approvalService.createApproval({
      requestId: "r3",
      capabilityId: "cap-1",
      agentId: "agent-1",
      transaction,
      decision: allow("within authority"),
      capabilityExpiresAt: NOW + 3600,
      now: NOW,
    });

    const attempts = await Promise.all(
      Array.from({ length: 8 }, () =>
        attemptSign({
          ...h,
          approvalId: approval.approvalId,
          transaction,
        }),
      ),
    );

    expect(attempts.filter((a) => a.signed)).toHaveLength(1);
    // The claim that matters: one signature was produced, not eight discarded.
    expect(h.adapter.calls).toBe(1);
  });

  it("is not invoked again after the approval is consumed", async () => {
    const h = harness();
    const transaction = normalize();

    const approval = h.approvalService.createApproval({
      requestId: "r4",
      capabilityId: "cap-1",
      agentId: "agent-1",
      transaction,
      decision: allow("within authority"),
      capabilityExpiresAt: NOW + 3600,
      now: NOW,
    });

    await attemptSign({ ...h, approvalId: approval.approvalId, transaction });
    expect(h.adapter.calls).toBe(1);

    const replay = await attemptSign({
      ...h,
      approvalId: approval.approvalId,
      transaction,
    });

    expect(replay.signed).toBe(false);
    expect(h.adapter.calls).toBe(1);
  });

  it("refuses to mint an approval from a denial at all", () => {
    const h = harness();

    // There is no path from a denied decision to an approval, so the signer
    // question never arises.
    expect(() =>
      h.approvalService.createApproval({
        requestId: "r5",
        capabilityId: "cap-1",
        agentId: "agent-1",
        transaction: normalize(),
        decision: deny("RECIPIENT_NOT_ALLOWED", "not on the allowlist"),
        capabilityExpiresAt: NOW + 3600,
        now: NOW,
      }),
    ).toThrow(ArxError);

    expect(h.adapter.calls).toBe(0);
  });
});
