import { approvalOf } from "../lib/api";
import {
  assertSignerHonesty,
  requestApproval,
  requestSignature,
} from "../lib/flows";
import { ADDRESS, buildIntent, nativeTransfer, weiForUsd } from "../lib/fixtures";
import type { Scenario } from "../lib/scenario";

/**
 * The baseline. Everything else in the suite is a refusal, and a firewall that
 * refuses everything is not a firewall — so the suite starts by proving the
 * authorised path actually completes, end to end, through the signer boundary.
 */
export const allowedPayment: Scenario = {
  name: "allowed-payment",
  title: "Allowed payment: allowlisted recipient, inside every limit",
  kind: "CONTROL",
  story: [
    "The agent has been asked to pay a supplier from the treasury.",
    "The recipient is on the capability's allowlist, the amount is well",
    "below the escalation threshold, and the capability is live.",
  ],
  expectation:
    "ALLOW POLICY_APPROVED, an approval artifact, then a signature from the configured signer",

  async run(ctx, trace): Promise<void> {
    const capability = ctx.seeds.payments;
    const transaction = nativeTransfer(
      ADDRESS.vendor,
      weiForUsd(25, ctx.ethUsd),
    );

    const intent = buildIntent({
      capabilityId: capability.capabilityId,
      nonce: ctx.nextNonce(capability.capabilityId),
      timestamp: ctx.now,
      amountUsd: 25,
      transaction,
    });

    const approvalResult = await requestApproval(ctx, trace, intent);

    trace.expectVerdict("intent is authorised", approvalResult, "ALLOW");
    trace.expectCode("policy code", approvalResult, { code: "POLICY_APPROVED" });

    const approval = approvalOf(approvalResult);

    if (!approval) {
      trace.assert(
        "approval artifact returned",
        false,
        "an approval with an approvalId",
        "none in response",
      );

      return;
    }

    trace.assert(
      "approval artifact returned",
      true,
      "an approval with an approvalId",
      approval.approvalId,
    );

    trace.assert(
      "approval is immediately usable",
      approval.status === "APPROVED",
      "APPROVED",
      approval.status ?? "unknown",
    );

    trace.assert(
      "approval is bound to a transaction hash",
      /^0x[0-9a-f]{64}$/i.test(approval.transactionHash ?? ""),
      "0x + 64 hex",
      approval.transactionHash ?? "absent",
    );

    const signResult = await requestSignature(ctx, trace, {
      approvalId: approval.approvalId,
      transaction,
    });

    trace.expectHttp("signing succeeded", signResult, [200, 201]);
    assertSignerHonesty(trace, signResult);
  },
};
