import { approvalOf } from "../lib/api";
import {
  assertSignerHonesty,
  requestApproval,
  requestSignature,
} from "../lib/flows";
import { ADDRESS, buildIntent, nativeTransfer, weiForUsd } from "../lib/fixtures";
import type { Scenario } from "../lib/scenario";

/**
 * Escalation is not rejection.
 *
 * A high-value payment to an allowlisted recipient is not an attack — it is
 * ordinary treasury work that happens to exceed what the agent was trusted to do
 * alone. The correct answer is neither "allow" nor "deny" but "not without a
 * person", and the same approval artifact then carries the human's decision
 * forward to the signer. Invariant 10.
 */
export const highValueEscalation: Scenario = {
  name: "high-value-escalation",
  title: "High value: escalate to a human, then sign on their approval",
  kind: "LIFECYCLE",
  story: [
    "The agent proposes a legitimate payment to an allowlisted recipient,",
    "but it is far above the amount this capability may move autonomously.",
    "Arx suspends it, a human resolves it, and only then does it sign.",
  ],
  expectation:
    "ESCALATE HUMAN_APPROVAL_REQUIRED, approval PENDING_HUMAN, then a human approves and it signs",

  async run(ctx, trace): Promise<void> {
    const capability = ctx.seeds.highValue;
    const transaction = nativeTransfer(
      ADDRESS.treasury,
      weiForUsd(5_000, ctx.ethUsd),
    );

    const intent = buildIntent({
      capabilityId: capability.capabilityId,
      nonce: ctx.nextNonce(capability.capabilityId),
      timestamp: ctx.now,
      amountUsd: 5_000,
      transaction,
    });

    const escalation = await requestApproval(ctx, trace, intent);

    trace.expectVerdict("the request is suspended, not refused", escalation, [
      "ESCALATE",
    ]);
    trace.expectCode("escalation code", escalation, {
      code: "HUMAN_APPROVAL_REQUIRED",
      alsoAcceptable: ["APPROVAL_PENDING_HUMAN"],
    });

    const approval = approvalOf(escalation);

    if (!approval) {
      trace.assert(
        "an approval artifact is created for the human to act on",
        false,
        "an approval with an approvalId",
        "none in response",
      );

      return;
    }

    trace.assert(
      "approval waits on a human",
      approval.status === "PENDING_HUMAN",
      "PENDING_HUMAN",
      approval.status ?? "unknown",
    );

    // Signing before the human decides must fail, or the escalation is theatre.
    const premature = await requestSignature(
      ctx,
      trace,
      { approvalId: approval.approvalId, transaction },
      "POST /sign (before the human has decided)",
    );

    // Either shape is honest here: a refusal, or a restatement that the request
    // is still escalated. What must not happen is a signature.
    trace.expectVerdict("signing is refused while pending", premature, [
      "DENY",
      "ESCALATE",
    ]);

    trace.assert(
      "nothing was signed before the human decided",
      !/signedtransaction/i.test(premature.rawBody),
      "no signedTransaction in the response",
      /signedtransaction/i.test(premature.rawBody)
        ? "a signature was returned"
        : "none",
    );
    trace.expectCode("refusal names the pending state", premature, {
      code: "APPROVAL_PENDING_HUMAN",
      alsoAcceptable: [
        "APPROVAL_INVALID",
        "APPROVAL_STATE_CONFLICT",
        "HUMAN_APPROVAL_REQUIRED",
      ],
    });

    const decision = trace.requireRoute(
      await trace.call(
        `POST /approvals/${approval.approvalId}/approve`,
        [
          ["actor", "operator@arx.demo (control plane)"],
          ["authority", "admin credential, not the agent's"],
        ],
        () =>
          ctx.client.post(
            `/approvals/${approval.approvalId}/approve`,
            { decidedBy: "operator@arx.demo", note: "demo run" },
            { admin: true },
          ),
      ),
    );

    trace.expectHttp("human approval recorded", decision, [200, 201, 204]);

    const signResult = await requestSignature(ctx, trace, {
      approvalId: approval.approvalId,
      transaction,
    });

    trace.expectHttp("signing succeeds after approval", signResult, [200, 201]);
    assertSignerHonesty(trace, signResult);
  },
};
