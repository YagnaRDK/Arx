import { approvalOf } from "../lib/api";
import { requestApproval, requestSignature } from "../lib/flows";
import { ADDRESS, buildIntent, nativeTransfer, weiForUsd } from "../lib/fixtures";
import { BlockedError, type Scenario } from "../lib/scenario";

/**
 * One approval, one signature.
 *
 * An approval is a bearer authorisation: if it can be presented twice, a
 * $25 payment an operator sanctioned becomes a $25 payment repeated until the
 * treasury is empty. Invariant 5.
 *
 * Two replays are checked, because they are different mechanisms: replaying the
 * *approval* at the signer boundary, and replaying the *intent* nonce at the
 * policy boundary.
 */
export const replay: Scenario = {
  name: "replay",
  title: "Replay: a consumed approval, and a reused intent nonce",
  kind: "ATTACK",
  story: [
    "The agent captured its own successful request and simply sent it again",
    "— first the approval at the signer, then the whole intent at the policy",
    "engine. Nothing is forged; everything is a verbatim resubmission.",
  ],
  expectation:
    "second signature refused APPROVAL_ALREADY_CONSUMED; resubmitted nonce refused REPLAY_DETECTED",

  async run(ctx, trace): Promise<void> {
    const capability = ctx.seeds.payments;
    const transaction = nativeTransfer(
      ADDRESS.vendor,
      weiForUsd(25, ctx.ethUsd),
    );

    const nonce = ctx.nextNonce(capability.capabilityId);

    const intent = buildIntent({
      capabilityId: capability.capabilityId,
      nonce,
      timestamp: ctx.now,
      amountUsd: 25,
      transaction,
    });

    const first = await requestApproval(ctx, trace, intent);
    const approval = approvalOf(first);

    if (!approval) {
      throw new BlockedError(
        `Could not obtain an approval to replay (HTTP ${first.status}); the allowed-payment path must work before replay can be demonstrated`,
      );
    }

    const firstSign = await requestSignature(ctx, trace, {
      approvalId: approval.approvalId,
      transaction,
    });

    trace.expectHttp("first signature succeeds", firstSign, [200, 201]);

    const secondSign = await requestSignature(
      ctx,
      trace,
      { approvalId: approval.approvalId, transaction },
      "POST /sign (identical resubmission)",
    );

    trace.expectVerdict("second signature refused", secondSign, "DENY");
    trace.expectCode("refusal names the consumed approval", secondSign, {
      code: "APPROVAL_ALREADY_CONSUMED",
      alsoAcceptable: ["APPROVAL_INVALID", "APPROVAL_STATE_CONFLICT"],
    });

    const replayedIntent = await trace.call(
      "POST /approvals (same nonce again)",
      [
        ["capability", capability.capabilityId],
        ["nonce", `${nonce} (already used)`],
      ],
      () => ctx.client.post("/approvals", intent),
    );

    trace.expectVerdict("replayed intent refused", replayedIntent, "DENY");
    trace.expectCode("refusal names replay", replayedIntent, {
      code: "REPLAY_DETECTED",
      alsoAcceptable: ["NONCE_REUSED", "INVALID_NONCE", "INTENT_ID_CONFLICT"],
    });
  },
};
