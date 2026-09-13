import { approvalOf } from "../lib/api";
import { requestApproval, requestSignature } from "../lib/flows";
import { ADDRESS, buildIntent, nativeTransfer, weiForUsd } from "../lib/fixtures";
import { BlockedError, type Scenario } from "../lib/scenario";

/**
 * Revocation has to reach work already in flight.
 *
 * The moment an operator revokes a capability is the moment they have decided the
 * agent is compromised. If an approval issued thirty seconds earlier can still be
 * redeemed at the signer, revocation is a suggestion — and the window between
 * "we noticed" and "it stopped" is exactly the window an attacker needs.
 *
 * So the check is re-run at the signer boundary against the live capability,
 * not just at approval time. Invariant 6.
 */
export const revocationMidFlight: Scenario = {
  name: "revocation-mid-flight",
  title: "Revocation mid-flight: approved, then revoked, then presented",
  kind: "LIFECYCLE",
  story: [
    "A payment is approved normally. Before it is signed, an operator",
    "revokes the capability that authorised it — the agent is suspected",
    "of being compromised. The agent presents the approval anyway.",
  ],
  expectation:
    "DENY CAPABILITY_REVOKED at the signer, even though the approval itself was valid",

  async run(ctx, trace): Promise<void> {
    const capability = ctx.seeds.revocable;
    const transaction = nativeTransfer(
      ADDRESS.vendor,
      weiForUsd(45, ctx.ethUsd),
    );

    const intent = buildIntent({
      capabilityId: capability.capabilityId,
      nonce: ctx.nextNonce(capability.capabilityId),
      timestamp: ctx.now,
      amountUsd: 45,
      transaction,
    });

    const approvalResult = await requestApproval(ctx, trace, intent);

    trace.expectVerdict("the payment is authorised first", approvalResult, "ALLOW");

    const approval = approvalOf(approvalResult);

    if (!approval) {
      throw new BlockedError(
        `Could not obtain an approval to revoke against (HTTP ${approvalResult.status})`,
      );
    }

    const revocation = trace.requireRoute(
      await trace.call(
        `POST /capabilities/${capability.capabilityId}/revoke`,
        [
          ["actor", "operator@arx.demo (control plane)"],
          ["reason", "agent suspected compromised"],
        ],
        () =>
          ctx.client.post(
            `/capabilities/${capability.capabilityId}/revoke`,
            { reason: "agent suspected compromised" },
            { admin: true },
          ),
      ),
    );

    trace.expectHttp("revocation accepted", revocation, [200, 201, 204]);

    const signResult = await requestSignature(
      ctx,
      trace,
      { approvalId: approval.approvalId, transaction },
      "POST /sign (using the pre-revocation approval)",
    );

    trace.expectVerdict("the in-flight approval is refused", signResult, "DENY");
    trace.expectCode("refusal names the revocation", signResult, {
      code: "CAPABILITY_REVOKED",
      alsoAcceptable: [
        "APPROVAL_REVOKED",
        "APPROVAL_INVALID",
        "CAPABILITY_INACTIVE",
        "APPROVAL_STATE_CONFLICT",
      ],
    });

    trace.assert(
      "no signature was produced after revocation",
      !/signedtransaction/i.test(signResult.rawBody),
      "no signedTransaction in the response",
      /signedtransaction/i.test(signResult.rawBody)
        ? "a signature was returned"
        : "none",
    );
  },
};
