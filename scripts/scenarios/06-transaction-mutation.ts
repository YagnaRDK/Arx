import { approvalOf } from "../lib/api";
import { requestApproval, requestSignature } from "../lib/flows";
import { ADDRESS, buildIntent, nativeTransfer, weiForUsd } from "../lib/fixtures";
import { BlockedError, type Scenario } from "../lib/scenario";
import { formatWei } from "../lib/term";

/**
 * The transaction signed must be the transaction approved.
 *
 * This is the attack every "AI agent with a wallet" demo misses: the approval
 * step reviews transaction A, and the signing step is handed transaction B. If
 * the approval is bound to an id or a request rather than to the bytes, the
 * swap goes through and the human approved something that never happened.
 *
 * Arx binds the approval to a hash over the canonical transaction, so the swap
 * cannot even be described to the signer. Invariant 3.
 */
export const transactionMutation: Scenario = {
  name: "transaction-mutation",
  title: "Transaction mutation: approve A, submit B for signing",
  kind: "ATTACK",
  story: [
    "A payment of $25 to an allowlisted vendor is approved.",
    "At the signer, the agent substitutes a different transaction:",
    "same recipient, same capability, same approval id — larger amount.",
  ],
  expectation: "DENY TRANSACTION_HASH_MISMATCH",

  async run(ctx, trace): Promise<void> {
    const capability = ctx.seeds.payments;

    const approvedTransaction = nativeTransfer(
      ADDRESS.vendor,
      weiForUsd(25, ctx.ethUsd),
    );

    const intent = buildIntent({
      capabilityId: capability.capabilityId,
      nonce: ctx.nextNonce(capability.capabilityId),
      timestamp: ctx.now,
      amountUsd: 25,
      transaction: approvedTransaction,
    });

    const approvalResult = await requestApproval(ctx, trace, intent);
    const approval = approvalOf(approvalResult);

    if (!approval) {
      throw new BlockedError(
        `Could not obtain an approval to mutate (HTTP ${approvalResult.status})`,
      );
    }

    // Only the value changes. Every identifier the naive design would check —
    // approval id, agent, capability, recipient — is untouched.
    const mutatedTransaction = {
      ...approvedTransaction,
      value: weiForUsd(250, ctx.ethUsd),
    };

    trace.note(
      `approved ${formatWei(approvedTransaction.value)} → submitted ${formatWei(mutatedTransaction.value)}`,
    );

    const result = await requestSignature(
      ctx,
      trace,
      { approvalId: approval.approvalId, transaction: mutatedTransaction },
      "POST /sign (substituted transaction)",
    );

    trace.expectVerdict("the substitution is refused", result, "DENY");
    trace.expectCode("refusal names the hash binding", result, {
      code: "TRANSACTION_HASH_MISMATCH",
      alsoAcceptable: ["APPROVAL_INVALID"],
    });

    trace.assert(
      "no signature was produced",
      !/signedtransaction/i.test(result.rawBody),
      "no signedTransaction in the response",
      /signedtransaction/i.test(result.rawBody) ? "a signature was returned" : "none",
    );

    // The approval must survive unusable rather than being spent by the attempt:
    // a failed substitution should not burn a legitimate authorisation.
    const after = await ctx.client.get(`/approvals/${approval.approvalId}`);
    const state = approvalOf(after);

    if (state?.status) {
      trace.assert(
        "the original approval was not consumed by the attempt",
        state.status !== "CONSUMED",
        "not CONSUMED",
        state.status,
      );
    }
  },
};
