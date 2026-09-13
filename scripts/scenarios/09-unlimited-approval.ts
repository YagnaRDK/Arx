import { requestApproval } from "../lib/flows";
import {
  ADDRESS,
  buildIntent,
  contractCall,
  encodeErc20Approve,
  MAX_UINT256,
} from "../lib/fixtures";
import type { Scenario } from "../lib/scenario";
import { style } from "../lib/term";

/**
 * An unlimited allowance is a signature on a blank cheque.
 *
 * `approve(spender, 2^256-1)` moves nothing today, so every value-based limit in
 * the system waves it through: zero native value, a modest gas bill, an
 * allowlisted contract, a standard ERC-20 method. What it actually does is hand a
 * third party permanent, unbounded authority over the wallet's balance of that
 * token, outside Arx's view and after the capability expires.
 *
 * Either answer is defensible — refuse it, or make a human look at it — and both
 * are accepted here. What is not acceptable is treating it as routine.
 */
export const unlimitedApproval: Scenario = {
  name: "unlimited-approval",
  title: "Unlimited approval: approve(spender, 2^256-1)",
  kind: "ATTACK",
  story: [
    "value: 0            — nothing moves, so no amount limit trips",
    "to:    USDC         — allowlisted contract",
    "data:  approve(0x3333..., 115792089237316195423570985008687907853269984665640564039457584007913129639935)",
  ],
  expectation:
    "DENY UNLIMITED_APPROVAL_BLOCKED, or ESCALATE to a human — never a silent allow",

  async run(ctx, trace): Promise<void> {
    const capability = ctx.seeds.tokenOps;
    const data = encodeErc20Approve(ADDRESS.spender, MAX_UINT256);
    const transaction = contractCall(ADDRESS.usdc, data);

    if (!ctx.quiet) {
      trace.note(
        style.grey(
          "arg[1] is 0xffff...ffff — the maximum uint256, i.e. unbounded allowance",
        ),
      );
    }

    const intent = buildIntent({
      capabilityId: capability.capabilityId,
      nonce: ctx.nextNonce(capability.capabilityId),
      timestamp: ctx.now,
      amountUsd: 1,
      action: "approve",
      protocol: "erc20",
      inputToken: "USDC",
      outputToken: "USDC",
      transaction,
    });

    const result = await requestApproval(ctx, trace, intent);

    trace.expectVerdict("it is not treated as routine", result, [
      "DENY",
      "ESCALATE",
    ]);

    trace.expectCode("the unbounded allowance is named", result, {
      code: "UNLIMITED_APPROVAL_BLOCKED",
      alsoAcceptable: [
        "HUMAN_APPROVAL_REQUIRED",
        "CALLDATA_NOT_ALLOWED",
        "METHOD_NOT_ALLOWED",
      ],
    });

    // If it escalated, the approval must be unusable until a human acts — the
    // escalation is the control, so an APPROVED artifact here would be a bypass.
    const body = result.body as Record<string, any> | null;
    const status = body?.approval?.status;

    if (typeof status === "string") {
      trace.assert(
        "any approval created is not autonomously usable",
        status !== "APPROVED",
        "PENDING_HUMAN or no approval",
        status,
      );
    }
  },
};
