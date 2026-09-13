import {
  block,
  escalateFinding,
  info,
  type CheckContext,
  type FirewallFinding,
} from "../types";
import { UINT256_MAX, flattenCall } from "./decode-calldata";

/**
 * Approval semantics.
 *
 * An approval is not a payment, it is a standing authority: the transaction
 * being small says nothing about what the spender can take afterwards. An
 * unlimited approval to a contract the agent was tricked into naming is
 * indistinguishable from handing over the balance, only it happens later and
 * outside Arx's view entirely — there is no second decision to make.
 *
 * So unlimited approvals are blocked rather than escalated, and `permit` — which
 * grants an allowance via an off-chain signature Arx never sees the effects of —
 * escalates by default.
 */

/**
 * Any allowance at or above this is unlimited in practice. `2^256-1` is the
 * canonical spelling, but `2^128` base units exceeds the entire supply of every
 * real token, so a slightly smaller constant must not evade the check.
 */
const EFFECTIVELY_UNLIMITED = 2n ** 128n;

/** How far an allowance may exceed the value it is supposed to enable. */
const EXCESS_MULTIPLE = 10n;

export type ApproveSemanticsInput = {
  /** USD value of the allowance, when the token could be priced. */
  allowanceUsd?: number;
  /** The agent's declared action value, for the far-excess comparison. */
  declaredValueUsd: number;
};

export function checkApproveSemantics(
  context: CheckContext,
  input: ApproveSemanticsInput,
): FirewallFinding[] {
  const findings: FirewallFinding[] = [];

  for (const call of flattenCall(context.decodedCall)) {
    if (call.kind === "ERC20_PERMIT") {
      findings.push(
        escalateFinding(
          "UNLIMITED_APPROVAL_BLOCKED",
          `Call is an EIP-2612 permit granting ${call.spender ?? "a spender"} an allowance of ${call.allowance ?? "an unread amount"}; a signature-based allowance takes effect without a further on-chain decision, so it requires human approval`,
          {
            spender: call.spender,
            allowance: call.allowance,
            token: call.target,
          },
        ),
      );
    }

    if (call.allowance === undefined) {
      continue;
    }

    let allowance: bigint;

    try {
      allowance = BigInt(call.allowance);
    } catch {
      continue;
    }

    if (allowance >= EFFECTIVELY_UNLIMITED) {
      findings.push(
        block(
          "UNLIMITED_APPROVAL_BLOCKED",
          allowance === UINT256_MAX
            ? `${call.signature ?? "Approval"} grants ${call.spender ?? "a spender"} an unlimited (2^256-1) allowance over ${call.target ?? "the token"}; the authority outlives this transaction and Arx never sees it used`
            : `${call.signature ?? "Approval"} grants ${call.spender ?? "a spender"} an allowance of ${call.allowance} base units over ${call.target ?? "the token"}, beyond any real token supply and therefore unlimited in effect`,
          {
            spender: call.spender,
            allowance: call.allowance,
            token: call.target,
            signature: call.signature,
          },
        ),
      );

      continue;
    }

    if (allowance === 0n) {
      findings.push(
        info(
          "POLICY_APPROVED",
          `${call.signature ?? "Approval"} revokes ${call.spender ?? "a spender"}'s allowance`,
          { spender: call.spender, token: call.target },
        ),
      );

      continue;
    }

    // Far-excess, measured in USD where a price exists. Without a price there
    // is no honest comparison to make, so nothing is claimed.
    if (
      input.allowanceUsd !== undefined &&
      input.declaredValueUsd > 0 &&
      input.allowanceUsd >
        input.declaredValueUsd * Number(EXCESS_MULTIPLE)
    ) {
      findings.push(
        escalateFinding(
          "UNLIMITED_APPROVAL_BLOCKED",
          `Approval is worth about $${input.allowanceUsd.toFixed(2)} but the declared action is only worth $${input.declaredValueUsd.toFixed(2)} — more than ${EXCESS_MULTIPLE}x the authority the action needs`,
          {
            allowanceUsd: input.allowanceUsd,
            declaredValueUsd: input.declaredValueUsd,
            spender: call.spender,
            token: call.target,
          },
        ),
      );
    }
  }

  return findings;
}
