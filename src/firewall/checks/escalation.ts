import type { RiskSignal } from "../../core/seams";
import {
  escalateFinding,
  info,
  movesNativeValue,
  type CheckContext,
  type FirewallFinding,
} from "../types";
import {
  flattenCall,
  selectorForSignature,
  signatureForSelector,
} from "./decode-calldata";
import type { ResolvedPolicySet } from "./recipient-resolution";

/**
 * When autonomy stops.
 *
 * Escalation is neither an approval nor a rejection: the action is inside the
 * authority the agent was granted, but only a person at the device may complete
 * it. That third outcome is what lets a capability be genuinely useful without
 * being genuinely dangerous — the ceiling can be low and the escalation
 * threshold lower still, instead of the operator having to choose between
 * "blocked" and "unsupervised".
 *
 * Every rule here reads oracle- and calldata-derived facts, never the agent's
 * declaration. Escalating on a claimed value would let the claim decide whether
 * a human is consulted.
 */
export function checkEscalation(
  context: CheckContext,
  input: {
    valueUsd: number;
    valuePriced: boolean;
    riskScore: number;
    riskSignals: readonly RiskSignal[];
    recipients: ResolvedPolicySet;
  },
): FirewallFinding[] {
  const findings: FirewallFinding[] = [];
  const policy = context.capability.humanApproval;

  if (policy.alwaysRequired) {
    findings.push(
      escalateFinding(
        "HUMAN_APPROVAL_REQUIRED",
        "This capability is configured for full human-in-the-loop operation: every transaction requires explicit approval",
      ),
    );
  }

  if (policy.requiredAboveUsd > 0 && input.valuePriced) {
    if (input.valueUsd > policy.requiredAboveUsd) {
      findings.push(
        escalateFinding(
          "HUMAN_APPROVAL_REQUIRED",
          `Transaction moves $${input.valueUsd.toFixed(2)} by oracle price, above this capability's autonomous ceiling of $${policy.requiredAboveUsd.toFixed(2)}`,
          { valueUsd: input.valueUsd, threshold: policy.requiredAboveUsd },
        ),
      );
    }
  }

  if (policy.requiredForUnknownRecipient) {
    const known = new Set(
      input.recipients.set.allow.map((entry) => entry.toLowerCase()),
    );

    const counterparties = new Set<string>();

    if (context.tx.to !== undefined && movesNativeValue(context.tx)) {
      counterparties.add(context.tx.to.toLowerCase());
    }

    for (const call of flattenCall(context.decodedCall)) {
      for (const recipient of call.recipients) {
        counterparties.add(recipient.toLowerCase());
      }
    }

    const unknown = [...counterparties].filter(
      (address) => !known.has(address),
    );

    if (unknown.length > 0) {
      findings.push(
        escalateFinding(
          "HUMAN_APPROVAL_REQUIRED",
          `${unknown.length} counterparty(ies) are not on this capability's recipient allowlist: ${unknown.join(", ")}`,
          { unknownRecipients: unknown },
        ),
      );
    }
  }

  if (policy.requiredForMethods.length > 0) {
    // Accept either spelling on both sides, exactly as the method policy does,
    // so an escalation rule cannot be dodged by notation.
    const escalateOn = new Set<string>();

    for (const entry of policy.requiredForMethods) {
      escalateOn.add(entry.toLowerCase());

      if (entry.includes("(")) {
        const selector = selectorForSignature(entry);

        if (selector) {
          escalateOn.add(selector.toLowerCase());
        }
      } else {
        const signature = signatureForSelector(entry);

        if (signature) {
          escalateOn.add(signature.toLowerCase());
        }
      }
    }

    for (const call of flattenCall(context.decodedCall)) {
      const spellings = [call.selector, call.signature]
        .filter((value): value is string => value !== undefined)
        .map((value) => value.toLowerCase());

      const hit = spellings.find((spelling) => escalateOn.has(spelling));

      if (hit !== undefined) {
        findings.push(
          escalateFinding(
            "HUMAN_APPROVAL_REQUIRED",
            `Method ${call.signature ?? call.selector} is listed in this capability's human-approval rules`,
            {
              selector: call.selector,
              signature: call.signature,
              target: call.target,
            },
          ),
        );
      }
    }
  }

  if (input.riskScore >= policy.requiredAboveRiskScore) {
    const top = [...input.riskSignals]
      .sort((a, b) => b.weight - a.weight)
      .slice(0, 3);

    findings.push(
      escalateFinding(
        "HUMAN_APPROVAL_REQUIRED",
        `Risk score ${input.riskScore} is at or above this capability's escalation threshold of ${policy.requiredAboveRiskScore}: ${top
          .map((signal) => signal.id)
          .join(", ")}`,
        {
          riskScore: input.riskScore,
          threshold: policy.requiredAboveRiskScore,
          signals: top.map((signal) => ({
            id: signal.id,
            weight: signal.weight,
            explanation: signal.explanation,
          })),
        },
      ),
    );
  }

  if (findings.length === 0) {
    findings.push(
      info(
        "POLICY_APPROVED",
        "No human-approval rule was triggered; the transaction is within autonomous authority",
      ),
    );
  }

  return findings;
}
