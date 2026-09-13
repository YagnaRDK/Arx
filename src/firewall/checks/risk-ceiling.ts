import type { RiskSignal } from "../../core/seams";
import {
  block,
  info,
  type CheckContext,
  type FirewallFinding,
} from "../types";

/**
 * The hard risk ceiling.
 *
 * Distinct from the escalation threshold: `humanApproval.requiredAboveRiskScore`
 * says "a person must look at this", while `maxRiskScore` says "no person at a
 * device should be asked to look at this at all". Above the ceiling Arx refuses
 * rather than forwarding, because a confirmation screen is a poor place to
 * catch an address-poisoning substitution — the whole attack is that it looks
 * right.
 *
 * Risk only ever moves in this direction. A *low* score is not an input to any
 * decision; it cannot clear a check that failed, which is enforced structurally
 * by the orchestrator resolving BLOCK findings ahead of everything else.
 */
export function checkRiskCeiling(
  context: CheckContext,
  input: { score: number; signals: readonly RiskSignal[] },
): FirewallFinding[] {
  const ceiling = context.capability.maxRiskScore;

  if (input.score >= ceiling) {
    const worst = [...input.signals]
      .sort((a, b) => b.weight - a.weight)
      .slice(0, 3);

    return [
      block(
        "RISK_SCORE_EXCEEDED",
        `Risk score ${input.score} is at or above this capability's hard ceiling of ${ceiling}. Highest-weighted signals: ${worst
          .map((signal) => `${signal.id} (${signal.weight})`)
          .join(", ")}`,
        {
          score: input.score,
          ceiling,
          signals: input.signals.map((signal) => ({
            id: signal.id,
            weight: signal.weight,
            explanation: signal.explanation,
          })),
        },
      ),
    ];
  }

  return [
    info(
      "POLICY_APPROVED",
      `Risk score ${input.score} is below this capability's ceiling of ${ceiling}`,
      { score: input.score, ceiling, signalCount: input.signals.length },
    ),
  ];
}
