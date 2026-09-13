import type { DecisionCode } from "../core/codes";

/** Retained as an alias so existing imports keep working. */
export type PolicyCode = DecisionCode;

export type Decision = "ALLOW" | "DENY" | "ESCALATE";

export type EvaluationResult = {
  allowed: boolean;
  code: DecisionCode;
  reason: string;
  /**
   * `ESCALATE` means the request is within the agent's authority only if a
   * human confirms it. It is neither an approval nor a rejection.
   */
  decision?: Decision;
  details?: unknown;
};

export function allow(reason: string): EvaluationResult {
  return {
    allowed: true,
    code: "POLICY_APPROVED",
    reason,
    decision: "ALLOW",
  };
}

export function deny(
  code: DecisionCode,
  reason: string,
  details?: unknown,
): EvaluationResult {
  return {
    allowed: false,
    code,
    reason,
    decision: "DENY",
    ...(details === undefined ? {} : { details }),
  };
}

export function escalate(reason: string, details?: unknown): EvaluationResult {
  return {
    allowed: false,
    code: "HUMAN_APPROVAL_REQUIRED",
    reason,
    decision: "ESCALATE",
    ...(details === undefined ? {} : { details }),
  };
}
