import type { DecisionCode } from "../core/codes";

/** Retained as an alias so existing imports keep working. */
export type PolicyCode = DecisionCode;

/**
 * The four terminal outcomes, using Ledger's own vocabulary for agent
 * authorization.
 *
 * `ABORT` is distinct from `DENY`: a denial means the request was evaluated and
 * refused, while an abort means Arx could not establish the premise of the
 * decision at all — an oracle was unreachable, a name would not resolve, or the
 * device displayed something other than what was approved. Collapsing the two
 * would hide exactly the failures that matter, because an abort says the system
 * does not know, and not knowing is never permission.
 */
export type Decision = "ALLOW" | "DENY" | "ESCALATE" | "ABORT";

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

/**
 * Arx could not establish what it needed to decide. Never an approval.
 */
export function abort(
  code: DecisionCode,
  reason: string,
  details?: unknown,
): EvaluationResult {
  return {
    allowed: false,
    code,
    reason,
    decision: "ABORT",
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
