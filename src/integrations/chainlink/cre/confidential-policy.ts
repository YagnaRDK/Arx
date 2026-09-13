/**
 * The computation an Arx Chainlink CRE Confidential Workflow would run.
 *
 * **Status: the policy evaluation in this file is real, deterministic and
 * runnable. The CRE workflow that would host it is a design sketch and has
 * never executed on CRE.** See `./CRE_CONFIDENTIAL_WORKFLOW.md` and
 * `./workflow.sketch.ts` for exactly where the line falls. Nothing here
 * pretends to be an attestation.
 *
 * The problem it solves is a real one for Arx. A capability's ceilings are
 * themselves sensitive: publishing "this agent may move up to $50,000 per day
 * to these four addresses" tells an attacker precisely how much to try to take
 * and where it is allowed to go. But the ceilings have to be enforced
 * somewhere, and if they are enforced only inside Arx then Arx's operator is
 * the single point of trust.
 *
 * A Confidential Workflow moves the evaluation into a TEE: the secret policy
 * is decrypted inside the enclave at the moment it is needed, the enclave sees
 * the public request, and only the verdict leaves. Node operators learn
 * whether a transfer was within limits, never what the limits are.
 *
 * The two design choices that make that verifiable:
 *
 *   - **A commitment, not the policy.** The verdict carries
 *     `policyCommitment`, the canonical hash of the secret policy document.
 *     Anyone holding the policy can confirm the enclave used *that* version;
 *     nobody learns it from the commitment. Hashed through `hashCanonical` so
 *     key order cannot change the commitment for an identical policy.
 *   - **Time is an input.** `evaluatedAt` is passed in, never read from a
 *     clock inside the function, so the same inputs always produce the same
 *     verdict and the enclave's output is reproducible by an auditor.
 */

import { hashCanonical } from "../../../crypto/hash";
import type { DecisionCode } from "../../../core/codes";

/**
 * The secret half. This is the document that would live in the CRE Vault DON
 * and be decrypted only inside the enclave.
 */
export type ConfidentialPolicy = {
  policyId: string;
  /** Per-transaction ceiling, USD. */
  maxAmountUsd: number;
  /** Rolling-window ceiling, USD. */
  maxWindowAmountUsd: number;
  windowSeconds: number;
  /** Lowercase addresses. Empty means nothing is permitted — fail closed. */
  allowedRecipients: string[];
  /** Lowercase addresses. A deny always beats an allow. */
  deniedRecipients: string[];
  /** Hard risk ceiling, 0-100. */
  maxRiskScore: number;
};

/** The public half: what the enclave is asked about. */
export type ConfidentialRequest = {
  agentId: string;
  chainId: number;
  recipient: string;
  amountUsd: number;
  riskScore: number;
  /** Spend already recorded in the current window, USD. */
  windowSpentUsd: number;
  /** Injected. Never read from a clock inside the enclave. */
  evaluatedAt: number;
};

export type ConfidentialVerdict = {
  allowed: boolean;
  code: DecisionCode;
  reason: string;
  /** Canonical hash of the secret policy. Reveals nothing; proves version. */
  policyCommitment: string;
  /** Canonical hash of the request, so a verdict cannot be moved to another. */
  requestCommitment: string;
  evaluatedAt: number;
  /**
   * How the verdict was produced. `CRE_CONFIDENTIAL_TEE` is reserved for a
   * verdict that genuinely came out of an enclave; local evaluation says so.
   */
  executionMode: "LOCAL_UNATTESTED" | "CRE_CONFIDENTIAL_TEE";
};

/**
 * Evaluates the secret policy against the public request.
 *
 * Deliberately ordered cheapest-and-most-specific first so the reason an
 * operator sees is the most informative one, and written so that every exit is
 * an explicit decision — there is no fall-through that ends in "allowed".
 */
export function evaluateConfidentialPolicy(
  policy: ConfidentialPolicy,
  request: ConfidentialRequest,
  executionMode: ConfidentialVerdict["executionMode"] = "LOCAL_UNATTESTED",
): ConfidentialVerdict {
  const policyCommitment = hashCanonical(policy);
  const requestCommitment = hashCanonical(request);

  const base = {
    policyCommitment,
    requestCommitment,
    evaluatedAt: request.evaluatedAt,
    executionMode,
  };

  const recipient = request.recipient.toLowerCase();
  const denied = new Set(
    policy.deniedRecipients.map((entry) => entry.toLowerCase()),
  );

  if (denied.has(recipient)) {
    return {
      ...base,
      allowed: false,
      code: "RECIPIENT_DENIED",
      reason: "Recipient is on the confidential denylist",
    };
  }

  const allowed = new Set(
    policy.allowedRecipients.map((entry) => entry.toLowerCase()),
  );

  // An empty allowlist permits nothing. A confidential policy that defaulted
  // open would be the worst of both worlds: unauditable and permissive.
  if (!allowed.has(recipient)) {
    return {
      ...base,
      allowed: false,
      code: "RECIPIENT_NOT_ALLOWED",
      reason: "Recipient is not on the confidential allowlist",
    };
  }

  if (request.riskScore >= policy.maxRiskScore) {
    return {
      ...base,
      allowed: false,
      code: "RISK_SCORE_EXCEEDED",
      reason: `Risk score ${request.riskScore} meets or exceeds the confidential ceiling`,
    };
  }

  if (request.amountUsd > policy.maxAmountUsd) {
    return {
      ...base,
      allowed: false,
      code: "AMOUNT_EXCEEDED",
      reason: "Amount exceeds the confidential per-transaction ceiling",
    };
  }

  if (request.windowSpentUsd + request.amountUsd > policy.maxWindowAmountUsd) {
    return {
      ...base,
      allowed: false,
      code: "SPEND_WINDOW_EXCEEDED",
      reason: "Amount would exceed the confidential rolling-window ceiling",
    };
  }

  return {
    ...base,
    allowed: true,
    code: "POLICY_APPROVED",
    reason: "Within the confidential policy's ceilings and allowlist",
  };
}

/**
 * Confirms a verdict was produced from a specific policy and request.
 *
 * The reason this exists: a verdict is only useful to an auditor if it cannot
 * be detached from its inputs. Comparing commitments is how a verdict from an
 * enclave — which never reveals the policy — is still checkable by whoever
 * holds it.
 */
export function verifyVerdictBinding(
  verdict: ConfidentialVerdict,
  policy: ConfidentialPolicy,
  request: ConfidentialRequest,
): { bound: boolean; reason: string } {
  if (verdict.policyCommitment !== hashCanonical(policy)) {
    return { bound: false, reason: "Verdict was produced from a different policy" };
  }

  if (verdict.requestCommitment !== hashCanonical(request)) {
    return {
      bound: false,
      reason: "Verdict was produced for a different request",
    };
  }

  return { bound: true, reason: "Verdict is bound to this policy and request" };
}
