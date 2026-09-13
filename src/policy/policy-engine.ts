import { allow, deny, type EvaluationResult } from "../types/evaluation";
import type { Capability } from "../types/capability";
import type { Intent } from "../types/intent";
import { checkNonce, checkTimestamp } from "./nonce";

export const POLICY_VERSION = "arx-policy-v2";

export type PolicyContext = {
  /** Highest nonce this capability has already accepted, if any. */
  highestAcceptedNonce?: number | null;
  /** Whether this exact nonce was already used. */
  isReplay?: boolean;
  maxClockSkewSeconds?: number;
};

/**
 * Capability-level evaluation: is this intent inside the authority the agent was
 * granted?
 *
 * This layer sees only the agent's declared intent, not the transaction bytes —
 * the transaction firewall handles those. Checks are ordered cheapest and most
 * certain first, so a denial is fast and never depends on later, costlier work.
 *
 * Every branch is a pure function of (capability, intent, context, currentTime).
 * `currentTime` is a parameter rather than a `Date.now()` call so the same
 * inputs always yield the same decision, which is what makes decisions
 * reproducible from the audit log.
 */
export class PolicyEngine {
  evaluate(
    capability: Capability,
    intent: Intent,
    isReplayOrContext: boolean | PolicyContext = false,
    currentTime: number = Math.floor(Date.now() / 1000),
  ): EvaluationResult {
    // The third parameter was a bare `isReplay` boolean in v0.4. Both shapes
    // are accepted so existing callers and tests keep working.
    const context: PolicyContext =
      typeof isReplayOrContext === "boolean"
        ? { isReplay: isReplayOrContext }
        : isReplayOrContext;

    if (capability.capabilityId !== intent.capabilityId) {
      return deny(
        "CAPABILITY_ID_MISMATCH",
        "Intent capability ID does not match the supplied capability",
      );
    }

    if (capability.status === "REVOKED") {
      return deny("CAPABILITY_REVOKED", "Capability has been revoked");
    }

    if (capability.status === "CONSUMED") {
      return deny(
        "CAPABILITY_CONSUMED",
        "Single-use capability has already been consumed",
      );
    }

    if (capability.status !== "ACTIVE") {
      return deny("CAPABILITY_INACTIVE", "Capability is not active");
    }

    if (capability.notBefore !== undefined && currentTime < capability.notBefore) {
      return deny(
        "CAPABILITY_NOT_YET_VALID",
        `Capability becomes valid in ${capability.notBefore - currentTime}s`,
      );
    }

    if (currentTime >= capability.expiresAt) {
      return deny("CAPABILITY_EXPIRED", "Capability has expired");
    }

    if (capability.agentId !== intent.agentId) {
      return deny(
        "AGENT_MISMATCH",
        "Intent agent does not match capability agent",
      );
    }

    if (!capability.allowedActions.includes(intent.action)) {
      return deny(
        "ACTION_NOT_ALLOWED",
        `Action "${intent.action}" is not in the capability's allowed actions`,
      );
    }

    if (!capability.allowedProtocols.includes(intent.protocol)) {
      return deny(
        "PROTOCOL_NOT_ALLOWED",
        `Protocol "${intent.protocol}" is not in the capability's allowed protocols`,
      );
    }

    if (!capability.allowedChains.includes(intent.chainId)) {
      return deny(
        "CHAIN_NOT_ALLOWED",
        `Chain ${intent.chainId} is not in the capability's allowed chains`,
      );
    }

    if (!capability.allowedTokens.input.includes(intent.inputToken)) {
      return deny(
        "INPUT_TOKEN_NOT_ALLOWED",
        `Input token "${intent.inputToken}" is not allowed`,
      );
    }

    if (!capability.allowedTokens.output.includes(intent.outputToken)) {
      return deny(
        "OUTPUT_TOKEN_NOT_ALLOWED",
        `Output token "${intent.outputToken}" is not allowed`,
      );
    }

    if (intent.amountUsd > capability.maxAmountUsd) {
      return deny(
        "AMOUNT_EXCEEDED",
        `Declared amount $${intent.amountUsd} exceeds the capability limit of $${capability.maxAmountUsd}`,
      );
    }

    if (intent.slippageBps > capability.maxSlippageBps) {
      return deny(
        "SLIPPAGE_EXCEEDED",
        `Slippage ${intent.slippageBps}bps exceeds the capability limit of ${capability.maxSlippageBps}bps`,
      );
    }

    const timestampVerdict = checkTimestamp({
      timestamp: intent.timestamp,
      ttlSeconds: intent.ttlSeconds,
      now: currentTime,
      maxSkewSeconds: context.maxClockSkewSeconds ?? 300,
    });

    if (!timestampVerdict.ok) {
      return deny(timestampVerdict.code, timestampVerdict.reason);
    }

    const nonceVerdict = checkNonce({
      capability,
      nonce: intent.nonce,
      highestAccepted: context.highestAcceptedNonce ?? null,
      alreadyUsed: context.isReplay ?? false,
    });

    if (!nonceVerdict.ok) {
      return deny(nonceVerdict.code, nonceVerdict.reason);
    }

    return allow("Intent is within the capability's granted authority");
  }
}
