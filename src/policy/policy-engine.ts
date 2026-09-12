import type { Capability } from "../types/capability";
import type { EvaluationResult } from "../types/evaluation";
import type { Intent } from "../types/intent";

export class PolicyEngine {
  evaluate(
    capability: Capability,
    intent: Intent,
    isReplay: boolean,
    currentTime: number = Math.floor(Date.now() / 1000),
  ): EvaluationResult {
    if (capability.capabilityId !== intent.capabilityId) {
      return {
        allowed: false,
        code: "CAPABILITY_ID_MISMATCH",
        reason: "Intent capability ID does not match the supplied capability",
      };
    }

    if (capability.status === "REVOKED") {
      return {
        allowed: false,
        code: "CAPABILITY_REVOKED",
        reason: "Capability has been revoked",
      };
    }

    if (capability.status === "CONSUMED") {
      return {
        allowed: false,
        code: "CAPABILITY_CONSUMED",
        reason: "Single-use capability has already been consumed",
      };
    }

    if (capability.status !== "ACTIVE") {
      return {
        allowed: false,
        code: "CAPABILITY_INACTIVE",
        reason: "Capability is not active",
      };
    }

    if (currentTime >= capability.expiresAt) {
      return {
        allowed: false,
        code: "CAPABILITY_EXPIRED",
        reason: "Capability has expired",
      };
    }

    if (capability.agentId !== intent.agentId) {
      return {
        allowed: false,
        code: "AGENT_MISMATCH",
        reason: "Intent agent does not match capability agent",
      };
    }

    if (!capability.allowedActions.includes(intent.action)) {
      return {
        allowed: false,
        code: "ACTION_NOT_ALLOWED",
        reason: "Requested action is not allowed",
      };
    }

    if (!capability.allowedProtocols.includes(intent.protocol)) {
      return {
        allowed: false,
        code: "PROTOCOL_NOT_ALLOWED",
        reason: "Requested protocol is not allowed",
      };
    }

    if (!capability.allowedChains.includes(intent.chainId)) {
      return {
        allowed: false,
        code: "CHAIN_NOT_ALLOWED",
        reason: "Requested chain is not allowed",
      };
    }

    if (!capability.allowedTokens.input.includes(intent.inputToken)) {
      return {
        allowed: false,
        code: "INPUT_TOKEN_NOT_ALLOWED",
        reason: "Input token is not allowed",
      };
    }

    if (!capability.allowedTokens.output.includes(intent.outputToken)) {
      return {
        allowed: false,
        code: "OUTPUT_TOKEN_NOT_ALLOWED",
        reason: "Output token is not allowed",
      };
    }

    if (intent.amountUsd > capability.maxAmountUsd) {
      return {
        allowed: false,
        code: "AMOUNT_EXCEEDED",
        reason: "Intent amount exceeds capability limit",
      };
    }

    if (intent.slippageBps > capability.maxSlippageBps) {
      return {
        allowed: false,
        code: "SLIPPAGE_EXCEEDED",
        reason: "Intent slippage exceeds capability limit",
      };
    }

    if (intent.nonce < capability.nonce) {
      return {
        allowed: false,
        code: "INVALID_NONCE",
        reason: "Intent nonce is lower than the capability nonce",
      };
    }

    if (isReplay) {
      return {
        allowed: false,
        code: "REPLAY_DETECTED",
        reason: "Intent has already been processed",
      };
    }

    return {
      allowed: true,
      code: "POLICY_APPROVED",
      reason: "Intent approved by capability policy",
    };
  }
}
