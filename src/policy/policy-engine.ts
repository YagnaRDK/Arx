import type { Capability } from "../types/capability";
import type { Intent } from "../types/intent";

export type PolicyResult =
  | {
      allowed: true;
      reason: string;
    }
  | {
      allowed: false;
      reason: string;
    };

export class PolicyEngine {
  evaluate(
    capability: Capability,
    intent: Intent,
    currentTime: number = Math.floor(Date.now() / 1000),
  ): PolicyResult {
    if (intent.capabilityId !== capability.capabilityId) {
      return {
        allowed: false,
        reason: "Capability ID mismatch",
      };
    }

    if (capability.status !== "ACTIVE") {
      return {
        allowed: false,
        reason: `Capability is ${capability.status}`,
      };
    }

    if (currentTime >= capability.expiresAt) {
      return {
        allowed: false,
        reason: "Capability has expired",
      };
    }

    if (intent.agentId !== capability.agentId) {
      return {
        allowed: false,
        reason: "Agent identity mismatch",
      };
    }

    if (!capability.allowedActions.includes(intent.action)) {
      return {
        allowed: false,
        reason: "Action is not allowed",
      };
    }

    if (!capability.allowedProtocols.includes(intent.protocol)) {
      return {
        allowed: false,
        reason: "Protocol is not allowed",
      };
    }

    if (!capability.allowedChains.includes(intent.chainId)) {
      return {
        allowed: false,
        reason: "Chain is not allowed",
      };
    }

    if (!capability.allowedTokens.input.includes(intent.inputToken)) {
      return {
        allowed: false,
        reason: "Input token is not allowed",
      };
    }

    if (!capability.allowedTokens.output.includes(intent.outputToken)) {
      return {
        allowed: false,
        reason: "Output token is not allowed",
      };
    }

    if (intent.amountUsd > capability.maxAmountUsd) {
      return {
        allowed: false,
        reason: "Transaction amount exceeds capability limit",
      };
    }

    if (intent.slippageBps > capability.maxSlippageBps) {
      return {
        allowed: false,
        reason: "Slippage exceeds capability limit",
      };
    }

    if (intent.nonce !== capability.nonce) {
      return {
        allowed: false,
        reason: "Invalid or reused nonce",
      };
    }

    return {
      allowed: true,
      reason: "Intent satisfies all policy rules",
    };
  }
}
