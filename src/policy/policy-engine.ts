import type { Capability } from "../types/capability";
import type { Intent } from "../types/intent";

export type PolicyCode =
  | "POLICY_APPROVED"
  | "CAPABILITY_ID_MISMATCH"
  | "CAPABILITY_EXPIRED"
  | "CAPABILITY_REVOKED"
  | "CAPABILITY_CONSUMED"
  | "CAPABILITY_INACTIVE"
  | "AGENT_MISMATCH"
  | "ACTION_NOT_ALLOWED"
  | "PROTOCOL_NOT_ALLOWED"
  | "CHAIN_NOT_ALLOWED"
  | "INPUT_TOKEN_NOT_ALLOWED"
  | "OUTPUT_TOKEN_NOT_ALLOWED"
  | "AMOUNT_EXCEEDED"
  | "SLIPPAGE_EXCEEDED"
  | "INVALID_NONCE"
  | "REPLAY_DETECTED";

export type PolicyResult =
  | {
      allowed: true;
      code: "POLICY_APPROVED";
      reason: string;
    }
  | {
      allowed: false;
      code: Exclude<PolicyCode, "POLICY_APPROVED">;
      reason: string;
    };

export class PolicyEngine {
  evaluate(
    capability: Capability,
    intent: Intent,
    isReplay: boolean = false,
    currentTime: number = Math.floor(Date.now() / 1000),
  ): PolicyResult {
    if (intent.capabilityId !== capability.capabilityId) {
      return {
        allowed: false,
        code: "CAPABILITY_ID_MISMATCH",
        reason: "Intent references a different capability",
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
        reason: "Capability has already been consumed",
      };
    }

    if (capability.status !== "ACTIVE") {
      return {
        allowed: false,
        code: "CAPABILITY_INACTIVE",
        reason: `Capability is ${capability.status}`,
      };
    }

    if (currentTime >= capability.expiresAt) {
      return {
        allowed: false,
        code: "CAPABILITY_EXPIRED",
        reason: "Capability has expired",
      };
    }

    if (intent.agentId !== capability.agentId) {
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
        reason: "Requested input token is not allowed",
      };
    }

    if (!capability.allowedTokens.output.includes(intent.outputToken)) {
      return {
        allowed: false,
        code: "OUTPUT_TOKEN_NOT_ALLOWED",
        reason: "Requested output token is not allowed",
      };
    }

    if (intent.amountUsd > capability.maxAmountUsd) {
      return {
        allowed: false,
        code: "AMOUNT_EXCEEDED",
        reason: "Transaction amount exceeds capability limit",
      };
    }

    if (intent.slippageBps > capability.maxSlippageBps) {
      return {
        allowed: false,
        code: "SLIPPAGE_EXCEEDED",
        reason: "Slippage exceeds capability limit",
      };
    }

    if (intent.nonce !== capability.nonce) {
      return {
        allowed: false,
        code: "INVALID_NONCE",
        reason: "Intent nonce does not match capability nonce",
      };
    }

    if (isReplay) {
      return {
        allowed: false,
        code: "REPLAY_DETECTED",
        reason: "This intent has already been processed",
      };
    }

    return {
      allowed: true,
      code: "POLICY_APPROVED",
      reason: "Intent satisfies all policy rules",
    };
  }
}
