import { z } from "zod";

import { EvmTransactionSchema } from "./transaction";

export const IntentSchema = z.object({
  capabilityId: z.string().min(1),
  agentId: z.string().min(1),

  action: z.string().min(1),
  protocol: z.string().min(1),
  chainId: z.number().int().positive(),

  inputToken: z.string().min(1),
  outputToken: z.string().min(1),

  /**
   * The agent's own claim about what this action is worth. Arx treats it as an
   * assertion to be checked against an oracle, never as ground truth — see
   * `src/firewall/checks/value-binding.ts`.
   */
  amountUsd: z.number().positive(),
  slippageBps: z.number().int().nonnegative(),

  /** Replay control value. Must be unique per capability and at or above the
   * capability's nonce floor. */
  nonce: z.number().int().nonnegative(),
  timestamp: z.number().int().positive(),

  /**
   * Caller-supplied identifier for one logical action, used for idempotency.
   * Re-submitting the same `intentId` with an identical payload replays the
   * original decision instead of producing a second authorization.
   */
  intentId: z.string().min(1).max(128).optional(),

  /** How long this intent stays submittable, in seconds from `timestamp`. */
  ttlSeconds: z.number().int().positive().max(3600).optional(),

  transaction: EvmTransactionSchema.optional(),
});

export type Intent = z.infer<typeof IntentSchema>;

/**
 * The fields that define an intent's identity for idempotency purposes.
 * `timestamp` is excluded so that a retried request — which may legitimately
 * carry a fresh clock reading — still matches the original.
 */
export function intentIdentityPayload(intent: Intent) {
  return {
    capabilityId: intent.capabilityId,
    agentId: intent.agentId,
    action: intent.action,
    protocol: intent.protocol,
    chainId: intent.chainId,
    inputToken: intent.inputToken,
    outputToken: intent.outputToken,
    amountUsd: intent.amountUsd,
    slippageBps: intent.slippageBps,
    nonce: intent.nonce,
    transaction: intent.transaction ?? null,
  };
}
