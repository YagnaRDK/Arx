import type { DecisionCode } from "../core/codes";
import type { Capability } from "../types/capability";

export type NonceVerdict =
  | { ok: true }
  | { ok: false; code: DecisionCode; reason: string };

/**
 * Nonce admissibility.
 *
 * The original design used `capabilityId + agentId + nonce` as a single replay
 * key and rejected any intent whose nonce was below the capability's, which
 * produced a capability that could authorize exactly one action before every
 * subsequent nonce was either "already processed" or "too low". The fix is to
 * give the two values distinct jobs:
 *
 *   capability.nonce  — a floor. The lowest nonce this grant will ever accept.
 *                       Raising it retires every outstanding lower nonce at once.
 *   intent.nonce      — a per-action counter. Must be strictly above the highest
 *                       nonce already accepted, and may never be reused.
 *
 * A SINGLE_USE capability is the special case where the floor *is* the only
 * admissible value, since there is only ever one action.
 */
export function checkNonce(input: {
  capability: Capability;
  nonce: number;
  highestAccepted: number | null;
  alreadyUsed: boolean;
}): NonceVerdict {
  const { capability, nonce, highestAccepted, alreadyUsed } = input;

  if (nonce < capability.nonce) {
    return {
      ok: false,
      code: "INVALID_NONCE",
      reason: `Intent nonce ${nonce} is below the capability nonce floor ${capability.nonce}`,
    };
  }

  if (capability.usage === "SINGLE_USE" && nonce !== capability.nonce) {
    return {
      ok: false,
      code: "INVALID_NONCE",
      reason: `Single-use capability accepts only nonce ${capability.nonce}, received ${nonce}`,
    };
  }

  if (alreadyUsed) {
    return {
      ok: false,
      code: "REPLAY_DETECTED",
      reason: `Nonce ${nonce} has already been used by capability ${capability.capabilityId}`,
    };
  }

  // Requiring strict increase — rather than merely "not previously seen" —
  // means an intent captured off the wire cannot be held and replayed later
  // once the counter has moved past it, even though its specific nonce is
  // unused.
  if (highestAccepted !== null && nonce <= highestAccepted) {
    return {
      ok: false,
      code: "NONCE_REUSED",
      reason: `Intent nonce ${nonce} must be greater than the highest accepted nonce ${highestAccepted}`,
    };
  }

  return { ok: true };
}

export type TimestampVerdict =
  | { ok: true }
  | { ok: false; code: DecisionCode; reason: string };

/**
 * Freshness. An intent carries its own clock reading and an optional TTL; both
 * are bounded so a captured intent has a short life even if its nonce is still
 * admissible.
 */
export function checkTimestamp(input: {
  timestamp: number;
  ttlSeconds?: number;
  now: number;
  maxSkewSeconds: number;
}): TimestampVerdict {
  const { timestamp, ttlSeconds, now, maxSkewSeconds } = input;

  if (timestamp > now + maxSkewSeconds) {
    return {
      ok: false,
      code: "INTENT_TIMESTAMP_SKEWED",
      reason: `Intent timestamp is ${timestamp - now}s in the future, beyond the ${maxSkewSeconds}s tolerance`,
    };
  }

  if (ttlSeconds !== undefined && now > timestamp + ttlSeconds) {
    return {
      ok: false,
      code: "INTENT_EXPIRED",
      reason: `Intent expired ${now - (timestamp + ttlSeconds)}s ago`,
    };
  }

  return { ok: true };
}
