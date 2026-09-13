import { z } from "zod";

/**
 * An allowlist/denylist pair with an explicit mode.
 *
 * `ALLOWLIST` is the fail-closed mode: an empty `allow` array denies
 * everything. `ANY` permits anything not explicitly denied, and exists only so
 * that a deliberately broad capability can be expressed — it is never the
 * default, because a security layer that defaults to "permit" is not one.
 */
export const PolicySetModeSchema = z.enum(["ALLOWLIST", "ANY"]);

export type PolicySetMode = z.infer<typeof PolicySetModeSchema>;

export const PolicySetSchema = z
  .object({
    mode: PolicySetModeSchema.default("ALLOWLIST"),
    allow: z.array(z.string().min(1)).default([]),
    deny: z.array(z.string().min(1)).default([]),
  })
  .prefault({});

export type PolicySet = z.infer<typeof PolicySetSchema>;

export type PolicySetVerdict =
  | { outcome: "ALLOWED" }
  | { outcome: "DENIED"; reason: "EXPLICIT_DENY" | "NOT_ON_ALLOWLIST" };

/**
 * Evaluates a candidate against a policy set. A deny entry always wins over an
 * allow entry, so revoking access to a single address never requires rebuilding
 * the allowlist.
 *
 * Comparison is case-insensitive because the same address legitimately appears
 * as lowercase hex and as an EIP-55 checksummed string, and the same ENS name
 * may be written in either case.
 */
export function evaluatePolicySet(
  set: PolicySet,
  candidates: readonly string[],
): PolicySetVerdict {
  const normalized = candidates
    .filter((candidate) => candidate.length > 0)
    .map((candidate) => candidate.toLowerCase());

  const deny = new Set(set.deny.map((entry) => entry.toLowerCase()));

  for (const candidate of normalized) {
    if (deny.has(candidate)) {
      return { outcome: "DENIED", reason: "EXPLICIT_DENY" };
    }
  }

  if (set.mode === "ANY") {
    return { outcome: "ALLOWED" };
  }

  const allow = new Set(set.allow.map((entry) => entry.toLowerCase()));

  for (const candidate of normalized) {
    if (allow.has(candidate)) {
      return { outcome: "ALLOWED" };
    }
  }

  return { outcome: "DENIED", reason: "NOT_ON_ALLOWLIST" };
}
