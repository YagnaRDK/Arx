import type { NameResolver } from "../../core/seams";
import type { PolicySet } from "../../types/policy-sets";

/**
 * Turning a policy set into something comparable against transaction bytes.
 *
 * A recipient allowlist is written by a human, so it legitimately contains ENS
 * names. Transaction bytes contain only 20-byte addresses. Bridging the two
 * requires resolution, and resolution is a network call that can fail — which
 * makes this the exact place where a dependency outage would otherwise become
 * an authorization bypass.
 *
 * The rule: an unresolved entry never becomes a match, and the caller is told
 * which entries could not be resolved so it can escalate instead of guessing.
 * A resolver that is absent is treated the same as a resolver that failed.
 */

const HEX_ADDRESS = /^0x[0-9a-fA-F]{40}$/;

export function isHexAddress(value: string): boolean {
  return HEX_ADDRESS.test(value);
}

export type ResolvedPolicySet = {
  /** Only literal addresses; safe to compare against calldata. */
  set: PolicySet;
  /** Allow entries that are names and could not be resolved. */
  unresolvedAllow: string[];
  /**
   * Deny entries that are names and could not be resolved. These matter more
   * than unresolved allow entries: an unresolved deny means Arx cannot prove the
   * recipient is *not* on the denylist.
   */
  unresolvedDeny: string[];
  /** name -> address pairs that did resolve, for the audit record. */
  resolutions: Array<{ name: string; address: string; source: string }>;
};

async function resolveEntries(
  entries: readonly string[],
  chainId: number,
  resolver: NameResolver | undefined,
): Promise<{
  addresses: string[];
  unresolved: string[];
  resolutions: Array<{ name: string; address: string; source: string }>;
}> {
  const addresses: string[] = [];
  const unresolved: string[] = [];
  const resolutions: Array<{ name: string; address: string; source: string }> =
    [];

  for (const entry of entries) {
    if (isHexAddress(entry)) {
      addresses.push(entry.toLowerCase());
      continue;
    }

    if (!resolver || !resolver.isReady()) {
      unresolved.push(entry);
      continue;
    }

    let resolved;

    try {
      resolved = await resolver.resolve(entry, chainId);
    } catch {
      unresolved.push(entry);
      continue;
    }

    if (resolved.status !== "OK" || !isHexAddress(resolved.value.address)) {
      unresolved.push(entry);
      continue;
    }

    addresses.push(resolved.value.address.toLowerCase());
    resolutions.push({
      name: entry,
      address: resolved.value.address.toLowerCase(),
      source: resolved.value.source,
    });
  }

  return { addresses, unresolved, resolutions };
}

/**
 * The synchronous case: no resolver, so every name is unresolved.
 *
 * Kept explicit rather than implied. A caller with no resolver must get the
 * same fail-closed answer as a caller whose resolver failed, and must be told
 * which entries were skipped.
 */
export function resolvePolicySetSync(set: PolicySet): ResolvedPolicySet {
  const allow: string[] = [];
  const deny: string[] = [];
  const unresolvedAllow: string[] = [];
  const unresolvedDeny: string[] = [];

  for (const entry of set.allow) {
    if (isHexAddress(entry)) {
      allow.push(entry.toLowerCase());
    } else {
      unresolvedAllow.push(entry);
    }
  }

  for (const entry of set.deny) {
    if (isHexAddress(entry)) {
      deny.push(entry.toLowerCase());
    } else {
      unresolvedDeny.push(entry);
    }
  }

  return {
    set: { mode: set.mode, allow, deny },
    unresolvedAllow,
    unresolvedDeny,
    resolutions: [],
  };
}

export async function resolvePolicySet(
  set: PolicySet,
  chainId: number,
  resolver?: NameResolver,
): Promise<ResolvedPolicySet> {
  if (!resolver || !resolver.isReady()) {
    return resolvePolicySetSync(set);
  }

  const allow = await resolveEntries(set.allow, chainId, resolver);
  const deny = await resolveEntries(set.deny, chainId, resolver);

  return {
    set: {
      mode: set.mode,
      allow: allow.addresses,
      deny: deny.addresses,
    },
    unresolvedAllow: allow.unresolved,
    unresolvedDeny: deny.unresolved,
    resolutions: [...allow.resolutions, ...deny.resolutions],
  };
}
