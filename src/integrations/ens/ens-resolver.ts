/**
 * ENS name resolution over ENSv2, as a `NameResolver`.
 *
 * Two things make this more than a convenience lookup:
 *
 * 1. **Allowlists can name people, not addresses.** A capability whose
 *    `recipients.allow` contains `treasury.arx.eth` is auditable by a human in
 *    a way that `0x8ba1…` is not, and the resolved primary name is what the
 *    Ledger device can display for clear signing.
 *
 * 2. **Resolution is a TOCTOU surface.** A name is a mutable pointer. The naive
 *    integration resolves the name once during the policy check and resolves it
 *    again — or lets the signer resolve it — at signing time. Between those two
 *    moments the name's owner can re-point the record, and funds approved for
 *    `treasury.arx.eth` leave for an attacker's address, with an audit log that
 *    truthfully says an allowlisted name was paid. Arx therefore *binds* the
 *    resolution: `resolveForAuthorization` returns a `NameBinding` carrying the
 *    exact address the name held at decision time plus a hash over it, the
 *    transaction is checked against that recorded address, and
 *    `verifyBinding` re-resolves with the cache bypassed before signing. A name
 *    re-pointed in between produces a mismatch and an aborted authorization,
 *    never a redirected payment.
 *
 * ENSv2 on Sepolia: ENS's own documentation states the Sepolia Universal
 * Resolver and apps are linked against the ENSv2 deployment, at the canonical
 * proxy `0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe`.
 *   https://docs.ens.domains/learn/deployments/
 *   https://docs.ens.domains/resolvers/universal/   (ENSIP-23 `resolve`/`reverse`)
 *   https://docs.ens.domains/ensv2/overview/
 *
 * The address is not hard-coded here on purpose. viem 2.56.3 ships that same
 * address as `sepolia.contracts.ensUniversalResolver`
 * (node_modules/viem/_cjs/chains/definitions/sepolia.js), so viem's ENS actions
 * route through the ENSv2 Universal Resolver without Arx restating an address
 * it would then have to keep in sync. `ENS_UNIVERSAL_RESOLVER_OVERRIDE` exists
 * for the case where a future deployment moves before viem catches up.
 */

import { createPublicClient, http, isAddress, type PublicClient } from "viem";
import { mainnet, sepolia } from "viem/chains";
import { normalize } from "viem/ens";

import { env } from "../../config/env";
import { hashCanonical } from "../../crypto/hash";
import {
  ok,
  unavailable,
  type Availability,
  type NameResolver,
  type ResolvedName,
} from "../../core/seams";
import { cacheKey, invalidateCache, readCache, writeCache } from "../cache";

/**
 * Deliberately short. A longer TTL widens the window in which Arx authorizes
 * against a record the registry no longer holds.
 */
const FORWARD_TTL_SECONDS = 30;
/** Reverse records are display-only, so they tolerate a longer life. */
const REVERSE_TTL_SECONDS = 300;

const RESOLUTION_TIMEOUT_MS = 4_000;

export type EnsChainName = "mainnet" | "sepolia";

const CHAIN_IDS: Record<EnsChainName, number> = {
  mainnet: 1,
  sepolia: 11_155_111,
};

/**
 * The address a name held at authorization time, plus a digest over the whole
 * binding. The digest goes into the approval record; the address is what the
 * firewall compares the transaction's recipient against.
 */
export type NameBinding = {
  name: string;
  /** Lowercase hex. The only address this binding authorizes. */
  address: string;
  chainId: number;
  source: string;
  resolvedAt: number;
  bindingHash: string;
};

export type BindingVerdict =
  | { status: "INTACT"; binding: NameBinding }
  | {
      status: "REPOINTED";
      binding: NameBinding;
      currentAddress: string;
      resolvedAt: number;
    }
  | { status: "UNVERIFIABLE"; binding: NameBinding; reason: string };

export type EnsResolverOptions = {
  chain?: EnsChainName;
  rpcUrl?: string;
  enabled?: boolean;
  /** Injected so tests and the demo can drive resolution deterministically. */
  now?: () => number;
};

export class EnsNameResolver implements NameResolver {
  readonly name = "ens";

  readonly chainName: EnsChainName;
  readonly chainId: number;
  readonly universalResolverAddress: string | undefined;

  private readonly enabled: boolean;
  private readonly rpcUrl: string;
  private readonly now: () => number;
  private client: PublicClient | null = null;

  constructor(options: EnsResolverOptions = {}) {
    this.chainName = options.chain ?? env.ensChain;
    this.chainId = CHAIN_IDS[this.chainName];
    this.enabled = options.enabled ?? env.ensEnabled;
    this.rpcUrl =
      options.rpcUrl ??
      (this.chainName === "mainnet"
        ? env.rpcUrls.ethereum
        : env.rpcUrls.sepolia);
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));

    const chain = this.chainName === "mainnet" ? mainnet : sepolia;

    this.universalResolverAddress =
      chain.contracts?.ensUniversalResolver?.address;
  }

  /**
   * Fail-closed readiness: an enabled flag alone is not enough, because
   * resolution without an RPC endpoint would return `UNAVAILABLE` on every
   * call and the registry would report a live integration that cannot answer.
   */
  isReady(): boolean {
    return this.enabled && this.rpcUrl.length > 0;
  }

  /**
   * Recorded on every result. Only Sepolia is labelled `ensv2`: ENS documents
   * the Sepolia Universal Resolver as linked against the ENSv2 deployment,
   * while mainnet still fronts the v1 registry through the same ENSIP-23
   * interface. Labelling both "v2" would overstate what mainnet answers with.
   */
  get source(): string {
    return this.chainName === "sepolia" ? "ensv2:sepolia" : "ens:mainnet";
  }

  async resolve(
    name: string,
    chainId: number,
  ): Promise<Availability<ResolvedName>> {
    const binding = await this.resolveForAuthorization(name, chainId);

    if (binding.status !== "OK") {
      return binding;
    }

    return ok({
      name: binding.value.name,
      address: binding.value.address,
      source: binding.value.source,
      resolvedAt: binding.value.resolvedAt,
    });
  }

  /**
   * The call the policy layer should make. Returns the binding, not just an
   * address, so the decision can be recorded against the exact record that was
   * read. `options.bypassCache` forces a fresh read for the pre-signing check.
   */
  async resolveForAuthorization(
    name: string,
    chainId: number,
    options: { bypassCache?: boolean } = {},
  ): Promise<Availability<NameBinding>> {
    if (!this.isReady()) {
      return unavailable<NameBinding>(this.disabledReason(), false);
    }

    if (chainId !== this.chainId) {
      // Resolving a mainnet name and then spending on a testnet (or the
      // reverse) would authorize against a record from a different registry.
      return unavailable<NameBinding>(
        `ENS resolver is configured for chain ${this.chainId}; refusing to resolve for chain ${chainId}`,
        false,
      );
    }

    let normalizedName: string;

    try {
      // UTS-46 normalization. Without it, two visually identical names with
      // different codepoints are different allowlist entries, which is a
      // homoglyph bypass.
      normalizedName = normalize(name);
    } catch (error) {
      return unavailable<NameBinding>(
        `"${name}" is not a valid ENS name: ${message(error)}`,
        false,
      );
    }

    const key = cacheKey("ens:fwd", this.chainName, normalizedName);
    const now = this.now();

    if (options.bypassCache === true) {
      invalidateCache(key);
    } else {
      const cached = readCache<NameBinding>(key, now);

      if (cached !== null) {
        return ok(cached.value);
      }
    }

    const client = this.publicClient();

    let address: string | null;

    try {
      address = await client.getEnsAddress({
        name: normalizedName,
        ...(this.universalResolverAddress === undefined
          ? {}
          : {
              universalResolverAddress:
                this.universalResolverAddress as `0x${string}`,
            }),
      });
    } catch (error) {
      return unavailable<NameBinding>(
        `ENSv2 resolution failed for ${normalizedName}: ${message(error)}`,
        true,
      );
    }

    if (address === null || !isAddress(address)) {
      // "Checked, and this name holds no address" is a definite answer, not an
      // outage — but it is still not an authorization, so it is surfaced as
      // non-retryable unavailability rather than an empty success.
      return unavailable<NameBinding>(
        `ENSv2 has no address record for ${normalizedName} on ${this.chainName}`,
        false,
      );
    }

    const binding = buildBinding({
      name: normalizedName,
      address: address.toLowerCase(),
      chainId: this.chainId,
      source: this.source,
      resolvedAt: now,
    });

    writeCache({
      key,
      value: binding,
      source: this.source,
      now,
      ttlSeconds: FORWARD_TTL_SECONDS,
    });

    return ok(binding);
  }

  /**
   * Re-resolves the bound name with the cache bypassed and reports whether the
   * record still points where it did at authorization time.
   *
   * `UNVERIFIABLE` is not `INTACT`. The caller must treat it as an abort: if
   * Arx cannot confirm the name still resolves to the approved address, it does
   * not know whether it is about to redirect funds.
   */
  async verifyBinding(binding: NameBinding): Promise<BindingVerdict> {
    const fresh = await this.resolveForAuthorization(
      binding.name,
      binding.chainId,
      { bypassCache: true },
    );

    if (fresh.status !== "OK") {
      return { status: "UNVERIFIABLE", binding, reason: fresh.reason };
    }

    if (fresh.value.address !== binding.address.toLowerCase()) {
      return {
        status: "REPOINTED",
        binding,
        currentAddress: fresh.value.address,
        resolvedAt: fresh.value.resolvedAt,
      };
    }

    return { status: "INTACT", binding };
  }

  async reverse(
    address: string,
    chainId: number,
  ): Promise<Availability<ResolvedName>> {
    if (!this.isReady()) {
      return unavailable<ResolvedName>(this.disabledReason(), false);
    }

    if (chainId !== this.chainId) {
      return unavailable<ResolvedName>(
        `ENS resolver is configured for chain ${this.chainId}; refusing to reverse for chain ${chainId}`,
        false,
      );
    }

    if (!isAddress(address)) {
      return unavailable<ResolvedName>(`"${address}" is not an address`, false);
    }

    const key = cacheKey("ens:rev", this.chainName, address);
    const now = this.now();
    const cached = readCache<ResolvedName>(key, now);

    if (cached !== null) {
      return ok(cached.value);
    }

    const client = this.publicClient();

    let primary: string | null;

    try {
      primary = await client.getEnsName({
        address: address as `0x${string}`,
        ...(this.universalResolverAddress === undefined
          ? {}
          : {
              universalResolverAddress:
                this.universalResolverAddress as `0x${string}`,
            }),
      });
    } catch (error) {
      return unavailable<ResolvedName>(
        `ENSv2 reverse lookup failed for ${address}: ${message(error)}`,
        true,
      );
    }

    if (primary === null || primary.length === 0) {
      return unavailable<ResolvedName>(
        `ENSv2 has no primary name for ${address} on ${this.chainName}`,
        false,
      );
    }

    const resolved: ResolvedName = {
      name: primary,
      address: address.toLowerCase(),
      source: this.source,
      resolvedAt: now,
    };

    writeCache({
      key,
      value: resolved,
      source: this.source,
      now,
      ttlSeconds: REVERSE_TTL_SECONDS,
    });

    return ok(resolved);
  }

  private publicClient(): PublicClient {
    if (this.client === null) {
      this.client = createPublicClient({
        chain: this.chainName === "mainnet" ? mainnet : sepolia,
        transport: http(this.rpcUrl, { timeout: RESOLUTION_TIMEOUT_MS }),
      }) as PublicClient;
    }

    return this.client;
  }

  private disabledReason(): string {
    if (!this.enabled) {
      return "ENS resolution is disabled (set ENS_ENABLED=true)";
    }

    return `No RPC URL configured for ${this.chainName} (set RPC_URL_${
      this.chainName === "mainnet" ? "ETHEREUM" : "SEPOLIA"
    })`;
  }
}

/** True for anything that should be resolved rather than parsed as hex. */
export function looksLikeEnsName(candidate: string): boolean {
  return !candidate.startsWith("0x") && candidate.includes(".");
}

function buildBinding(input: {
  name: string;
  address: string;
  chainId: number;
  source: string;
  resolvedAt: number;
}): NameBinding {
  // Hashed through `hashCanonical`, never `JSON.stringify`: the binding hash
  // ends up inside an approval artifact, and a key-order-dependent digest
  // would let the same binding hash two different ways.
  const bindingHash = hashCanonical({
    name: input.name,
    address: input.address,
    chainId: input.chainId,
    source: input.source,
    resolvedAt: input.resolvedAt,
  });

  return { ...input, bindingHash };
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
