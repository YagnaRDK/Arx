/**
 * Run context: the shared state every scenario needs.
 *
 * Two things here are worth explaining.
 *
 * **Nonces.** A capability's `nonce` is a floor and each intent nonce must be
 * strictly above the highest already accepted, so a second run against a
 * persistent database would replay the first run's nonces. The context therefore
 * allocates from a base derived from the wall clock, and `--nonce-base` pins it
 * when a byte-identical run is wanted.
 *
 * **The ETH price.** Several scenarios need a transaction whose oracle-derived
 * USD value lands in a known band, and the demo cannot know what price the
 * server's oracle reports. Rather than guessing silently, the price is
 * discovered from the server when it exposes one, the source is printed, and the
 * capabilities that are not testing value binding carry a wide tolerance. The
 * scenario that *is* testing value binding uses a 5% tolerance and lies by six
 * orders of magnitude, so no price assumption can make it pass or fail wrongly.
 */

import { ArxClient } from "./api";
import { buildSeedSet, CHAIN_ID, type SeedSet } from "./fixtures";

export const DEFAULT_ADMIN_TOKEN = "arx-demo-admin-token";

export type ServerHandle = {
  baseUrl: string;
  /** True when this process started the server and must stop it. */
  spawned: boolean;
  databasePath: string | null;
  stop(): Promise<void>;
  logs(): string;
};

export type RunContext = {
  client: ArxClient;
  adminToken: string;
  tag: string;
  /** Unix seconds captured once at run start, so scenarios share a clock. */
  now: number;
  ethUsd: number;
  ethUsdSource: string;
  seeds: SeedSet;
  databasePath: string | null;
  quiet: boolean;
  nextNonce(capabilityId: string): number;
  sleep(ms: number): Promise<void>;
};

type PriceDiscovery = { price: number; source: string };

/**
 * Asks the server what ETH is worth, falling back to a printed assumption.
 *
 * The fallback is never treated as truth: it is reported as
 * `assumed (no oracle endpoint)` in the run header and in `--json` output, so a
 * reader can see that the USD figures in the transcript are derived from an
 * assumption rather than from the oracle.
 */
export async function discoverEthPrice(
  client: ArxClient,
): Promise<PriceDiscovery> {
  const override = process.env.ARX_DEMO_ETH_USD;

  if (override && Number.isFinite(Number(override)) && Number(override) > 0) {
    return { price: Number(override), source: "ARX_DEMO_ETH_USD" };
  }

  const candidates = [
    `/oracle/price?asset=ETH&chainId=${CHAIN_ID}`,
    `/prices/ETH?chainId=${CHAIN_ID}`,
    "/integrations",
  ];

  for (const path of candidates) {
    const result = await client.get(path);

    if (!result.ok || typeof result.body !== "object" || result.body === null) {
      continue;
    }

    const price = findPrice(result.body);

    if (price !== null) {
      return { price, source: `server ${path}` };
    }
  }

  return { price: 3_000, source: "assumed (no oracle endpoint)" };
}

/** Walks a small response object looking for a USD price field. */
function findPrice(value: unknown, depth = 0): number | null {
  if (depth > 4 || typeof value !== "object" || value === null) {
    return null;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      const found = findPrice(item, depth + 1);

      if (found !== null) {
        return found;
      }
    }

    return null;
  }

  const record = value as Record<string, unknown>;

  for (const key of ["priceUsd", "ethUsd", "usd", "price"]) {
    const candidate = record[key];

    if (typeof candidate === "number" && candidate > 0) {
      return candidate;
    }
  }

  for (const nested of Object.values(record)) {
    const found = findPrice(nested, depth + 1);

    if (found !== null) {
      return found;
    }
  }

  return null;
}

export function createContext(input: {
  client: ArxClient;
  adminToken: string;
  tag: string;
  now: number;
  nonceBase: number;
  ethUsd: number;
  ethUsdSource: string;
  databasePath: string | null;
  quiet: boolean;
}): RunContext {
  const counters = new Map<string, number>();

  return {
    client: input.client,
    adminToken: input.adminToken,
    tag: input.tag,
    now: input.now,
    ethUsd: input.ethUsd,
    ethUsdSource: input.ethUsdSource,
    seeds: buildSeedSet(input.tag, input.now),
    databasePath: input.databasePath,
    quiet: input.quiet,

    nextNonce(capabilityId: string): number {
      const current = counters.get(capabilityId) ?? input.nonceBase;

      counters.set(capabilityId, current + 1);

      return current;
    },

    sleep(ms: number): Promise<void> {
      return new Promise((resolve) => setTimeout(resolve, ms));
    },
  };
}

/** A base36 tag short enough to read in a capability id. */
export function makeTag(now = Date.now()): string {
  return now.toString(36).slice(-6);
}

/**
 * Nonce floor for a run. Capability seeds set `nonce: 1`, so any base at or
 * above 1 is admissible; the millisecond clock guarantees two runs against one
 * database never collide.
 */
export function makeNonceBase(now = Date.now()): number {
  return now;
}
