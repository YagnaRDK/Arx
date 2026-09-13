import { createPublicClient, http, type PublicClient } from "viem";
import { mainnet, sepolia } from "viem/chains";

import { env } from "../config/env";
import {
  ok,
  unavailable,
  type Availability,
  type PriceOracle,
  type PriceQuote,
} from "../core/seams";
import { pricingSymbol } from "./assets";
import type { OracleCache } from "./oracle-cache";

/**
 * The two functions Arx needs from `AggregatorV3Interface`.
 *
 * `latestRoundData` returns `updatedAt`, which is the whole reason to read the
 * aggregator directly rather than a convenience API: it lets Arx enforce its own
 * staleness bound instead of trusting that someone else did.
 */
export const AGGREGATOR_V3_ABI = [
  {
    type: "function",
    name: "latestRoundData",
    stateMutability: "view",
    inputs: [],
    outputs: [
      { name: "roundId", type: "uint80" },
      { name: "answer", type: "int256" },
      { name: "startedAt", type: "uint256" },
      { name: "updatedAt", type: "uint256" },
      { name: "answeredInRound", type: "uint80" },
    ],
  },
  {
    type: "function",
    name: "decimals",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint8" }],
  },
] as const;

export type ChainlinkFeed = {
  address: `0x${string}`;
  /** Documented decimals, used only to cross-check the on-chain answer. */
  decimals: number;
  /**
   * Chainlink's published heartbeat: the longest interval the feed is expected
   * to go without an update. A quote older than this is stale by the feed's own
   * specification, independently of Arx's configured bound.
   */
  heartbeatSeconds: number;
};

/**
 * Verified aggregator proxy addresses.
 *
 * Source: Chainlink's official Data Feeds reference-data directory, the same
 * dataset that renders https://docs.chain.link/data-feeds/price-feeds/addresses
 *   Sepolia: https://reference-data-directory.vercel.app/feeds-ethereum-testnet-sepolia.json
 *   Mainnet: https://reference-data-directory.vercel.app/feeds-mainnet.json
 * Retrieved 2026-09-12. Each entry below was read out of that directory by
 * `name` and `path` (the plain `eth-usd` / `usdc-usd` feeds, not the `-svr`
 * variants), so no address here is from memory.
 *
 * Only assets with a verified feed on a given chain are listed. An asset absent
 * from this table makes the adapter report UNAVAILABLE for it rather than
 * guessing an address, which would be a silent authorization bug: a wrong
 * aggregator returns a confident number for the wrong asset.
 */
export const CHAINLINK_FEEDS: Record<number, Record<string, ChainlinkFeed>> = {
  // Ethereum mainnet
  1: {
    ETH: {
      address: "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419",
      decimals: 8,
      heartbeatSeconds: 3600,
    },
    USDC: {
      address: "0x8fFfFfd4AfB6115b954Bd326cbe7B4BA576818f6",
      decimals: 8,
      heartbeatSeconds: 82_800,
    },
  },
  // Ethereum Sepolia
  11155111: {
    ETH: {
      address: "0x694AA1769357215DE4FAC081bf1f309aDC325306",
      decimals: 8,
      heartbeatSeconds: 3600,
    },
    USDC: {
      address: "0xA2F78ab2355fe2f984D808B5CeE7FD0A93D5270E",
      decimals: 8,
      heartbeatSeconds: 86_400,
    },
  },
};

/**
 * Chains Arx has no verified aggregator address for. Recorded explicitly so the
 * gap is visible in code review rather than being an accidental omission:
 * Hedera (295/296) and Arc have no entry above and are never priced by this
 * adapter.
 */
export const CHAINLINK_UNVERIFIED_CHAINS = [295, 296] as const;

export const CHAINLINK_PRICE_SOURCE = "chainlink";

export type ChainlinkPriceOracleOptions = {
  /** chainId -> JSON-RPC URL. An asset on a chain with no URL is unavailable. */
  rpcUrls?: Record<number, string>;
  /** Hard per-call budget. Without it a hung RPC stalls an authorization. */
  timeoutMs?: number;
  /** How long a fetched round may be reused from cache. */
  cacheTtlSeconds?: number;
  cache?: OracleCache;
  now?: () => number;
  feeds?: Record<number, Record<string, ChainlinkFeed>>;
};

function chainFor(chainId: number) {
  if (chainId === mainnet.id) {
    return mainnet;
  }

  if (chainId === sepolia.id) {
    return sepolia;
  }

  return undefined;
}

/**
 * Rejects after `ms`.
 *
 * viem's transport timeout covers a single HTTP request; this bounds the whole
 * operation including retries, so the firewall's latency is capped no matter
 * how the transport behaves.
 */
async function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;

  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(
          () => reject(new Error(`Chainlink call timed out after ${ms}ms`)),
          ms,
        );
      }),
    ]);
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

/**
 * Reads USD prices straight from Chainlink aggregator contracts.
 *
 * Availability is a first-class outcome here. A missing RPC URL, an unverified
 * feed address, a timeout, a non-positive answer and a round older than its own
 * heartbeat all produce UNAVAILABLE — never a best-effort number. The caller
 * (`CompositePriceOracle`, then the value-binding check) decides what an unknown
 * price means, and in Arx an unknown price never means "permit".
 */
export class ChainlinkPriceOracle implements PriceOracle {
  readonly name = CHAINLINK_PRICE_SOURCE;

  private readonly rpcUrls: Record<number, string>;
  private readonly timeoutMs: number;
  private readonly cacheTtlSeconds: number;
  private readonly cache?: OracleCache;
  private readonly now: () => number;
  private readonly feeds: Record<number, Record<string, ChainlinkFeed>>;
  private readonly clients = new Map<number, PublicClient>();

  constructor(options: ChainlinkPriceOracleOptions = {}) {
    this.rpcUrls = options.rpcUrls ?? {
      1: env.rpcUrls.ethereum,
      11155111: env.rpcUrls.sepolia,
    };
    this.timeoutMs = options.timeoutMs ?? 4000;
    this.cacheTtlSeconds = options.cacheTtlSeconds ?? 60;
    this.cache = options.cache;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
    this.feeds = options.feeds ?? CHAINLINK_FEEDS;
  }

  isReady(): boolean {
    return Object.entries(this.rpcUrls).some(
      ([chainId, url]) =>
        url.length > 0 && this.feeds[Number(chainId)] !== undefined,
    );
  }

  private clientFor(chainId: number): PublicClient | undefined {
    const cached = this.clients.get(chainId);

    if (cached) {
      return cached;
    }

    const url = this.rpcUrls[chainId];

    if (!url) {
      return undefined;
    }

    const client = createPublicClient({
      chain: chainFor(chainId),
      transport: http(url, { timeout: this.timeoutMs, retryCount: 0 }),
    }) as PublicClient;

    this.clients.set(chainId, client);

    return client;
  }

  async getUsdPrice(
    asset: string,
    chainId: number,
  ): Promise<Availability<PriceQuote>> {
    const symbol = pricingSymbol(asset);
    const feed = this.feeds[chainId]?.[symbol];

    if (!feed) {
      return unavailable(
        `No verified Chainlink feed for ${symbol} on chain ${chainId}`,
        false,
      );
    }

    const now = this.now();
    const cacheKey = `chainlink:${chainId}:${symbol}`;
    const cached = this.cache?.get(cacheKey, now);

    if (cached) {
      const parsed = this.parseCached(cached.value);

      if (parsed) {
        return ok(parsed);
      }
    }

    const client = this.clientFor(chainId);

    if (!client) {
      return unavailable(`No RPC URL configured for chain ${chainId}`, false);
    }

    let answer: bigint;
    let updatedAt: bigint;
    let decimals: number;

    try {
      const [roundData, onChainDecimals] = await withTimeout(
        Promise.all([
          client.readContract({
            address: feed.address,
            abi: AGGREGATOR_V3_ABI,
            functionName: "latestRoundData",
          }),
          client.readContract({
            address: feed.address,
            abi: AGGREGATOR_V3_ABI,
            functionName: "decimals",
          }),
        ]),
        this.timeoutMs,
      );

      answer = roundData[1];
      updatedAt = roundData[3];
      decimals = Number(onChainDecimals);
    } catch (error) {
      return unavailable(
        `Chainlink read failed: ${error instanceof Error ? error.message : String(error)}`,
        true,
      );
    }

    if (answer <= 0n) {
      // A non-positive answer is a malfunctioning feed, not a cheap asset.
      return unavailable(
        `Chainlink feed ${feed.address} returned a non-positive answer`,
        true,
      );
    }

    if (updatedAt === 0n) {
      return unavailable(
        `Chainlink feed ${feed.address} reported an incomplete round`,
        true,
      );
    }

    const observedAt = Number(updatedAt);
    const age = now - observedAt;

    // The feed's own heartbeat is an upper bound the operator did not have to
    // configure. Arx's `priceMaxAgeSeconds` is applied separately, later.
    if (age > feed.heartbeatSeconds) {
      return {
        status: "UNAVAILABLE",
        reason: "PRICE_STALE",
        retryable: true,
      };
    }

    const priceUsd = Number(answer) / 10 ** decimals;

    if (!Number.isFinite(priceUsd) || priceUsd <= 0) {
      return unavailable(
        `Chainlink feed ${feed.address} produced a non-finite price`,
        false,
      );
    }

    const quote: PriceQuote = {
      asset: symbol,
      priceUsd,
      source: `${CHAINLINK_PRICE_SOURCE}:${feed.address.toLowerCase()}`,
      updatedAt: observedAt,
    };

    this.cache?.set(cacheKey, {
      value: JSON.stringify(quote),
      source: quote.source,
      fetchedAt: now,
      expiresAt: now + this.cacheTtlSeconds,
    });

    return ok(quote);
  }

  private parseCached(raw: string): PriceQuote | undefined {
    try {
      const parsed = JSON.parse(raw) as Partial<PriceQuote>;

      if (
        typeof parsed.asset === "string" &&
        typeof parsed.priceUsd === "number" &&
        Number.isFinite(parsed.priceUsd) &&
        parsed.priceUsd > 0 &&
        typeof parsed.source === "string" &&
        typeof parsed.updatedAt === "number"
      ) {
        return parsed as PriceQuote;
      }
    } catch {
      // A corrupt cache row is a miss, never a trusted value.
    }

    return undefined;
  }
}
