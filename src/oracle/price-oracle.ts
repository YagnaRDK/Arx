import { env } from "../config/env";
import type { DecisionCode } from "../core/codes";
import {
  ok,
  type Availability,
  type PriceOracle,
  type PriceQuote,
} from "../core/seams";
import { ChainlinkPriceOracle } from "./chainlink-oracle";
import { SqliteOracleCache } from "./oracle-cache";
import { StaticPriceOracle } from "./static-oracle";

/**
 * The two machine-readable reasons a price can be missing.
 *
 * `Availability.reason` is a free-form string, so these adapters put the
 * DecisionCode itself in that field. The firewall then maps the reason straight
 * onto a denial code instead of pattern-matching prose, which keeps "the price
 * was old" distinguishable from "nobody answered" in the audit log.
 */
export const PRICE_UNAVAILABLE_REASON: DecisionCode = "PRICE_UNAVAILABLE";
export const PRICE_STALE_REASON: DecisionCode = "PRICE_STALE";

/** Maps an `UNAVAILABLE` reason back to the code to deny or escalate under. */
export function priceDecisionCode(reason: string): DecisionCode {
  return reason === PRICE_STALE_REASON
    ? PRICE_STALE_REASON
    : PRICE_UNAVAILABLE_REASON;
}

export type CompositePriceOracleOptions = {
  /**
   * Maximum accepted quote age, in seconds. A quote older than this is
   * UNAVAILABLE — not "old but usable". Pricing drives the USD ceilings, so a
   * stale number is an authorization decision made on last week's market.
   */
  maxAgeSeconds?: number;
  now?: () => number;
};

/**
 * Tries each adapter in order and enforces one staleness bound across all of
 * them.
 *
 * Two properties matter and are easy to get wrong:
 *
 *  1. A stale quote from an early adapter must not shadow a fresh quote from a
 *     later one, so staleness demotes an adapter rather than aborting the walk.
 *  2. Exhausting every adapter yields UNAVAILABLE, never a fabricated price.
 *     `unavailable` is the honest answer and the caller is forced to decide what
 *     it means; in Arx it never means "permit".
 */
export class CompositePriceOracle implements PriceOracle {
  readonly name = "composite";

  private readonly maxAgeSeconds: number;
  private readonly now: () => number;

  constructor(
    private readonly adapters: readonly PriceOracle[],
    options: CompositePriceOracleOptions = {},
  ) {
    this.maxAgeSeconds = options.maxAgeSeconds ?? env.priceMaxAgeSeconds;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  isReady(): boolean {
    return this.adapters.some((adapter) => adapter.isReady());
  }

  /** Adapter names in the order they will be consulted, for `/health`. */
  describe(): { adapters: string[]; maxAgeSeconds: number } {
    return {
      adapters: this.adapters.map((adapter) => adapter.name),
      maxAgeSeconds: this.maxAgeSeconds,
    };
  }

  async getUsdPrice(
    asset: string,
    chainId: number,
  ): Promise<Availability<PriceQuote>> {
    const now = this.now();
    let sawStale = false;

    for (const adapter of this.adapters) {
      if (!adapter.isReady()) {
        continue;
      }

      let result: Availability<PriceQuote>;

      try {
        result = await adapter.getUsdPrice(asset, chainId);
      } catch {
        // An adapter that throws is an adapter that did not answer. It must not
        // be able to abort the walk and take down pricing for every asset.
        continue;
      }

      if (result.status === "UNAVAILABLE") {
        if (result.reason === PRICE_STALE_REASON) {
          sawStale = true;
        }

        continue;
      }

      const quote = result.value;

      if (!Number.isFinite(quote.priceUsd) || quote.priceUsd <= 0) {
        continue;
      }

      // A quote timestamped in the future is a clock problem somewhere; treat
      // the magnitude of the skew as age so it cannot bypass the bound.
      const age = Math.abs(now - quote.updatedAt);

      if (age > this.maxAgeSeconds) {
        sawStale = true;
        continue;
      }

      return ok(quote);
    }

    return {
      status: "UNAVAILABLE",
      reason: sawStale ? PRICE_STALE_REASON : PRICE_UNAVAILABLE_REASON,
      retryable: true,
    };
  }
}

export type CreatePriceOracleOptions = CompositePriceOracleOptions & {
  /** Defaults to `env.priceOracleMode`. */
  mode?: "static" | "chainlink";
  /**
   * Whether the static table may answer when Chainlink cannot. Left on by
   * default because a labelled offline quote is more useful than no
   * authorization at all, and every quote carries `source: "static-table"` so
   * the substitution is visible in the response and the audit record. Turn it
   * off to require live data.
   */
  staticFallback?: boolean;
};

/**
 * Builds the oracle the server should inject into the firewall.
 *
 * In `chainlink` mode Chainlink is consulted first and the static table is the
 * labelled fallback. In `static` mode only the table is used — no RPC is
 * touched, so a clean clone runs the full demo offline.
 */
export function createPriceOracle(
  options: CreatePriceOracleOptions = {},
): CompositePriceOracle {
  const mode = options.mode ?? env.priceOracleMode;
  const adapters: PriceOracle[] = [];

  if (mode === "chainlink") {
    adapters.push(
      new ChainlinkPriceOracle({
        cache: new SqliteOracleCache(),
        now: options.now,
      }),
    );
  }

  if (mode === "static" || (options.staticFallback ?? true)) {
    adapters.push(new StaticPriceOracle({ now: options.now }));
  }

  return new CompositePriceOracle(adapters, options);
}

export { StaticPriceOracle, STATIC_PRICE_SOURCE } from "./static-oracle";
export { ChainlinkPriceOracle, CHAINLINK_FEEDS } from "./chainlink-oracle";
export {
  baseUnitsToUsd,
  describeNativeAsset,
  describeToken,
  pricingSymbol,
  type AssetDescriptor,
} from "./assets";
