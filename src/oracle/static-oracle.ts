import {
  ok,
  type Availability,
  type PriceOracle,
  type PriceQuote,
} from "../core/seams";
import { pricingSymbol } from "./assets";

/**
 * The source label every quote from this adapter carries.
 *
 * It is exported so callers (API responses, the dashboard, the audit record)
 * can detect a static quote by identity rather than by string-matching, and so
 * nobody can mistake a table lookup for live market data.
 */
export const STATIC_PRICE_SOURCE = "static-table";

/** When the figures below were written down. They do not move. */
export const STATIC_TABLE_AS_OF = "2026-09-01";

/**
 * Fixed reference prices, USD per whole unit.
 *
 * These exist so the authorization pipeline is exercisable with no network at
 * all — a firewall that cannot decide when the internet is down is not a
 * firewall. They are NOT market prices and must never be presented as such:
 * every quote reports `source: "static-table"`.
 */
const STATIC_PRICES_USD: Record<string, number> = {
  ETH: 3200,
  // WETH folds onto ETH via `pricingSymbol`, but is listed so a caller asking
  // for it by name without normalization still gets an answer.
  WETH: 3200,
  USDC: 1,
  USDT: 1,
  DAI: 1,
  WBTC: 62000,
  HBAR: 0.22,
};

export type StaticPriceOracleOptions = {
  /** Injected clock. A decision must not depend on an ambient `Date.now()`. */
  now?: () => number;
  /** Overrides or extends the built-in table, e.g. for a test fixture. */
  prices?: Record<string, number>;
};

/**
 * A price oracle backed by a hardcoded table.
 *
 * `updatedAt` is reported as the time of the query rather than a fixed date.
 * That is deliberate: the table has no observation time, so pretending it has
 * an old one would make every quote fail the staleness bound and disable USD
 * checks entirely, while pretending it has a *recent* one is only honest
 * because `source` says plainly that this is a static table. The source label,
 * not the timestamp, is what tells an operator this is not live data.
 */
export class StaticPriceOracle implements PriceOracle {
  readonly name = STATIC_PRICE_SOURCE;

  private readonly prices: Record<string, number>;
  private readonly now: () => number;

  constructor(options: StaticPriceOracleOptions = {}) {
    this.prices = { ...STATIC_PRICES_USD, ...(options.prices ?? {}) };
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  isReady(): boolean {
    return true;
  }

  async getUsdPrice(
    asset: string,
    _chainId: number,
  ): Promise<Availability<PriceQuote>> {
    const symbol = pricingSymbol(asset);
    const priceUsd = this.prices[symbol];

    if (priceUsd === undefined) {
      return {
        status: "UNAVAILABLE",
        reason: "PRICE_UNAVAILABLE",
        retryable: false,
      };
    }

    return ok({
      asset: symbol,
      priceUsd,
      source: STATIC_PRICE_SOURCE,
      updatedAt: this.now(),
    });
  }

  /** The symbols this table can price, for `/health`-style reporting. */
  supportedAssets(): string[] {
    return Object.keys(this.prices).sort();
  }
}
