/**
 * Asset identity for pricing.
 *
 * The firewall has to convert *transaction bytes* into USD, and the bytes only
 * ever name an asset one of two ways: implicitly (native value on a chain) or
 * as a token contract address. The agent's `inputToken` string is a claim and is
 * deliberately not used here — see `src/firewall/checks/value-binding.ts`.
 *
 * Unknown means unknown. A token that is not in this registry produces no
 * descriptor, which makes the value-binding check escalate rather than quietly
 * price the transfer at zero.
 */

export type AssetDescriptor = {
  /** Canonical pricing symbol, e.g. "ETH". */
  symbol: string;
  decimals: number;
};

/** Native currency per chain. */
const NATIVE_ASSETS: Record<number, AssetDescriptor> = {
  1: { symbol: "ETH", decimals: 18 },
  11155111: { symbol: "ETH", decimals: 18 },
  // Hedera's EVM layer expresses value in weibar, i.e. 18 decimals, even though
  // HBAR itself has 8 decimals at the consensus layer.
  295: { symbol: "HBAR", decimals: 18 },
  296: { symbol: "HBAR", decimals: 18 },
};

/**
 * Known ERC-20s, lowercase address keys.
 *
 * Only addresses verified against a first-party source are listed. Mainnet
 * entries are the long-standing canonical deployments; Sepolia has only USDC,
 * verified against Circle's published contract-address list
 * (https://developers.circle.com/stablecoins/usdc-contract-addresses).
 * Anything absent here is treated as an unpriceable token, not as $0.
 */
const TOKEN_ASSETS: Record<number, Record<string, AssetDescriptor>> = {
  1: {
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": { symbol: "USDC", decimals: 6 },
    "0xdac17f958d2ee523a2206206994597c13d831ec7": { symbol: "USDT", decimals: 6 },
    "0x6b175474e89094c44da98b954eedeac495271d0f": { symbol: "DAI", decimals: 18 },
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": { symbol: "WETH", decimals: 18 },
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": { symbol: "WBTC", decimals: 8 },
  },
  11155111: {
    "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238": { symbol: "USDC", decimals: 6 },
  },
};

/**
 * Symbols that price off another asset one-for-one. Wrapped ETH is ETH for
 * valuation purposes; a stablecoin is not assumed to be $1 — it still has to be
 * priced by an oracle, so it is not aliased here.
 */
const SYMBOL_ALIASES: Record<string, string> = {
  WETH: "ETH",
  ETH: "ETH",
  HBAR: "HBAR",
};

export function describeNativeAsset(chainId: number): AssetDescriptor | undefined {
  return NATIVE_ASSETS[chainId];
}

export function describeToken(
  chainId: number,
  address: string,
): AssetDescriptor | undefined {
  return TOKEN_ASSETS[chainId]?.[address.toLowerCase()];
}

/** Folds a symbol onto the symbol an oracle is actually asked for. */
export function pricingSymbol(symbol: string): string {
  const upper = symbol.toUpperCase();
  return SYMBOL_ALIASES[upper] ?? upper;
}

/**
 * Converts a base-unit integer amount into USD.
 *
 * Split into whole and fractional parts so a 2^256-scale `amount` does not lose
 * the low-order digits to a single float division. The result is still a
 * double, and is an estimate used for limit comparison — never for accounting.
 */
export function baseUnitsToUsd(
  amount: bigint,
  decimals: number,
  priceUsd: number,
): number {
  if (amount === 0n) {
    return 0;
  }

  const divisor = 10n ** BigInt(decimals);
  const whole = amount / divisor;
  const remainder = amount % divisor;

  return (Number(whole) + Number(remainder) / Number(divisor)) * priceUsd;
}
