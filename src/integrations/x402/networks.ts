/**
 * The x402 networks Arx can gate a route on.
 *
 * Nothing here is guessed. Each entry records how it was checked, because a
 * wrong asset address in a payment gate means either a payment that can never
 * settle or, worse, one that settles to the wrong token.
 *
 * Verified 2026-09-12:
 *
 * `base-sepolia`
 *   - chain id 84532 — `eth_chainId` on https://84532.rpc.thirdweb.com returned
 *     `0x14a34`.
 *   - USDC `0x036CbD53842c5426634e7929541eC2318f3dCF7e` — the address used in
 *     the x402 v1 specification's own `accepts[]` example. `eth_call` against
 *     it returned `symbol() = "USDC"`, `name() = "USDC"`, `version() = "2"`,
 *     `decimals() = 6`, and a non-zero `DOMAIN_SEPARATOR()`, so it implements
 *     the EIP-712 domain EIP-3009 needs.
 *     https://github.com/coinbase/x402/blob/main/specs/x402-specification-v1.md
 *
 * `hedera-testnet`
 *   - chain id 296 — `eth_chainId` on https://testnet.hashio.io/api returned
 *     `0x128`.
 *   - USDC is HTS token `0.0.429274` per
 *     https://docs.x402.org/core-concepts/network-and-token-support ;
 *     the Hedera testnet mirror node confirms
 *     `{"token_id":"0.0.429274","symbol":"USDC","decimals":"6"}`
 *     (https://testnet.mirrornode.hedera.com/api/v1/tokens/0.0.429274).
 *     Its EVM long-zero address `0x0000000000000000000000000000000000068cda`
 *     (0x68cda == 429274) answers `symbol() = "USDC"` and `decimals() = 6`.
 *   - **but** `eth_getCode` on that address returns the HTS redirect proxy and
 *     `DOMAIN_SEPARATOR()` returns `0x` — empty. HTS USDC exposes no EIP-712
 *     domain, so it cannot implement EIP-3009 `transferWithAuthorization`, so
 *     the `exact` EVM scheme cannot be verified or settled against it locally.
 *     `exactEvm` is therefore `false` and this network is only usable with a
 *     facilitator that speaks `hedera:testnet`. Claiming otherwise would be a
 *     gate that accepts signatures it cannot check.
 */

export type X402NetworkConfig = {
  /** The `network` string that goes on the wire in `accepts[]`. */
  network: string;
  /** CAIP-2 identifier, which x402 v2 uses in the same field. */
  caip2: string;
  chainId: number;
  /** Token contract (EVM) or token id (Hedera native). */
  asset: string;
  assetSymbol: string;
  assetDecimals: number;
  /**
   * Whether the `exact` EVM scheme applies — i.e. whether the asset implements
   * EIP-3009 so an authorization can be verified locally and settled on chain.
   */
  exactEvm: boolean;
  /** EIP-712 domain for the asset. Only meaningful when `exactEvm` is true. */
  eip712?: { name: string; version: string };
  /** Why `exactEvm` is false, surfaced to operators. */
  limitation?: string;
};

export const X402_NETWORKS: Readonly<Record<string, X402NetworkConfig>> = {
  "base-sepolia": {
    network: "base-sepolia",
    caip2: "eip155:84532",
    chainId: 84_532,
    asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    assetSymbol: "USDC",
    assetDecimals: 6,
    exactEvm: true,
    eip712: { name: "USDC", version: "2" },
  },
  "hedera-testnet": {
    network: "hedera-testnet",
    caip2: "hedera:testnet",
    chainId: 296,
    asset: "0.0.429274",
    assetSymbol: "USDC",
    assetDecimals: 6,
    exactEvm: false,
    limitation:
      "HTS USDC (0.0.429274 / 0x0000000000000000000000000000000000068cda) exposes no EIP-712 DOMAIN_SEPARATOR, so EIP-3009 transferWithAuthorization is unavailable. Settlement requires an x402 facilitator supporting hedera:testnet (set X402_FACILITATOR_URL).",
  },
};

/** Hedera testnet's EVM view of HTS USDC, for the calldata/firewall path. */
export const HEDERA_TESTNET_USDC_EVM_ADDRESS =
  "0x0000000000000000000000000000000000068cda";

export function x402Network(name: string): X402NetworkConfig | undefined {
  return X402_NETWORKS[name];
}

/** Smallest-unit amount for a decimal USD string, e.g. "0.01" -> "10000". */
export function toAtomicAmount(amount: string, decimals: number): string {
  if (!/^\d+(\.\d+)?$/.test(amount)) {
    throw new Error(`x402 price "${amount}" is not a decimal amount`);
  }

  const [whole = "0", fraction = ""] = amount.split(".");
  const padded = (fraction + "0".repeat(decimals)).slice(0, decimals);

  // String arithmetic rather than floating point: 0.01 * 10**6 is 10000.000000000002
  // in IEEE 754, and an off-by-one atomic unit is a payment that never settles.
  return BigInt(`${whole}${padded}`).toString();
}
