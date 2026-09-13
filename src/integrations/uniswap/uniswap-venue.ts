/**
 * Uniswap v3 as an `ExecutionVenue`.
 *
 * The Arx angle is the sequencing. A venue adapter normally hands its calldata
 * straight to a signer, and the agent's own description of the trade is the
 * only thing anyone ever checked. Here the quote comes back with the exact
 * `to`, selector and encoded recipient, and `describeForFirewall` extracts
 * those as *candidates for the capability's policy sets* — so a router that
 * returns calldata paying someone other than the requested recipient is caught
 * before signing, by comparing bytes rather than reading a label.
 *
 * The quote itself is a real on-chain `eth_call` against QuoterV2, not a
 * pricing API, so it needs no API key — only an RPC URL.
 *
 * Addresses verified 2026-09-12 against Uniswap's own deployments page,
 * https://developers.uniswap.org/contracts/v3/reference/deployments/ethereum-deployments
 * which also warns "Integrators should no longer assume that they are deployed
 * to the same addresses across chains", hence the per-chain table below rather
 * than one constant:
 *   Ethereum mainnet  QuoterV2      0x61fFE014bA17989E743c5F6cB21bF9697530B21e
 *                     SwapRouter02  0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45
 *                     Factory       0x1F98431c8aD98523631AE4a59f267346ea31F984
 *   Sepolia           QuoterV2      0xEd1f6473345F45b75F8179591dd5bA1888cf2FB3
 *                     SwapRouter02  0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E
 *                     Factory       0x0227628f3F023bb0B980b67D528571c95c6DaC1c
 *
 * `quoteExactInputSingle` is declared `view` in the local ABI so viem issues a
 * plain `eth_call`. QuoterV2 returns its result normally (it catches the inner
 * revert itself), so this is the documented way to read a quote without a
 * state-changing transaction — not a trick that happens to work.
 */

import { createPublicClient, encodeFunctionData, http, isAddress, parseAbi } from "viem";
import { mainnet, sepolia } from "viem/chains";

import { env } from "../../config/env";
import {
  ok,
  unavailable,
  type Availability,
  type ExecutionQuote,
  type ExecutionVenue,
} from "../../core/seams";

type UniswapDeployment = {
  chainId: number;
  quoterV2: string;
  swapRouter02: string;
  factory: string;
};

export const UNISWAP_V3_DEPLOYMENTS: Readonly<
  Record<number, UniswapDeployment>
> = {
  1: {
    chainId: 1,
    quoterV2: "0x61fFE014bA17989E743c5F6cB21bF9697530B21e",
    swapRouter02: "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45",
    factory: "0x1F98431c8aD98523631AE4a59f267346ea31F984",
  },
  11_155_111: {
    chainId: 11_155_111,
    quoterV2: "0xEd1f6473345F45b75F8179591dd5bA1888cf2FB3",
    swapRouter02: "0x3bFA4769FB09eefC5a80d6E87c3B9C650f7Ae48E",
    factory: "0x0227628f3F023bb0B980b67D528571c95c6DaC1c",
  },
};

const QUOTER_V2_ABI = parseAbi([
  "struct QuoteExactInputSingleParams { address tokenIn; address tokenOut; uint256 amountIn; uint24 fee; uint160 sqrtPriceLimitX96; }",
  "function quoteExactInputSingle(QuoteExactInputSingleParams params) view returns (uint256 amountOut, uint160 sqrtPriceX96After, uint32 initializedTicksCrossed, uint256 gasEstimate)",
]);

const SWAP_ROUTER_02_ABI = parseAbi([
  "struct ExactInputSingleParams { address tokenIn; address tokenOut; uint24 fee; address recipient; uint256 amountIn; uint256 amountOutMinimum; uint160 sqrtPriceLimitX96; }",
  "function exactInputSingle(ExactInputSingleParams params) payable returns (uint256 amountOut)",
]);

/** The v3 fee tiers, in hundredths of a bip. Tried cheapest-impact first. */
const FEE_TIERS = [500, 3_000, 10_000, 100] as const;

const CALL_TIMEOUT_MS = 6_000;

export type UniswapVenueOptions = {
  rpcUrls?: Partial<Record<number, string>>;
  timeoutMs?: number;
};

export class UniswapV3Venue implements ExecutionVenue {
  readonly name = "uniswap-v3";

  private readonly rpcUrls: Partial<Record<number, string>>;
  private readonly timeoutMs: number;

  constructor(options: UniswapVenueOptions = {}) {
    this.rpcUrls = options.rpcUrls ?? {
      1: env.rpcUrls.ethereum,
      11_155_111: env.rpcUrls.sepolia,
    };
    this.timeoutMs = options.timeoutMs ?? CALL_TIMEOUT_MS;
  }

  isReady(): boolean {
    return Object.keys(UNISWAP_V3_DEPLOYMENTS).some((chainId) =>
      this.hasRpc(Number(chainId)),
    );
  }

  readinessDetail(): string {
    const live = Object.keys(UNISWAP_V3_DEPLOYMENTS)
      .map(Number)
      .filter((chainId) => this.hasRpc(chainId));

    if (live.length === 0) {
      return "No RPC URL for any chain with a verified Uniswap v3 deployment (set RPC_URL_SEPOLIA or RPC_URL_ETHEREUM)";
    }

    return `On-chain QuoterV2 quotes on chain(s) ${live.join(", ")}`;
  }

  async quote(input: {
    chainId: number;
    inputToken: string;
    outputToken: string;
    amount: string;
    recipient: string;
    slippageBps: number;
  }): Promise<Availability<ExecutionQuote>> {
    const deployment = UNISWAP_V3_DEPLOYMENTS[input.chainId];

    if (deployment === undefined) {
      return unavailable<ExecutionQuote>(
        `No verified Uniswap v3 deployment recorded for chain ${input.chainId}`,
        false,
      );
    }

    const rpcUrl = this.rpcUrls[input.chainId] ?? "";

    if (rpcUrl.length === 0) {
      return unavailable<ExecutionQuote>(
        `No RPC URL configured for chain ${input.chainId}`,
        false,
      );
    }

    if (
      !isAddress(input.inputToken) ||
      !isAddress(input.outputToken) ||
      !isAddress(input.recipient)
    ) {
      return unavailable<ExecutionQuote>(
        "Uniswap quoting needs token and recipient addresses, not symbols",
        false,
      );
    }

    if (!/^\d+$/.test(input.amount) || BigInt(input.amount) === 0n) {
      return unavailable<ExecutionQuote>(
        "Amount must be a positive integer string in the input token's smallest unit",
        false,
      );
    }

    const client = createPublicClient({
      chain: input.chainId === 1 ? mainnet : sepolia,
      transport: http(rpcUrl, { timeout: this.timeoutMs }),
    });

    const failures: string[] = [];

    for (const fee of FEE_TIERS) {
      try {
        const result = await client.readContract({
          address: deployment.quoterV2 as `0x${string}`,
          abi: QUOTER_V2_ABI,
          functionName: "quoteExactInputSingle",
          args: [
            {
              tokenIn: input.inputToken as `0x${string}`,
              tokenOut: input.outputToken as `0x${string}`,
              amountIn: BigInt(input.amount),
              fee,
              sqrtPriceLimitX96: 0n,
            },
          ],
        });

        const amountOut = (result as readonly bigint[])[0] ?? 0n;

        if (amountOut === 0n) {
          failures.push(`fee ${fee}: zero output`);

          continue;
        }

        // Slippage is applied here rather than left to the router, because
        // `amountOutMinimum` is the only field that bounds what the agent can
        // lose to a sandwich, and it must come from the capability's declared
        // tolerance rather than a venue default.
        const amountOutMinimum =
          (amountOut * BigInt(10_000 - clampBps(input.slippageBps))) / 10_000n;

        const data = encodeFunctionData({
          abi: SWAP_ROUTER_02_ABI,
          functionName: "exactInputSingle",
          args: [
            {
              tokenIn: input.inputToken as `0x${string}`,
              tokenOut: input.outputToken as `0x${string}`,
              fee,
              recipient: input.recipient as `0x${string}`,
              amountIn: BigInt(input.amount),
              amountOutMinimum,
              sqrtPriceLimitX96: 0n,
            },
          ],
        });

        return ok({
          venue: this.name,
          chainId: input.chainId,
          to: deployment.swapRouter02,
          data,
          value: "0",
          estimatedOutput: amountOut.toString(),
          source: `uniswap-v3-quoterv2:${input.chainId}`,
        });
      } catch (error) {
        failures.push(`fee ${fee}: ${message(error)}`);
      }
    }

    return unavailable<ExecutionQuote>(
      `No Uniswap v3 pool answered a quote: ${failures.join("; ")}`,
      true,
    );
  }

  /**
   * The facts the firewall should check a venue quote against.
   *
   * `recipient` is decoded back out of the calldata the venue produced, so a
   * router (or a tampered response in between) that redirects the output is
   * caught by comparing bytes to the capability's allowlist rather than
   * trusting the quote's own summary.
   */
  describeForFirewall(quote: ExecutionQuote): {
    contract: string;
    selector: string;
    recipient: string | null;
  } {
    return {
      contract: quote.to.toLowerCase(),
      selector: quote.data.slice(0, 10).toLowerCase(),
      recipient: decodeExactInputSingleRecipient(quote.data),
    };
  }

  private hasRpc(chainId: number): boolean {
    return (this.rpcUrls[chainId] ?? "").length > 0;
  }
}

/**
 * Pulls the `recipient` out of `exactInputSingle` calldata.
 *
 * Hand-decoded from the fixed-size head rather than via a full ABI decode so
 * it still works on calldata this process did not build — which is the only
 * case where the check matters.
 */
export function decodeExactInputSingleRecipient(data: string): string | null {
  const body = data.slice(10);

  // tokenIn, tokenOut, fee, recipient: the fourth 32-byte word.
  if (body.length < 4 * 64) {
    return null;
  }

  const word = body.slice(3 * 64, 4 * 64);
  const address = `0x${word.slice(24)}`;

  return isAddress(address) ? address.toLowerCase() : null;
}

function clampBps(bps: number): number {
  if (!Number.isFinite(bps) || bps < 0) {
    return 0;
  }

  // A 100% slippage tolerance is not a tolerance, it is a donation.
  return Math.min(Math.floor(bps), 5_000);
}

function message(error: unknown): string {
  return error instanceof Error
    ? error.message.split("\n")[0] ?? error.message
    : String(error);
}
