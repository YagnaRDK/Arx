/**
 * 1inch as an `ExecutionVenue`, in two shapes — one implemented, one honestly
 * unconfigured.
 *
 * 1. `OneInchClassicSwapVenue` — the Classic Swap aggregation API. Implemented
 *    and functional, but it needs an API key, and `src/config/env.ts` has no
 *    field for one, so it must be constructed with `apiKey` explicitly and
 *    reports `isReady() === false` otherwise.
 *
 *    Verified 2026-09-12 against 1inch's own documentation,
 *    https://business.1inch.com/portal/documentation/apis/swap/classic-swap/quick-start :
 *    base `https://api.1inch.com/swap/v6.1/{chainId}`, paths `/quote` and
 *    `/swap`, query parameters `src`, `dst`, `amount`, `from`, `slippage`,
 *    `disableEstimate`, `allowPartialFill`, auth via
 *    `Authorization: Bearer <apiKey>`, and a `/swap` response carrying
 *    `tx.to`, `tx.data`, `tx.value` plus `dstAmount`.
 *
 * 2. `AquaSwapVmVenue` — the Aqua / SwapVM onchain path. **Not implemented,
 *    and deliberately not guessed.** 1inch's Aqua repository
 *    (https://github.com/1inch/aqua) ships no deployments directory, no
 *    address list and no canonical registry: `DEPLOY.md` is a guide for
 *    deploying *your own* `AquaRouter` via Foundry, parameterized by
 *    `OPS_CHAIN_ID` and `OPS_AQUA_ROUTER_ADDRESS`. There is therefore no
 *    official AquaRouter/SwapVMRouter address this adapter could verify, and a
 *    fabricated router address in an authorization layer would be strictly
 *    worse than a missing feature: every policy check downstream would be
 *    validating calls to a contract that does not exist. So the venue accepts
 *    an operator-supplied `routerAddress` and stays `isReady() === false`
 *    until one is given.
 *
 * Either way, the Arx angle is the same as Uniswap's: the venue's calldata is
 * treated as untrusted input. `describeForFirewall` reports the contract and
 * selector so the capability's `contracts` and `methods` policy sets decide
 * whether that call may be signed — a router is not trusted merely because the
 * agent asked it for a quote.
 */

import { isAddress } from "viem";

import {
  ok,
  unavailable,
  type Availability,
  type ExecutionQuote,
  type ExecutionVenue,
} from "../../core/seams";
import { requestJson } from "../http";

const DEFAULT_BASE_URL = "https://api.1inch.com";

/** Chains 1inch Classic Swap serves. Quoting an unlisted chain fails closed. */
export const ONEINCH_SUPPORTED_CHAINS = new Set([
  1, 10, 56, 100, 130, 137, 324, 8453, 42161, 43114, 59144, 8217,
]);

export type OneInchVenueOptions = {
  apiKey?: string;
  baseUrl?: string;
  timeoutMs?: number;
};

type OneInchSwapResponse = {
  dstAmount?: string;
  tx?: { to?: string; data?: string; value?: string };
};

export class OneInchClassicSwapVenue implements ExecutionVenue {
  readonly name = "1inch-classic-swap";

  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(options: OneInchVenueOptions = {}) {
    this.apiKey = options.apiKey ?? "";
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.timeoutMs = options.timeoutMs ?? 6_000;
  }

  isReady(): boolean {
    return this.apiKey.length > 0;
  }

  readinessDetail(): string {
    return this.isReady()
      ? `1inch Classic Swap v6.1 at ${this.baseUrl}`
      : "No 1inch API key. There is no env field for one in src/config/env.ts; pass apiKey explicitly (see report) to enable.";
  }

  async quote(input: {
    chainId: number;
    inputToken: string;
    outputToken: string;
    amount: string;
    recipient: string;
    slippageBps: number;
  }): Promise<Availability<ExecutionQuote>> {
    if (!this.isReady()) {
      return unavailable<ExecutionQuote>(this.readinessDetail(), false);
    }

    if (!ONEINCH_SUPPORTED_CHAINS.has(input.chainId)) {
      return unavailable<ExecutionQuote>(
        `1inch Classic Swap does not serve chain ${input.chainId}`,
        false,
      );
    }

    if (
      !isAddress(input.inputToken) ||
      !isAddress(input.outputToken) ||
      !isAddress(input.recipient)
    ) {
      return unavailable<ExecutionQuote>(
        "1inch quoting needs token and recipient addresses, not symbols",
        false,
      );
    }

    const query = new URLSearchParams({
      src: input.inputToken,
      dst: input.outputToken,
      amount: input.amount,
      from: input.recipient,
      // 1inch takes percent, Arx carries basis points.
      slippage: String(Math.min(50, Math.max(0, input.slippageBps / 100))),
      // Arx has not moved the funds yet, so an on-chain gas estimate against
      // the payer's current balance would fail and be reported as a routing
      // failure. Estimation is Arx's job anyway.
      disableEstimate: "true",
      allowPartialFill: "false",
    });

    const outcome = await requestJson<OneInchSwapResponse>({
      url: `${this.baseUrl}/swap/v6.1/${input.chainId}/swap?${query.toString()}`,
      headers: { authorization: `Bearer ${this.apiKey}` },
      timeoutMs: this.timeoutMs,
    });

    if (!outcome.ok) {
      return unavailable<ExecutionQuote>(
        `1inch quote failed: ${outcome.failure.message}`,
        outcome.failure.kind === "TIMEOUT" || outcome.failure.kind === "NETWORK",
      );
    }

    const to = outcome.value.tx?.to;
    const data = outcome.value.tx?.data;

    if (typeof to !== "string" || typeof data !== "string") {
      return unavailable<ExecutionQuote>(
        "1inch response carried no transaction to authorize",
        false,
      );
    }

    return ok({
      venue: this.name,
      chainId: input.chainId,
      to,
      data,
      value: outcome.value.tx?.value ?? "0",
      ...(outcome.value.dstAmount === undefined
        ? {}
        : { estimatedOutput: outcome.value.dstAmount }),
      source: `1inch-classic-swap-v6.1:${input.chainId}`,
    });
  }

  /** See the Uniswap adapter: venue calldata is checked, not trusted. */
  describeForFirewall(quote: ExecutionQuote): {
    contract: string;
    selector: string;
  } {
    return {
      contract: quote.to.toLowerCase(),
      selector: quote.data.slice(0, 10).toLowerCase(),
    };
  }
}

export type AquaVenueOptions = {
  /**
   * An AquaRouter / SwapVMRouter address the operator deployed themselves.
   * There is no canonical published deployment to default to.
   */
  routerAddress?: string;
  chainId?: number;
};

/**
 * Aqua / SwapVM venue. Interface-complete, intentionally inert: it answers
 * `UNAVAILABLE` with the reason until an operator supplies a router address
 * they have verified. See the module comment for why nothing is hard-coded.
 */
export class AquaSwapVmVenue implements ExecutionVenue {
  readonly name = "1inch-aqua-swapvm";

  private readonly routerAddress: string;
  private readonly chainId: number | undefined;

  constructor(options: AquaVenueOptions = {}) {
    this.routerAddress = options.routerAddress ?? "";
    this.chainId = options.chainId;
  }

  isReady(): boolean {
    return isAddress(this.routerAddress) && this.chainId !== undefined;
  }

  readinessDetail(): string {
    if (!isAddress(this.routerAddress)) {
      return "No AquaRouter address. 1inch publishes no canonical Aqua/SwapVM deployment list (github.com/1inch/aqua ships a Foundry deploy guide, not addresses), so none is assumed. Supply routerAddress + chainId to enable.";
    }

    if (this.chainId === undefined) {
      return "AquaRouter address given but no chainId; a router address without a chain is not a deployment";
    }

    return `AquaRouter ${this.routerAddress} on chain ${this.chainId} (operator-supplied, not verified by Arx)`;
  }

  async quote(): Promise<Availability<ExecutionQuote>> {
    return unavailable<ExecutionQuote>(
      `Aqua/SwapVM quoting is not implemented: ${this.readinessDetail()}`,
      false,
    );
  }
}
