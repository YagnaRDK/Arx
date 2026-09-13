/**
 * Thin client over The Graph's Token API.
 *
 * The Token API is operated on Pinax infrastructure: `token-api.thegraph.com`
 * is a CNAME to `token-api.service.pinax.network`, and The Graph's own docs URL
 * (`https://thegraph.com/docs/en/token-api/quick-start/`) 301-redirects to
 * `https://app.pinax.network/docs/api/`. Verified on 2026-09-12:
 *   - `https://api.pinax.network/openapi` serves the live OpenAPI document
 *     (`"title":"Pinax API","version":"3.21.1+af56ff2 (2026-07-09)"`), listing
 *     `/v1/evm/transfers`, `/v1/evm/transfers/native`, `/v1/evm/balances`,
 *     `/v1/evm/tokens` and `/v1/evm/holders`.
 *   - an unauthenticated request to `/v1/evm/transfers` returns
 *     `{"error":{"status":401,"code":"unauthorized"}}`.
 *   - `https://token-api.thegraph.com/...` fails the TLS handshake outright,
 *     so the legacy host is not usable as a base URL.
 *
 * Auth is `Authorization: Bearer <token>` per the documented scheme
 * (`bearerAuth` in the OpenAPI `securitySchemes`).
 */

import { requestJson, type HttpOutcome } from "../http";

/** Exactly the `network` enum from the live OpenAPI document, EVM endpoints. */
export const TOKEN_API_NETWORKS = [
  "arbitrum-one",
  "avalanche",
  "base",
  "bsc",
  "hyperevm",
  "mainnet",
  "optimism",
  "polygon",
  "unichain",
] as const;

export type TokenApiNetwork = (typeof TOKEN_API_NETWORKS)[number];

/**
 * Chain id to Token API network name. Only chains the API actually indexes
 * appear here: an unlisted chain must produce `UNAVAILABLE`, never a lookup
 * against the wrong network's data.
 */
export const CHAIN_ID_TO_TOKEN_API_NETWORK: Readonly<
  Record<number, TokenApiNetwork>
> = {
  1: "mainnet",
  10: "optimism",
  56: "bsc",
  130: "unichain",
  137: "polygon",
  8453: "base",
  42161: "arbitrum-one",
  43114: "avalanche",
};

export type TransferRow = {
  block_num?: number;
  timestamp?: number;
  datetime?: string;
  transaction_id?: string;
  contract?: string;
  from?: string;
  to?: string;
  value?: string | number;
};

type TransfersResponse = { data?: TransferRow[] };

export type TokenApiClientOptions = {
  baseUrl: string;
  apiKey: string;
  timeoutMs?: number;
};

export class TokenApiClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly timeoutMs: number;

  constructor(options: TokenApiClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.apiKey = options.apiKey;
    this.timeoutMs = options.timeoutMs ?? 5_000;
  }

  /** ERC-20 transfers. `direction` selects which side the address is on. */
  transfers(input: {
    network: TokenApiNetwork;
    address: string;
    direction: "to" | "from";
    limit: number;
    page: number;
  }): Promise<HttpOutcome<TransfersResponse>> {
    return this.get("/v1/evm/transfers", input);
  }

  /** Native-value transfers, which ERC-20 transfers do not cover. */
  nativeTransfers(input: {
    network: TokenApiNetwork;
    address: string;
    direction: "to" | "from";
    limit: number;
    page: number;
  }): Promise<HttpOutcome<TransfersResponse>> {
    return this.get("/v1/evm/transfers/native", input);
  }

  private get(
    path: string,
    input: {
      network: TokenApiNetwork;
      address: string;
      direction: "to" | "from";
      limit: number;
      page: number;
    },
  ): Promise<HttpOutcome<TransfersResponse>> {
    const query = new URLSearchParams({
      network: input.network,
      [input.direction === "to" ? "to_address" : "from_address"]:
        input.address.toLowerCase(),
      limit: String(input.limit),
      page: String(input.page),
    });

    return requestJson<TransfersResponse>({
      url: `${this.baseUrl}${path}?${query.toString()}`,
      headers: { authorization: `Bearer ${this.apiKey}` },
      timeoutMs: this.timeoutMs,
    });
  }
}

export function rowsOf(response: { data?: TransferRow[] }): TransferRow[] {
  return Array.isArray(response.data) ? response.data : [];
}
