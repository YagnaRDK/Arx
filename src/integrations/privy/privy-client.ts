/**
 * Minimal Privy server-wallet client over documented HTTP, no SDK.
 *
 * Sources (fetched 2026-09-12):
 *   - base URL `https://api.privy.io`, `Authorization: Basic <app id>:<app
 *     secret>` and the `privy-app-id` header:
 *     https://docs.privy.io/guide/server-wallets/quickstart/api
 *   - `POST /v1/wallets/{wallet_id}/rpc` with
 *     `{"method":"eth_signTransaction","params":{"transaction":{ to, value,
 *     chain_id, data, gas_limit, nonce, max_fee_per_gas,
 *     max_priority_fee_per_gas, type }}}` returning
 *     `{"method":...,"data":{"signed_transaction":"...","encoding":"rlp"}}`:
 *     https://docs.privy.io/api-reference/wallets/ethereum/eth-sign-transaction
 *   - `eth_signTypedData_v4` on the same route with
 *     `{"params":{"typed_data":{ domain, types, primary_type, message }}}`
 *     returning `{"data":{"signature":"...","encoding":...}}`:
 *     https://docs.privy.io/api-reference/wallets/ethereum/eth-signtypeddata-v4
 *   - `POST /v1/policies` with `{version, name, chain_type, rules:[{name,
 *     method, action, conditions:[{field_source, field, operator, value}]}]}`:
 *     https://docs.privy.io/controls/policies/create-a-policy
 *     https://docs.privy.io/controls/policies/example-policies/ethereum
 *
 * NOT implemented: the `privy-authorization-signature` header. Privy requires
 * it for wallets that have an owner or authorization key attached, and it is a
 * P-256 signature over a canonicalized request that Arx has no verified
 * construction for. An adapter that omitted it silently would fail at the
 * moment it mattered, so `PrivySignerAdapter` reports this in its status and
 * only ever fails closed on the resulting 401/403.
 */

import { requestJson, type HttpOutcome } from "../http";

const PRIVY_BASE_URL = "https://api.privy.io";

export type PrivyCredentials = {
  appId: string;
  appSecret: string;
  baseUrl?: string;
  timeoutMs?: number;
};

export type PrivyRpcResponse<T> = { method?: string; data?: T };

export type PrivySignedTransaction = {
  signed_transaction?: string;
  encoding?: string;
};

export type PrivySignature = { signature?: string; encoding?: string };

export type PrivyWallet = {
  id?: string;
  address?: string;
  chain_type?: string;
  policy_ids?: string[];
};

export type PrivyPolicy = { id?: string; name?: string; version?: string };

export type PrivyEthereumTransaction = {
  to: string;
  value: string;
  chain_id: number;
  data: string;
  gas_limit: string;
  nonce: number;
  max_fee_per_gas?: string;
  max_priority_fee_per_gas?: string;
  gas_price?: string;
  type?: number;
};

export type PrivyTypedData = {
  domain: Record<string, unknown>;
  types: Record<string, unknown>;
  primary_type: string;
  message: Record<string, unknown>;
};

/**
 * A Privy policy rule. Field names are Privy's, from the documented example.
 */
export type PrivyPolicyRule = {
  name: string;
  method: string;
  action: "ALLOW" | "DENY";
  conditions: {
    field_source: string;
    field: string;
    operator: string;
    value: unknown;
  }[];
};

export class PrivyClient {
  readonly baseUrl: string;

  private readonly appId: string;
  private readonly appSecret: string;
  private readonly timeoutMs: number;

  constructor(credentials: PrivyCredentials) {
    this.appId = credentials.appId;
    this.appSecret = credentials.appSecret;
    this.baseUrl = (credentials.baseUrl ?? PRIVY_BASE_URL).replace(/\/+$/, "");
    this.timeoutMs = credentials.timeoutMs ?? 10_000;
  }

  get configured(): boolean {
    return this.appId.length > 0 && this.appSecret.length > 0;
  }

  getWallet(walletId: string): Promise<HttpOutcome<PrivyWallet>> {
    return this.call<PrivyWallet>({
      path: `/v1/wallets/${encodeURIComponent(walletId)}`,
      method: "GET",
    });
  }

  signTransaction(
    walletId: string,
    transaction: PrivyEthereumTransaction,
  ): Promise<HttpOutcome<PrivyRpcResponse<PrivySignedTransaction>>> {
    return this.call<PrivyRpcResponse<PrivySignedTransaction>>({
      path: `/v1/wallets/${encodeURIComponent(walletId)}/rpc`,
      method: "POST",
      body: {
        method: "eth_signTransaction",
        params: { transaction },
      },
      timeoutMs: 20_000,
    });
  }

  signTypedData(
    walletId: string,
    typedData: PrivyTypedData,
  ): Promise<HttpOutcome<PrivyRpcResponse<PrivySignature>>> {
    return this.call<PrivyRpcResponse<PrivySignature>>({
      path: `/v1/wallets/${encodeURIComponent(walletId)}/rpc`,
      method: "POST",
      body: {
        method: "eth_signTypedData_v4",
        params: { typed_data: typedData },
      },
      timeoutMs: 20_000,
    });
  }

  createPolicy(policy: {
    name: string;
    chain_type: string;
    rules: PrivyPolicyRule[];
    version?: string;
  }): Promise<HttpOutcome<PrivyPolicy>> {
    return this.call<PrivyPolicy>({
      path: "/v1/policies",
      method: "POST",
      body: { version: policy.version ?? "1.0", ...policy },
    });
  }

  getPolicy(policyId: string): Promise<HttpOutcome<PrivyPolicy>> {
    return this.call<PrivyPolicy>({
      path: `/v1/policies/${encodeURIComponent(policyId)}`,
      method: "GET",
    });
  }

  private call<T>(input: {
    path: string;
    method: "GET" | "POST";
    body?: unknown;
    timeoutMs?: number;
  }): Promise<HttpOutcome<T>> {
    const basic = Buffer.from(`${this.appId}:${this.appSecret}`, "utf8").toString(
      "base64",
    );

    return requestJson<T>({
      url: `${this.baseUrl}${input.path}`,
      method: input.method,
      ...(input.body === undefined ? {} : { body: input.body }),
      headers: {
        authorization: `Basic ${basic}`,
        "privy-app-id": this.appId,
      },
      timeoutMs: input.timeoutMs ?? this.timeoutMs,
      // Privy's error bodies name the policy that refused, which is exactly
      // what an operator needs to see.
      expectStatuses: [400, 401, 403, 404, 422],
    });
  }
}
