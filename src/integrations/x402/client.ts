/**
 * The agent-side half of x402: a payer that cannot pay without authorization.
 *
 * This is the whole Arx thesis reduced to one HTTP call. An autonomous agent
 * hits a paid endpoint, gets a 402 with terms, and then — before any signature
 * exists — the payment is expressed as an ordinary EVM transaction and pushed
 * through Arx's own policy and firewall path. If Arx denies it, the client
 * never calls the signer. The agent has a budget and an allowlist, not a wallet.
 *
 * Two dependencies are injected rather than constructed, because both are
 * trust boundaries this module must not own:
 *
 *   - `authorize`: the Arx decision. `createArxFirewallAuthorizer` below posts
 *     to Arx's `POST /firewall/submit`, so the payment is checked by the same
 *     capability, spend-window, recipient and method policy as any other
 *     transaction. Nothing here re-implements policy.
 *   - `signTypedData`: the signing boundary. There is no default. Without one
 *     the client reports `isReady() === false` and refuses to fabricate a
 *     payment, because a payer that can invent its own signature is the exact
 *     thing Arx exists to prevent.
 *
 * The EIP-3009 authorization is the same structure the gate verifies; see
 * `./types.ts` for the specification citations.
 */

import { encodeFunctionData, parseAbi } from "viem";

import { requestJson } from "../http";
import {
  PaymentRequirementsResponseSchema,
  TRANSFER_WITH_AUTHORIZATION_TYPES,
  X402_PAYMENT_HEADER,
  X402_PAYMENT_RESPONSE_HEADER,
  X402_VERSION,
  decodeHeaderValue,
  encodeHeaderValue,
  type PaymentPayload,
  type PaymentRequirements,
  type SettlementResponse,
} from "./types";
import { x402Network, type X402NetworkConfig } from "./networks";

/** EIP-3009, as it appears on an EIP-3009 token. */
const TRANSFER_WITH_AUTHORIZATION_ABI = parseAbi([
  "function transferWithAuthorization(address from, address to, uint256 value, uint256 validAfter, uint256 validBefore, bytes32 nonce, bytes signature)",
]);

export type TypedDataRequest = {
  domain: {
    name: string;
    version: string;
    chainId: number;
    verifyingContract: string;
  };
  types: typeof TRANSFER_WITH_AUTHORIZATION_TYPES;
  primaryType: "TransferWithAuthorization";
  message: {
    from: string;
    to: string;
    value: string;
    validAfter: string;
    validBefore: string;
    nonce: string;
  };
};

/** Anything that can produce an EIP-712 signature for the payer's address. */
export type TypedDataSigner = {
  readonly name: string;
  address: string;
  signTypedData(request: TypedDataRequest): Promise<string>;
};

/**
 * The transaction Arx is asked to authorize. This is a real EVM transaction:
 * calling `transferWithAuthorization` on the asset contract is exactly how the
 * payment settles, so the firewall inspects the same `to` and selector that
 * will eventually move the funds.
 */
export type PaymentTransactionPreview = {
  chainId: number;
  to: string;
  data: string;
  value: string;
  asset: string;
  assetSymbol: string;
  payTo: string;
  amountAtomic: string;
  amountDecimal: string;
};

export type X402AuthorizationRequest = {
  resourceUrl: string;
  requirements: PaymentRequirements;
  network: X402NetworkConfig;
  preview: PaymentTransactionPreview;
};

export type X402AuthorizationOutcome =
  | { allowed: true; reference?: string; details?: unknown }
  | { allowed: false; code: string; reason: string; details?: unknown };

export type X402Authorizer = {
  readonly name: string;
  authorize(
    request: X402AuthorizationRequest,
  ): Promise<X402AuthorizationOutcome>;
};

export type X402ClientOptions = {
  authorizer: X402Authorizer;
  signer?: TypedDataSigner;
  /** Seconds the authorization stays valid. Kept short on purpose. */
  validitySeconds?: number;
  /** Injected for determinism in tests and the demo. */
  now?: () => number;
  randomNonce?: () => string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  /** Ceiling on what the client will ever agree to pay, in atomic units. */
  maxAmountAtomic?: string;
};

export type X402PaidResult = {
  outcome: "PAID";
  status: number;
  body: unknown;
  payer: string;
  amountAtomic: string;
  requirements: PaymentRequirements;
  settlement?: SettlementResponse;
  authorizationReference?: string;
};

export type X402RefusedResult = {
  outcome: "REFUSED_BY_ARX";
  code: string;
  reason: string;
  requirements: PaymentRequirements;
  preview: PaymentTransactionPreview;
  details?: unknown;
};

export type X402FailedResult = {
  outcome: "FAILED";
  reason: string;
  stage:
    | "INITIAL_REQUEST"
    | "PARSE_402"
    | "SELECT_REQUIREMENT"
    | "SIGNING"
    | "RETRY_REQUEST";
};

export type X402FreeResult = {
  outcome: "NO_PAYMENT_REQUIRED";
  status: number;
  body: unknown;
};

export type X402FetchResult =
  | X402PaidResult
  | X402RefusedResult
  | X402FailedResult
  | X402FreeResult;

export class X402Client {
  readonly name = "x402-client";

  private readonly authorizer: X402Authorizer;
  private readonly signer: TypedDataSigner | undefined;
  private readonly validitySeconds: number;
  private readonly now: () => number;
  private readonly randomNonce: () => string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  private readonly maxAmountAtomic: bigint | null;

  constructor(options: X402ClientOptions) {
    this.authorizer = options.authorizer;
    this.signer = options.signer;
    this.validitySeconds = options.validitySeconds ?? 120;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
    this.randomNonce = options.randomNonce ?? defaultNonce;
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.maxAmountAtomic =
      options.maxAmountAtomic === undefined
        ? null
        : BigInt(options.maxAmountAtomic);
  }

  isReady(): boolean {
    return this.signer !== undefined;
  }

  readinessDetail(): string {
    if (this.signer === undefined) {
      return "No typed-data signer wired: the client can read a 402 but will not produce a payment";
    }

    return `Payer ${this.signer.address} via ${this.signer.name}, authorized by ${this.authorizer.name}`;
  }

  /** Performs the request, paying at most once if a 402 comes back. */
  async fetch(
    url: string,
    init: RequestInit = {},
  ): Promise<X402FetchResult> {
    const first = await this.send(url, init);

    if (first === null) {
      return {
        outcome: "FAILED",
        reason: `Request to ${url} failed or timed out`,
        stage: "INITIAL_REQUEST",
      };
    }

    if (first.status !== 402) {
      return {
        outcome: "NO_PAYMENT_REQUIRED",
        status: first.status,
        body: await readBody(first),
      };
    }

    const parsed = PaymentRequirementsResponseSchema.safeParse(
      await readBody(first),
    );

    if (!parsed.success) {
      return {
        outcome: "FAILED",
        reason: "402 response body is not an x402 PaymentRequirementsResponse",
        stage: "PARSE_402",
      };
    }

    const selection = this.selectRequirement(parsed.data.accepts);

    if ("reason" in selection) {
      return {
        outcome: "FAILED",
        reason: selection.reason,
        stage: "SELECT_REQUIREMENT",
      };
    }

    const { requirements, network } = selection;

    if (this.signer === undefined) {
      return {
        outcome: "FAILED",
        reason: this.readinessDetail(),
        stage: "SIGNING",
      };
    }

    const issuedAt = this.now();
    const authorizationNonce = this.randomNonce();
    const validAfter = String(Math.max(0, issuedAt - 5));
    const validBefore = String(issuedAt + this.validitySeconds);

    const preview = this.buildPreview({
      requirements,
      network,
      from: this.signer.address,
      nonce: authorizationNonce,
      validAfter,
      validBefore,
    });

    // The firewall runs before the signer, never after. An agent that signs
    // first and asks second has already leaked a spendable authorization.
    const decision = await this.authorizer.authorize({
      resourceUrl: requirements.resource || url,
      requirements,
      network,
      preview,
    });

    if (!decision.allowed) {
      return {
        outcome: "REFUSED_BY_ARX",
        code: decision.code,
        reason: decision.reason,
        requirements,
        preview,
        ...(decision.details === undefined ? {} : { details: decision.details }),
      };
    }

    let signature: string;

    try {
      signature = await this.signer.signTypedData({
        domain: {
          name: network.eip712?.name ?? "",
          version: network.eip712?.version ?? "",
          chainId: network.chainId,
          verifyingContract: network.asset,
        },
        types: TRANSFER_WITH_AUTHORIZATION_TYPES,
        primaryType: "TransferWithAuthorization",
        message: {
          from: this.signer.address,
          to: requirements.payTo,
          value: requirements.maxAmountRequired,
          validAfter,
          validBefore,
          nonce: authorizationNonce,
        },
      });
    } catch (error) {
      return {
        outcome: "FAILED",
        reason: `Typed-data signing failed: ${describe(error)}`,
        stage: "SIGNING",
      };
    }

    const payload: PaymentPayload = {
      x402Version: X402_VERSION,
      scheme: requirements.scheme,
      network: requirements.network,
      payload: {
        signature,
        authorization: {
          from: this.signer.address as `0x${string}`,
          to: requirements.payTo as `0x${string}`,
          value: requirements.maxAmountRequired,
          validAfter,
          validBefore,
          nonce: authorizationNonce as `0x${string}`,
        },
      },
    };

    const retry = await this.send(url, {
      ...init,
      headers: {
        ...headerRecord(init.headers),
        [X402_PAYMENT_HEADER]: encodeHeaderValue(payload),
      },
    });

    if (retry === null) {
      return {
        outcome: "FAILED",
        reason: `Paid request to ${url} failed or timed out`,
        stage: "RETRY_REQUEST",
      };
    }

    const settlementHeader = retry.headers.get(X402_PAYMENT_RESPONSE_HEADER);
    let settlement: SettlementResponse | undefined;

    if (settlementHeader !== null) {
      try {
        settlement = decodeHeaderValue(settlementHeader) as SettlementResponse;
      } catch {
        settlement = undefined;
      }
    }

    return {
      outcome: "PAID",
      status: retry.status,
      body: await readBody(retry),
      payer: this.signer.address,
      amountAtomic: requirements.maxAmountRequired,
      requirements,
      ...(settlement === undefined ? {} : { settlement }),
      ...(decision.reference === undefined
        ? {}
        : { authorizationReference: decision.reference }),
    };
  }

  /**
   * Picks the cheapest requirement Arx knows how to describe as a transaction.
   * A requirement on an unknown network or scheme is skipped rather than
   * attempted: paying into something Arx cannot model means the firewall would
   * be inspecting a transaction that is not the one that settles.
   */
  private selectRequirement(
    accepts: readonly PaymentRequirements[],
  ):
    | { requirements: PaymentRequirements; network: X402NetworkConfig }
    | { reason: string } {
    const candidates: {
      requirements: PaymentRequirements;
      network: X402NetworkConfig;
    }[] = [];

    for (const requirements of accepts) {
      if (requirements.scheme !== "exact") {
        continue;
      }

      const network = x402Network(requirements.network);

      if (network === undefined || !network.exactEvm) {
        continue;
      }

      if (
        this.maxAmountAtomic !== null &&
        BigInt(requirements.maxAmountRequired) > this.maxAmountAtomic
      ) {
        continue;
      }

      candidates.push({ requirements, network });
    }

    candidates.sort(
      (a, b) =>
        Number(
          BigInt(a.requirements.maxAmountRequired) -
            BigInt(b.requirements.maxAmountRequired),
        ),
    );

    const chosen = candidates[0];

    if (chosen === undefined) {
      return {
        reason: `None of the ${accepts.length} offered requirement(s) are payable: need scheme "exact" on a known EIP-3009 network within the configured ceiling`,
      };
    }

    return chosen;
  }

  private buildPreview(input: {
    requirements: PaymentRequirements;
    network: X402NetworkConfig;
    from: string;
    nonce: string;
    validAfter: string;
    validBefore: string;
  }): PaymentTransactionPreview {
    const { requirements, network } = input;

    // The signature field is empty at preview time — it does not exist yet.
    // What the firewall needs is the destination contract, the selector and the
    // encoded recipient and amount, all of which are already final.
    const data = encodeFunctionData({
      abi: TRANSFER_WITH_AUTHORIZATION_ABI,
      functionName: "transferWithAuthorization",
      args: [
        input.from as `0x${string}`,
        requirements.payTo as `0x${string}`,
        BigInt(requirements.maxAmountRequired),
        BigInt(input.validAfter),
        BigInt(input.validBefore),
        input.nonce as `0x${string}`,
        "0x",
      ],
    });

    return {
      chainId: network.chainId,
      to: network.asset,
      data,
      value: "0",
      asset: network.asset,
      assetSymbol: network.assetSymbol,
      payTo: requirements.payTo,
      amountAtomic: requirements.maxAmountRequired,
      amountDecimal: fromAtomic(
        requirements.maxAmountRequired,
        network.assetDecimals,
      ),
    };
  }

  private async send(
    url: string,
    init: RequestInit,
  ): Promise<Response | null> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      return await this.fetchImpl(url, { ...init, signal: controller.signal });
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }
}

/**
 * The authorizer that makes this integration Arx-shaped: it posts the payment
 * to Arx's own firewall endpoint as an intent carrying the real calldata, so a
 * capability's recipient allowlist, method allowlist, value ceiling and spend
 * window all apply to the agent's API spending.
 *
 * `amountUsd` is the agent's claim about the payment's value, exactly as with
 * any other intent — Arx cross-checks it, and this module does not get to
 * decide it is true.
 */
export function createArxFirewallAuthorizer(options: {
  baseUrl: string;
  agentId: string;
  capabilityId: string;
  action?: string;
  protocol?: string;
  /** Nonce source for the Arx intent. Must be monotonic per capability. */
  nextNonce: () => number;
  headers?: Record<string, string>;
  now?: () => number;
  gasLimit?: string;
  maxFeePerGas?: string;
  maxPriorityFeePerGas?: string;
  timeoutMs?: number;
}): X402Authorizer {
  const baseUrl = options.baseUrl.replace(/\/+$/, "");
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));

  return {
    name: `arx-firewall(${baseUrl})`,

    async authorize(request) {
      const intent = {
        capabilityId: options.capabilityId,
        agentId: options.agentId,
        action: options.action ?? "x402_payment",
        protocol: options.protocol ?? "x402",
        chainId: request.preview.chainId,
        inputToken: request.preview.assetSymbol,
        outputToken: "API_ACCESS",
        amountUsd: Number(request.preview.amountDecimal),
        slippageBps: 0,
        nonce: options.nextNonce(),
        timestamp: now(),
        transaction: {
          chainId: request.preview.chainId,
          to: request.preview.to,
          value: request.preview.value,
          data: request.preview.data,
          gasLimit: options.gasLimit ?? "120000",
          maxFeePerGas: options.maxFeePerGas ?? "2000000000",
          maxPriorityFeePerGas: options.maxPriorityFeePerGas ?? "100000000",
          nonce: 0,
          type: "eip1559" as const,
        },
      };

      const outcome = await requestJson<Record<string, unknown>>({
        url: `${baseUrl}/firewall/submit`,
        method: "POST",
        body: intent,
        headers: options.headers,
        timeoutMs: options.timeoutMs ?? 8_000,
        // 4xx bodies carry the DecisionCode, which is the whole point of asking.
        expectStatuses: [400, 403, 409, 422],
      });

      if (!outcome.ok) {
        // Arx unreachable is not permission. Fail closed.
        return {
          allowed: false,
          code: "SIGNER_UNAVAILABLE",
          reason: `Arx firewall unreachable, refusing to pay: ${outcome.failure.message}`,
        };
      }

      if (outcome.status === 200) {
        const transactionId = outcome.value["transactionId"];

        return {
          allowed: true,
          ...(typeof transactionId === "string"
            ? { reference: transactionId }
            : {}),
          details: outcome.value,
        };
      }

      const code = outcome.value["code"];
      const reason = outcome.value["reason"];

      return {
        allowed: false,
        code: typeof code === "string" ? code : "TRANSACTION_NOT_ALLOWED",
        reason:
          typeof reason === "string"
            ? reason
            : `Arx refused the payment (HTTP ${outcome.status})`,
        details: outcome.value,
      };
    },
  };
}

/** Refuses everything. Useful as an explicit "not wired yet" authorizer. */
export function denyAllAuthorizer(reason: string): X402Authorizer {
  return {
    name: "deny-all",
    async authorize() {
      return { allowed: false, code: "FORBIDDEN", reason };
    },
  };
}

function defaultNonce(): string {
  const bytes = new Uint8Array(32);

  crypto.getRandomValues(bytes);

  return `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function fromAtomic(amount: string, decimals: number): string {
  const padded = amount.padStart(decimals + 1, "0");
  const whole = padded.slice(0, padded.length - decimals);
  const fraction = padded.slice(padded.length - decimals).replace(/0+$/, "");

  return fraction.length === 0 ? whole : `${whole}.${fraction}`;
}

function headerRecord(
  headers: RequestInit["headers"],
): Record<string, string> {
  if (headers === undefined) {
    return {};
  }

  if (headers instanceof Headers) {
    return Object.fromEntries(headers.entries());
  }

  if (Array.isArray(headers)) {
    return Object.fromEntries(headers as [string, string][]);
  }

  return headers as Record<string, string>;
}

async function readBody(response: Response): Promise<unknown> {
  const text = await response.text();

  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
