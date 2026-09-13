/**
 * The server half of x402: a framework-agnostic gate that turns a route into a
 * paid resource.
 *
 * Arx hosts this so an agent's *payment for an API call* becomes a first-class
 * authorization event rather than an invisible side effect. The gate does real
 * cryptography: it recovers the EIP-712 signer of the EIP-3009 authorization,
 * checks the amount, recipient and validity window against the requirement it
 * published, and claims the authorization nonce exactly once so a replayed
 * `X-PAYMENT` header buys nothing twice.
 *
 * What it does *not* do is pretend to settle. Settlement moves money, and
 * moving money requires either a facilitator or a funded signer. So:
 *
 *   - `X402_FACILITATOR_URL` set  -> `FACILITATOR` mode: `/verify` then
 *     `/settle` against the facilitator, and the `X-PAYMENT-RESPONSE` header
 *     carries the real transaction hash it returns.
 *   - unset -> `LOCAL_VERIFICATION_ONLY`: the signature is genuinely verified,
 *     but nothing settles. The gate **denies** in this mode unless the operator
 *     passes `allowUnsettledPayments: true`, and when they do, every response
 *     says `settled: false` and names the mode. An unsettled payment is never
 *     reported as a payment.
 *
 * Header names and body shapes come from the spec; see `./types.ts` for the
 * exact citations.
 */

import { verifyTypedData } from "viem";

import { env } from "../../config/env";
import { claimOnce } from "../cache";
import { requestJson } from "../http";
import {
  FacilitatorSettleResponseSchema,
  FacilitatorVerifyResponseSchema,
  PaymentPayloadSchema,
  TRANSFER_WITH_AUTHORIZATION_TYPES,
  X402_ERRORS,
  X402_PAYMENT_HEADER,
  X402_PAYMENT_RESPONSE_HEADER,
  X402_V2_PAYMENT_SIGNATURE_HEADER,
  X402_VERSION,
  decodeHeaderValue,
  encodeHeaderValue,
  type PaymentPayload,
  type PaymentRequirements,
  type PaymentRequirementsResponse,
  type SettlementResponse,
} from "./types";
import {
  X402_NETWORKS,
  toAtomicAmount,
  x402Network,
  type X402NetworkConfig,
} from "./networks";

export type X402SettlementMode = "FACILITATOR" | "LOCAL_VERIFICATION_ONLY";

export type X402GateOptions = {
  enabled?: boolean;
  network?: string;
  payTo?: string;
  /** Decimal price, e.g. "0.01". */
  priceUsdc?: string;
  facilitatorUrl?: string;
  /** Absolute URL of the resource being gated, echoed in `accepts[].resource`. */
  resourceUrl?: string;
  description?: string;
  maxTimeoutSeconds?: number;
  /**
   * Grant access on a locally verified but unsettled authorization. Off by
   * default: an authorization that cannot be settled is not a payment.
   */
  allowUnsettledPayments?: boolean;
  now?: () => number;
};

export type X402Denial = {
  outcome: "PAYMENT_REQUIRED";
  status: 402;
  body: PaymentRequirementsResponse;
  /** Spec error code, when the denial was caused by a specific payload fault. */
  errorCode?: string;
};

export type X402Grant = {
  outcome: "PAID";
  payer: string;
  settlement: SettlementResponse & {
    settled: boolean;
    mode: X402SettlementMode;
  };
  /** Merge into the 200 response. */
  responseHeaders: Record<string, string>;
};

export type X402Bypass = { outcome: "NOT_GATED"; reason: string };

export type X402GateResult = X402Denial | X402Grant | X402Bypass;

export type X402GateStatus = {
  enabled: boolean;
  ready: boolean;
  network: string;
  chainId?: number;
  asset?: string;
  priceAtomic?: string;
  payTo: string;
  settlementMode: X402SettlementMode;
  allowUnsettledPayments: boolean;
  detail: string;
};

export class X402Gate {
  readonly name = "x402-server";

  private readonly enabled: boolean;
  private readonly networkName: string;
  private readonly config: X402NetworkConfig | undefined;
  private readonly payTo: string;
  private readonly priceUsdc: string;
  private readonly facilitatorUrl: string;
  private readonly resourceUrl: string;
  private readonly description: string;
  private readonly maxTimeoutSeconds: number;
  private readonly allowUnsettled: boolean;
  private readonly now: () => number;

  constructor(options: X402GateOptions = {}) {
    this.enabled = options.enabled ?? env.x402Enabled;
    this.networkName = options.network ?? env.x402Network;
    this.config = x402Network(this.networkName);
    this.payTo = options.payTo ?? env.x402PayTo;
    this.priceUsdc = options.priceUsdc ?? env.x402PriceUsdc;
    this.facilitatorUrl = (
      options.facilitatorUrl ?? env.x402FacilitatorUrl
    ).replace(/\/+$/, "");
    this.resourceUrl = options.resourceUrl ?? "";
    this.description =
      options.description ?? "Arx paid API: authorization decision service";
    this.maxTimeoutSeconds = options.maxTimeoutSeconds ?? 60;
    this.allowUnsettled = options.allowUnsettledPayments ?? false;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  get settlementMode(): X402SettlementMode {
    return this.facilitatorUrl.length > 0
      ? "FACILITATOR"
      : "LOCAL_VERIFICATION_ONLY";
  }

  /**
   * Fail-closed readiness. A gate that advertises a requirement it cannot
   * check is worse than an ungated route: the caller believes they paid.
   */
  isReady(): boolean {
    if (!this.enabled) {
      return false;
    }

    if (this.config === undefined || this.payTo.length === 0) {
      return false;
    }

    if (!this.config.exactEvm && this.settlementMode !== "FACILITATOR") {
      // Nothing local can verify this network's authorizations.
      return false;
    }

    if (
      this.settlementMode === "LOCAL_VERIFICATION_ONLY" &&
      !this.allowUnsettled
    ) {
      return false;
    }

    return true;
  }

  status(): X402GateStatus {
    const base = {
      enabled: this.enabled,
      ready: this.isReady(),
      network: this.networkName,
      payTo: this.payTo,
      settlementMode: this.settlementMode,
      allowUnsettledPayments: this.allowUnsettled,
      ...(this.config === undefined
        ? {}
        : {
            chainId: this.config.chainId,
            asset: this.config.asset,
            priceAtomic: this.safeAtomicPrice(),
          }),
    };

    return { ...base, detail: this.readinessDetail() };
  }

  readinessDetail(): string {
    if (!this.enabled) {
      return "Disabled (set X402_ENABLED=true)";
    }

    if (this.config === undefined) {
      return `Unknown X402_NETWORK "${this.networkName}"; known: ${Object.keys(
        X402_NETWORKS,
      ).join(", ")}`;
    }

    if (this.payTo.length === 0) {
      return "X402_PAY_TO is unset, so there is no payee to advertise";
    }

    if (!this.config.exactEvm && this.settlementMode !== "FACILITATOR") {
      return this.config.limitation ?? "Network needs a facilitator";
    }

    if (this.settlementMode === "FACILITATOR") {
      return `Facilitator settlement via ${this.facilitatorUrl}`;
    }

    if (!this.allowUnsettled) {
      return "No X402_FACILITATOR_URL: signatures can be verified locally but nothing can settle, so the gate denies. Pass allowUnsettledPayments to accept verified-but-unsettled authorizations.";
    }

    return "LOCAL_VERIFICATION_ONLY: EIP-712 signatures are really verified; NO on-chain settlement occurs";
  }

  /** The `accepts[]` entry this gate publishes. */
  paymentRequirements(resourceUrl?: string): PaymentRequirements | null {
    if (this.config === undefined || this.payTo.length === 0) {
      return null;
    }

    return {
      scheme: "exact",
      network: this.config.network,
      maxAmountRequired: this.safeAtomicPrice() ?? "0",
      asset: this.config.asset,
      payTo: this.payTo,
      resource: resourceUrl ?? this.resourceUrl,
      description: this.description,
      mimeType: "application/json",
      outputSchema: null,
      maxTimeoutSeconds: this.maxTimeoutSeconds,
      ...(this.config.eip712 === undefined
        ? {}
        : {
            extra: {
              name: this.config.eip712.name,
              version: this.config.eip712.version,
            },
          }),
    };
  }

  /**
   * Gates one request.
   *
   * `headers` is a plain lowercase-keyed map so this works under Fastify, a
   * bare `Request`, or a test harness without dragging a framework into the
   * integration layer.
   */
  async gate(input: {
    headers: Record<string, string | string[] | undefined>;
    resourceUrl?: string;
  }): Promise<X402GateResult> {
    if (!this.enabled) {
      return { outcome: "NOT_GATED", reason: "x402 gating is disabled" };
    }

    if (!this.isReady()) {
      // Not `NOT_GATED`: an enabled-but-misconfigured gate must not quietly
      // hand out the resource for free.
      return this.deny(
        `x402 gate is enabled but not usable: ${this.readinessDetail()}`,
        input.resourceUrl,
      );
    }

    const requirements = this.paymentRequirements(input.resourceUrl);

    if (requirements === null) {
      return this.deny("x402 requirements are not configured", input.resourceUrl);
    }

    const header = readHeader(input.headers);

    if (header === null) {
      return this.deny(
        `${X402_PAYMENT_HEADER} header is required`,
        input.resourceUrl,
      );
    }

    let decoded: unknown;

    try {
      decoded = decodeHeaderValue(header);
    } catch {
      return this.deny(
        "Payment header is not base64-encoded JSON",
        input.resourceUrl,
        X402_ERRORS.invalidPayload,
      );
    }

    const parsed = PaymentPayloadSchema.safeParse(decoded);

    if (!parsed.success) {
      return this.deny(
        "Payment payload does not match the x402 exact-scheme schema",
        input.resourceUrl,
        X402_ERRORS.invalidPayload,
      );
    }

    const payload = parsed.data;

    if (payload.network !== requirements.network) {
      return this.deny(
        `Payment is for network "${payload.network}" but this resource requires "${requirements.network}"`,
        input.resourceUrl,
        X402_ERRORS.invalidNetwork,
      );
    }

    if (payload.scheme !== requirements.scheme) {
      return this.deny(
        `Unsupported payment scheme "${payload.scheme}"`,
        input.resourceUrl,
        X402_ERRORS.invalidPayload,
      );
    }

    const structural = this.checkAuthorizationFields(payload, requirements);

    if (structural !== null) {
      return this.deny(structural.reason, input.resourceUrl, structural.code);
    }

    if (this.config?.exactEvm === true) {
      const signatureCheck = await this.verifySignature(payload);

      if (signatureCheck !== null) {
        return this.deny(
          signatureCheck,
          input.resourceUrl,
          X402_ERRORS.signature,
        );
      }
    }

    // Replay control before settlement, not after: two concurrent requests
    // presenting the same authorization must not both reach the facilitator.
    const authorization = payload.payload.authorization;
    const claim = claimOnce({
      key: `x402:nonce:${payload.network}:${authorization.nonce.toLowerCase()}`,
      source: "x402-gate",
      now: this.now(),
      ttlSeconds: Math.max(
        60,
        Number(authorization.validBefore) - this.now() + 60,
      ),
    });

    if (!claim.claimed) {
      return this.deny(
        "This payment authorization nonce has already been used",
        input.resourceUrl,
        X402_ERRORS.invalidPayload,
      );
    }

    if (this.settlementMode === "FACILITATOR") {
      return this.settleViaFacilitator(payload, requirements, input.resourceUrl);
    }

    const settlement: SettlementResponse & {
      settled: boolean;
      mode: X402SettlementMode;
    } = {
      success: true,
      transaction: "",
      network: payload.network,
      payer: authorization.from,
      settled: false,
      mode: "LOCAL_VERIFICATION_ONLY",
      errorReason:
        "NOT SETTLED: signature and terms verified locally; no facilitator configured, so no on-chain transfer was made",
    };

    return {
      outcome: "PAID",
      payer: authorization.from,
      settlement,
      responseHeaders: {
        [X402_PAYMENT_RESPONSE_HEADER]: encodeHeaderValue(settlement),
        // A plain-text marker too, because a base64 header is easy to skim past
        // and "this was not settled" must be impossible to miss.
        "x-arx-x402-settlement": "LOCAL_VERIFICATION_ONLY;settled=false",
      },
    };
  }

  private checkAuthorizationFields(
    payload: PaymentPayload,
    requirements: PaymentRequirements,
  ): { reason: string; code: string } | null {
    const authorization = payload.payload.authorization;

    if (
      authorization.to.toLowerCase() !== requirements.payTo.toLowerCase()
    ) {
      return {
        reason: `Authorization pays ${authorization.to}, not the required payee ${requirements.payTo}`,
        code: X402_ERRORS.recipientMismatch,
      };
    }

    if (BigInt(authorization.value) < BigInt(requirements.maxAmountRequired)) {
      return {
        reason: `Authorization value ${authorization.value} is below the required ${requirements.maxAmountRequired}`,
        code: X402_ERRORS.value,
      };
    }

    const now = this.now();

    if (Number(authorization.validAfter) > now) {
      return {
        reason: "Authorization is not valid yet",
        code: X402_ERRORS.validAfter,
      };
    }

    if (Number(authorization.validBefore) <= now) {
      return {
        reason: "Authorization has expired",
        code: X402_ERRORS.validBefore,
      };
    }

    return null;
  }

  /** Returns null when the signature is good, or the failure reason. */
  private async verifySignature(payload: PaymentPayload): Promise<string | null> {
    const config = this.config;

    if (config === undefined || config.eip712 === undefined) {
      return "No EIP-712 domain is known for this network";
    }

    const authorization = payload.payload.authorization;

    try {
      const valid = await verifyTypedData({
        address: authorization.from as `0x${string}`,
        domain: {
          name: config.eip712.name,
          version: config.eip712.version,
          chainId: config.chainId,
          verifyingContract: config.asset as `0x${string}`,
        },
        types: TRANSFER_WITH_AUTHORIZATION_TYPES,
        primaryType: "TransferWithAuthorization",
        message: {
          from: authorization.from as `0x${string}`,
          to: authorization.to as `0x${string}`,
          value: BigInt(authorization.value),
          validAfter: BigInt(authorization.validAfter),
          validBefore: BigInt(authorization.validBefore),
          nonce: authorization.nonce as `0x${string}`,
        },
        signature: payload.payload.signature as `0x${string}`,
      });

      return valid
        ? null
        : `Signature does not recover to the declared payer ${authorization.from}`;
    } catch (error) {
      return `Signature verification failed: ${
        error instanceof Error ? error.message : String(error)
      }`;
    }
  }

  private async settleViaFacilitator(
    payload: PaymentPayload,
    requirements: PaymentRequirements,
    resourceUrl: string | undefined,
  ): Promise<X402GateResult> {
    const body = {
      x402Version: X402_VERSION,
      paymentPayload: payload,
      paymentRequirements: requirements,
    };

    const verify = await requestJson<unknown>({
      url: `${this.facilitatorUrl}/verify`,
      method: "POST",
      body,
      timeoutMs: 6_000,
    });

    if (!verify.ok) {
      return this.deny(
        `Facilitator /verify unreachable: ${verify.failure.message}`,
        resourceUrl,
      );
    }

    const verifyParsed = FacilitatorVerifyResponseSchema.safeParse(verify.value);

    if (!verifyParsed.success) {
      return this.deny(
        "Facilitator /verify returned an unrecognized body",
        resourceUrl,
      );
    }

    if (!verifyParsed.data.isValid) {
      return this.deny(
        `Facilitator rejected the payment: ${
          verifyParsed.data.invalidReason ?? "no reason given"
        }`,
        resourceUrl,
        verifyParsed.data.invalidReason,
      );
    }

    const settle = await requestJson<unknown>({
      url: `${this.facilitatorUrl}/settle`,
      method: "POST",
      body,
      timeoutMs: 20_000,
    });

    if (!settle.ok) {
      return this.deny(
        `Facilitator /settle unreachable: ${settle.failure.message}`,
        resourceUrl,
      );
    }

    const settleParsed = FacilitatorSettleResponseSchema.safeParse(settle.value);

    if (!settleParsed.success || !settleParsed.data.success) {
      return this.deny(
        `Settlement failed: ${
          (settleParsed.success ? settleParsed.data.errorReason : undefined) ??
          "facilitator returned an unrecognized body"
        }`,
        resourceUrl,
      );
    }

    const authorization = payload.payload.authorization;
    const settlement: SettlementResponse & {
      settled: boolean;
      mode: X402SettlementMode;
    } = {
      success: true,
      transaction: settleParsed.data.transaction ?? "",
      network: settleParsed.data.network ?? payload.network,
      payer: settleParsed.data.payer ?? authorization.from,
      settled: (settleParsed.data.transaction ?? "").length > 0,
      mode: "FACILITATOR",
    };

    return {
      outcome: "PAID",
      payer: settlement.payer,
      settlement,
      responseHeaders: {
        [X402_PAYMENT_RESPONSE_HEADER]: encodeHeaderValue(settlement),
        "x-arx-x402-settlement": `FACILITATOR;settled=${settlement.settled}`,
      },
    };
  }

  private deny(
    error: string,
    resourceUrl: string | undefined,
    errorCode?: string,
  ): X402Denial {
    const requirements = this.paymentRequirements(resourceUrl);

    return {
      outcome: "PAYMENT_REQUIRED",
      status: 402,
      body: {
        x402Version: X402_VERSION,
        error,
        // An empty `accepts` is the fail-closed answer when the gate cannot
        // describe a payable requirement: the caller learns payment is
        // required and that no terms are on offer.
        accepts: requirements === null ? [] : [requirements],
      },
      ...(errorCode === undefined ? {} : { errorCode }),
    };
  }

  private safeAtomicPrice(): string | undefined {
    if (this.config === undefined) {
      return undefined;
    }

    try {
      return toAtomicAmount(this.priceUsdc, this.config.assetDecimals);
    } catch {
      return undefined;
    }
  }
}

function readHeader(
  headers: Record<string, string | string[] | undefined>,
): string | null {
  for (const name of [
    X402_PAYMENT_HEADER,
    X402_V2_PAYMENT_SIGNATURE_HEADER,
  ]) {
    const raw = headers[name] ?? headers[name.toUpperCase()];
    const value = Array.isArray(raw) ? raw[0] : raw;

    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }

  return null;
}
