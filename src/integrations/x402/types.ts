/**
 * x402 wire types, transcribed from the specification rather than inferred.
 *
 * Sources (fetched 2026-09-12):
 *   - core types, `PaymentRequirementsResponse`, `PaymentPayload`,
 *     `SettlementResponse`, the `exact` scheme's EIP-3009 typed-data
 *     definition, and the facilitator `/verify` + `/settle` shapes:
 *     https://github.com/coinbase/x402/blob/main/specs/x402-specification-v1.md
 *   - HTTP transport binding — `X-PAYMENT` request header and
 *     `X-PAYMENT-RESPONSE` response header, both base64-encoded JSON, with the
 *     402 body carried as JSON:
 *     https://github.com/coinbase/x402/blob/main/specs/transports-v1/http.md
 *   - v2 renames the transport headers to `PAYMENT-REQUIRED` /
 *     `PAYMENT-SIGNATURE` / `PAYMENT-RESPONSE` and moves the requirements into
 *     a base64 header; Arx speaks v1 on the wire (still what deployed clients
 *     send) and additionally accepts the v2 request header name:
 *     https://github.com/coinbase/x402/blob/main/specs/x402-specification-v2.md
 *     https://docs.x402.org/core-concepts/http-402
 *
 * Field names below are the spec's, verbatim. Renaming any of them silently
 * breaks interoperability with every other x402 implementation.
 */

import { z } from "zod";

/** v1 HTTP transport: client -> server, base64 JSON `PaymentPayload`. */
export const X402_PAYMENT_HEADER = "x-payment";
/** v1 HTTP transport: server -> client, base64 JSON `SettlementResponse`. */
export const X402_PAYMENT_RESPONSE_HEADER = "x-payment-response";
/** v2 transport name for the same client -> server payload. Accepted on input. */
export const X402_V2_PAYMENT_SIGNATURE_HEADER = "payment-signature";

export const X402_VERSION = 1;

const HexAddress = z.string().regex(/^0x[a-fA-F0-9]{40}$/);
const UintString = z.string().regex(/^\d+$/);

export const PaymentRequirementsSchema = z.object({
  scheme: z.string().min(1),
  network: z.string().min(1),
  maxAmountRequired: UintString,
  asset: z.string().min(1),
  payTo: z.string().min(1),
  resource: z.string().min(1),
  description: z.string(),
  mimeType: z.string().optional(),
  outputSchema: z.unknown().nullable().optional(),
  maxTimeoutSeconds: z.number().int().positive(),
  extra: z.record(z.string(), z.unknown()).optional(),
});

export type PaymentRequirements = z.infer<typeof PaymentRequirementsSchema>;

export const PaymentRequirementsResponseSchema = z.object({
  x402Version: z.number().int(),
  error: z.string(),
  accepts: z.array(PaymentRequirementsSchema),
});

export type PaymentRequirementsResponse = z.infer<
  typeof PaymentRequirementsResponseSchema
>;

/** EIP-3009 `TransferWithAuthorization` parameters. */
export const ExactEvmAuthorizationSchema = z.object({
  from: HexAddress,
  to: HexAddress,
  value: UintString,
  validAfter: UintString,
  validBefore: UintString,
  nonce: z.string().regex(/^0x[a-fA-F0-9]{64}$/),
});

export type ExactEvmAuthorization = z.infer<typeof ExactEvmAuthorizationSchema>;

export const ExactEvmPayloadSchema = z.object({
  signature: z.string().regex(/^0x[a-fA-F0-9]+$/),
  authorization: ExactEvmAuthorizationSchema,
});

export const PaymentPayloadSchema = z.object({
  x402Version: z.number().int(),
  scheme: z.string().min(1),
  network: z.string().min(1),
  payload: ExactEvmPayloadSchema,
});

export type PaymentPayload = z.infer<typeof PaymentPayloadSchema>;

export const SettlementResponseSchema = z.object({
  success: z.boolean(),
  errorReason: z.string().optional(),
  transaction: z.string(),
  network: z.string(),
  payer: z.string(),
});

export type SettlementResponse = z.infer<typeof SettlementResponseSchema>;

export const FacilitatorVerifyResponseSchema = z.object({
  isValid: z.boolean(),
  invalidReason: z.string().optional(),
  payer: z.string().optional(),
});

export const FacilitatorSettleResponseSchema = z.object({
  success: z.boolean(),
  errorReason: z.string().optional(),
  transaction: z.string().optional(),
  network: z.string().optional(),
  payer: z.string().optional(),
});

/**
 * The EIP-712 type definition the `exact` EVM scheme signs. Copied verbatim
 * from spec section 6.1.1 — a single renamed or reordered member changes the
 * type hash and every signature verification fails.
 */
export const TRANSFER_WITH_AUTHORIZATION_TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

/** Spec error codes, used verbatim so clients can branch on them. */
export const X402_ERRORS = {
  insufficientFunds: "insufficient_funds",
  validAfter: "invalid_exact_evm_payload_authorization_valid_after",
  validBefore: "invalid_exact_evm_payload_authorization_valid_before",
  value: "invalid_exact_evm_payload_authorization_value",
  signature: "invalid_exact_evm_payload_signature",
  recipientMismatch: "invalid_exact_evm_payload_recipient_mismatch",
  invalidNetwork: "invalid_network",
  invalidPayload: "invalid_payload",
  invalidPaymentRequirements: "invalid_payment_requirements",
} as const;

export function encodeHeaderValue(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64");
}

export function decodeHeaderValue(header: string): unknown {
  return JSON.parse(Buffer.from(header, "base64").toString("utf8"));
}
