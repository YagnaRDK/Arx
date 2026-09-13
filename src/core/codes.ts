/**
 * The single registry of machine-readable decision codes.
 *
 * Every rejection Arx emits names the specific security reason it was rejected
 * for. Vague errors are a liability in an authorization layer: an operator
 * reading an audit log needs to know whether a transaction was blocked because
 * a capability expired or because the recipient was not on the allowlist.
 */

export const DECISION_CODES = [
  // Success
  "POLICY_APPROVED",
  "HUMAN_APPROVAL_REQUIRED",

  // Capability lifecycle
  "CAPABILITY_NOT_FOUND",
  "CAPABILITY_ID_MISMATCH",
  "CAPABILITY_EXPIRED",
  "CAPABILITY_NOT_YET_VALID",
  "CAPABILITY_REVOKED",
  "CAPABILITY_CONSUMED",
  "CAPABILITY_INACTIVE",

  // Scope
  "AGENT_MISMATCH",
  "ACTION_NOT_ALLOWED",
  "PROTOCOL_NOT_ALLOWED",
  "CHAIN_NOT_ALLOWED",
  "INPUT_TOKEN_NOT_ALLOWED",
  "OUTPUT_TOKEN_NOT_ALLOWED",
  "AMOUNT_EXCEEDED",
  "SLIPPAGE_EXCEEDED",

  // Replay / idempotency
  "INVALID_NONCE",
  "NONCE_REUSED",
  "REPLAY_DETECTED",
  "INTENT_ID_CONFLICT",
  "INTENT_EXPIRED",
  "INTENT_TIMESTAMP_SKEWED",

  // Spend accounting
  "SPEND_WINDOW_EXCEEDED",
  "TX_COUNT_WINDOW_EXCEEDED",

  // Transaction firewall
  "INVALID_INTENT",
  "INVALID_TRANSACTION",
  "TRANSACTION_NOT_ALLOWED",
  "TRANSACTION_CHAIN_MISMATCH",
  "RECIPIENT_NOT_ALLOWED",
  "RECIPIENT_DENIED",
  "CONTRACT_NOT_ALLOWED",
  "METHOD_NOT_ALLOWED",
  "CALLDATA_NOT_ALLOWED",
  "CALLDATA_RECIPIENT_NOT_ALLOWED",
  "VALUE_LIMIT_EXCEEDED",
  "GAS_LIMIT_EXCEEDED",
  "FEE_LIMIT_EXCEEDED",
  "VALUE_DECLARATION_MISMATCH",
  "CONTRACT_CREATION_NOT_ALLOWED",
  "UNLIMITED_APPROVAL_BLOCKED",
  "ADDRESS_POISONING_SUSPECTED",
  "SELF_TRANSFER_BLOCKED",
  "BURN_ADDRESS_BLOCKED",
  "RISK_SCORE_EXCEEDED",
  "PRICE_UNAVAILABLE",
  "PRICE_STALE",

  // Approval lifecycle
  "APPROVAL_NOT_FOUND",
  "APPROVAL_INVALID",
  "APPROVAL_EXPIRED",
  "APPROVAL_ALREADY_CONSUMED",
  "APPROVAL_REJECTED",
  "APPROVAL_PENDING_HUMAN",
  "APPROVAL_STATE_CONFLICT",
  "APPROVAL_SIGNATURE_INVALID",
  "TRANSACTION_HASH_MISMATCH",

  // Identity / transport
  "UNAUTHENTICATED",
  "FORBIDDEN",
  "AGENT_NOT_FOUND",
  "AGENT_DISABLED",
  "SIGNATURE_INVALID",
  "TIMESTAMP_SKEWED",
  "RATE_LIMITED",

  // Signer boundary
  "SIGNER_UNAVAILABLE",
  "SIGNER_REJECTED_BY_USER",
  "SIGNING_FAILED",
  "SIGNATURE_VERIFICATION_FAILED",
  "SIGNER_ADDRESS_MISMATCH",

  // Internal
  "INTERNAL_ERROR",
] as const;

export type DecisionCode = (typeof DECISION_CODES)[number];

const DECISION_CODE_SET = new Set<string>(DECISION_CODES);

export function isDecisionCode(value: string): value is DecisionCode {
  return DECISION_CODE_SET.has(value);
}

/** Maps a decision code onto the HTTP status that best describes it. */
export function httpStatusForCode(code: DecisionCode): number {
  switch (code) {
    case "POLICY_APPROVED":
      return 200;

    case "HUMAN_APPROVAL_REQUIRED":
    case "APPROVAL_PENDING_HUMAN":
      return 202;

    case "INVALID_INTENT":
    case "INVALID_TRANSACTION":
      return 400;

    case "UNAUTHENTICATED":
    case "SIGNATURE_INVALID":
    case "TIMESTAMP_SKEWED":
      return 401;

    case "CAPABILITY_NOT_FOUND":
    case "APPROVAL_NOT_FOUND":
    case "AGENT_NOT_FOUND":
      return 404;

    case "INTENT_ID_CONFLICT":
    case "APPROVAL_ALREADY_CONSUMED":
    case "APPROVAL_STATE_CONFLICT":
    case "NONCE_REUSED":
    case "REPLAY_DETECTED":
      return 409;

    case "RATE_LIMITED":
      return 429;

    case "SIGNER_UNAVAILABLE":
      return 503;

    case "SIGNING_FAILED":
    case "SIGNATURE_VERIFICATION_FAILED":
    case "INTERNAL_ERROR":
      return 500;

    default:
      // Every remaining code is an authorization denial.
      return 403;
  }
}
