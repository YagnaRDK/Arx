import type { DecisionCode } from "../core/codes";
import type { PriceQuote, RiskSignal } from "../core/seams";
import type { Capability } from "../types/capability";
import type { EvaluationResult } from "../types/evaluation";
import type { Intent } from "../types/intent";
import type {
  EvmTransaction,
  NormalizedTransaction,
} from "../types/transaction";
import type { DecodedCall } from "./checks/decode-calldata";

/**
 * How much a finding matters.
 *
 * `BLOCK` is a rejection no amount of human enthusiasm changes at this layer.
 * `ESCALATE` says the action is inside the agent's authority only with a person
 * at the device. `INFO` is recorded for the audit trail and influences nothing.
 *
 * The orchestrator resolves severities in that order, always: a BLOCK finding
 * wins over every ESCALATE finding, so a low risk score can never rescue a
 * failed policy check.
 */
export type FirewallSeverity = "BLOCK" | "ESCALATE" | "INFO";

export type FirewallFinding = {
  /** The narrowest code that describes this specific problem. */
  code: DecisionCode;
  severity: FirewallSeverity;
  message: string;
  evidence?: unknown;
};

export type FirewallDecision = {
  allowed: boolean;
  decision: "ALLOW" | "DENY" | "ESCALATE";
  /** Kept for compatibility with callers written against the v0.4 firewall. */
  result: EvaluationResult;
  /** Present only when the transaction may proceed to approval. */
  transaction?: NormalizedTransaction;
  findings: FirewallFinding[];
  riskScore: number;
  riskSignals: RiskSignal[];
  /** Oracle-derived USD value of what the bytes actually move. Not a claim. */
  valueUsd: number;
  /** What the agent said it was worth. */
  declaredValueUsd: number;
  /** Whether `valueUsd` was actually established, or is an unpriced zero. */
  valuePriced: boolean;
  priceQuotes: PriceQuote[];
  decodedCall?: DecodedCall;
};

/** Everything the synchronous checks read. Assembled once per transaction. */
export type CheckContext = {
  transaction: NormalizedTransaction;
  /** Shorthand for `transaction.transaction`. */
  tx: EvmTransaction;
  capability: Capability;
  intent: Intent;
  decodedCall: DecodedCall;
  /** Injected, never read from the clock inside a check. */
  now: number;
};

export type Check = (context: CheckContext) => FirewallFinding[];

export function block(
  code: DecisionCode,
  message: string,
  evidence?: unknown,
): FirewallFinding {
  return {
    code,
    severity: "BLOCK",
    message,
    ...(evidence === undefined ? {} : { evidence }),
  };
}

export function escalateFinding(
  code: DecisionCode,
  message: string,
  evidence?: unknown,
): FirewallFinding {
  return {
    code,
    severity: "ESCALATE",
    message,
    ...(evidence === undefined ? {} : { evidence }),
  };
}

export function info(
  code: DecisionCode,
  message: string,
  evidence?: unknown,
): FirewallFinding {
  return {
    code,
    severity: "INFO",
    message,
    ...(evidence === undefined ? {} : { evidence }),
  };
}

export function firstBlocking(
  findings: readonly FirewallFinding[],
): FirewallFinding | undefined {
  return findings.find((finding) => finding.severity === "BLOCK");
}

export function firstEscalation(
  findings: readonly FirewallFinding[],
): FirewallFinding | undefined {
  return findings.find((finding) => finding.severity === "ESCALATE");
}

/**
 * Whether this transaction moves native value.
 *
 * Used to decide whether the *recipient* policy applies to `to` (a payment) or
 * the *contract* policy does (a call). A transaction can be both, and when it is
 * both policies apply.
 */
export function movesNativeValue(tx: EvmTransaction): boolean {
  try {
    return BigInt(tx.value) > 0n;
  } catch {
    return false;
  }
}

export function isContractCall(tx: EvmTransaction): boolean {
  return tx.to !== undefined && tx.data !== "0x" && tx.data.length > 2;
}

export type { DecodedCall };
