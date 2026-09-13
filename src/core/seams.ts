/**
 * The extension points third-party integrations plug into.
 *
 * Each seam is a narrow interface the authorization pipeline depends on, so an
 * adapter can be swapped — Chainlink for a static price table, a Ledger device
 * for an emulator — without the policy layer changing shape.
 *
 * Every seam distinguishes "checked, and here is the answer" from "could not
 * check". That distinction is the whole point: an adapter that returns a clean
 * result when its data source was unreachable turns a dependency outage into a
 * silent authorization bypass. The `unavailable` variant forces the caller to
 * decide what an unknown means, and in Arx an unknown never means "permit".
 */

export type Availability<T> =
  | { status: "OK"; value: T }
  | { status: "UNAVAILABLE"; reason: string; retryable: boolean };

export function ok<T>(value: T): Availability<T> {
  return { status: "OK", value };
}

export function unavailable<T>(
  reason: string,
  retryable = true,
): Availability<T> {
  return { status: "UNAVAILABLE", reason, retryable };
}

// --- Price truth -----------------------------------------------------------

export type PriceQuote = {
  /** The asset priced, e.g. "ETH" or a token contract address. */
  asset: string;
  /** USD price per whole unit. */
  priceUsd: number;
  /** Where this came from, surfaced in API responses and the audit log. */
  source: string;
  /** Unix seconds. A quote older than the caller's bound is not usable. */
  updatedAt: number;
};

export interface PriceOracle {
  readonly name: string;
  /** Whether this oracle is configured enough to be asked. */
  isReady(): boolean;
  getUsdPrice(asset: string, chainId: number): Promise<Availability<PriceQuote>>;
}

// --- Identity --------------------------------------------------------------

export type ResolvedName = {
  name: string;
  address: string;
  /** Which resolver answered, e.g. "ens:sepolia". */
  source: string;
  resolvedAt: number;
};

export interface NameResolver {
  readonly name: string;
  isReady(): boolean;
  /** name -> address. */
  resolve(name: string, chainId: number): Promise<Availability<ResolvedName>>;
  /** address -> primary name, for display and clear signing. */
  reverse(
    address: string,
    chainId: number,
  ): Promise<Availability<ResolvedName>>;
}

// --- Reputation ------------------------------------------------------------

export type RiskSignal = {
  /** Stable identifier, e.g. "RECIPIENT_FIRST_SEEN_RECENTLY". */
  id: string;
  /** Points contributed to the score, 0-100. */
  weight: number;
  /** Operator-facing explanation. Always shown next to the score. */
  explanation: string;
  /** Supporting data, for the dashboard and audit record. */
  evidence?: Record<string, unknown>;
};

export type AddressProfile = {
  address: string;
  chainId: number;
  isContract?: boolean;
  firstSeenAt?: number;
  transactionCount?: number;
  uniqueCounterparties?: number;
  labels?: string[];
  source: string;
};

export interface RiskSignalProvider {
  readonly name: string;
  isReady(): boolean;
  /**
   * Signals about a proposed transaction's counterparty. An empty array means
   * "checked, nothing found"; `UNAVAILABLE` means "could not check" — the
   * caller must not treat the two alike.
   */
  signalsFor(input: {
    address: string;
    chainId: number;
    valueWei: string;
    selector?: string;
  }): Promise<Availability<{ signals: RiskSignal[]; profile?: AddressProfile }>>;
}

// --- Human verification ----------------------------------------------------

export type HumanVerification = {
  /** Which factor was satisfied, e.g. "world-selfie-check". */
  factor: string;
  /** Opaque subject identifier. Never a raw biometric or personal detail. */
  subject: string;
  verifiedAt: number;
  evidence?: Record<string, unknown>;
};

export interface HumanVerifier {
  readonly name: string;
  isReady(): boolean;
  /** Verifies a proof produced by a person, out of band from the agent. */
  verify(proof: unknown): Promise<Availability<HumanVerification>>;
}

// --- Execution venues ------------------------------------------------------

export type ExecutionQuote = {
  venue: string;
  chainId: number;
  /** The contract the resulting transaction would call. */
  to: string;
  /** Calldata the venue would have Arx authorize. */
  data: string;
  value: string;
  estimatedOutput?: string;
  priceImpactBps?: number;
  source: string;
};

export interface ExecutionVenue {
  readonly name: string;
  isReady(): boolean;
  quote(input: {
    chainId: number;
    inputToken: string;
    outputToken: string;
    amount: string;
    recipient: string;
    slippageBps: number;
  }): Promise<Availability<ExecutionQuote>>;
}
