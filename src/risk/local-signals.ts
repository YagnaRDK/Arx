import type { RiskSignal } from "../core/seams";
import type { Capability } from "../types/capability";
import { UINT256_MAX, flattenCall, type DecodedCall } from "../firewall/checks/decode-calldata";

/**
 * Risk signals computable from the transaction alone.
 *
 * No network, no cache, no external provider. That matters twice over: these
 * signals are the ones that still work when every integration is down, and they
 * are deterministic, so the same transaction always scores the same way and an
 * auditor can reproduce a decision from the log.
 *
 * Every signal is advisory. A signal can raise the score enough to force human
 * approval or to trip the capability's hard ceiling, but no signal — and no
 * absence of one — can clear a check that failed.
 */

export const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
export const DEAD_ADDRESS = "0x000000000000000000000000000000000000dead";

/**
 * Address-poisoning detection window, in hex characters.
 *
 * The attack works because wallet UIs abbreviate addresses to roughly the first
 * and last few characters, so an attacker grinds a vanity address sharing those
 * with a real counterparty and seeds it into the victim's history. Four
 * characters at each end is the abbreviation most interfaces show, and is the
 * threshold at which a match stops being coincidence: with 16 hex symbols, four
 * shared leading *and* four shared trailing characters is a 1-in-4-billion
 * accident, so a hit is evidence of grinding rather than of luck.
 */
export const POISON_PREFIX_CHARS = 4;
export const POISON_SUFFIX_CHARS = 4;

export const RISK_SIGNAL_WEIGHTS = {
  RECIPIENT_NOT_ON_ALLOWLIST: 25,
  ADDRESS_POISONING_LOOKALIKE: 55,
  UNLIMITED_TOKEN_APPROVAL: 45,
  APPROVAL_FAR_EXCEEDS_DECLARED: 30,
  VALUE_ABOVE_HISTORICAL_NORM: 20,
  CALLDATA_ON_DECLARED_TRANSFER: 35,
  CONTRACT_CREATION: 40,
  BURN_ADDRESS_RECIPIENT: 50,
  SELF_TRANSFER: 15,
  UNUSUAL_GAS_LIMIT: 10,
  UNUSUAL_FEE_PARAMETERS: 12,
  DECLARED_VALUE_DIVERGENCE: 45,
  UNDECODABLE_CALLDATA: 25,
  BATCH_WRAPPER: 15,
  OPAQUE_BATCH_WRAPPER: 35,
  PRICE_UNAVAILABLE: 20,
} as const;

export type LocalRiskSignalId = keyof typeof RISK_SIGNAL_WEIGHTS;

export type LocalSignalInput = {
  chainId: number;
  /** Absent means contract creation. */
  to?: string;
  valueWei: string;
  data: string;
  gasLimit: string;
  maxFeePerGas: string;
  maxPriorityFeePerGas: string;
  /** The signer's own address, when known, so a self-transfer is detectable. */
  from?: string;

  decodedCall: DecodedCall;
  capability: Capability;

  /** The agent's claim. Never used as truth, only compared against. */
  declaredValueUsd: number;
  /** Oracle-derived USD value, absent when no price could be obtained. */
  valueUsd?: number;
  /**
   * Why `valueUsd` is what it is.
   *
   * A zero from "this transaction moves nothing priceable" (an `approve`, a
   * zero-value contract call) must not be scored as an agent understating its
   * payment — that false positive would fire on every legitimate approval and
   * teach an operator to ignore the signal. Defaults are inferred from
   * `valueUsd` so an older caller still behaves sensibly.
   */
  pricingStatus?: "PRICED" | "NOTHING_TO_PRICE" | "UNPRICED";
  /** USD value of an allowance being granted, when priceable. */
  allowanceUsd?: number;
  /** The agent's declared action, e.g. "transfer". */
  action?: string;

  /** Mean prior transaction value for this capability, USD. */
  historicalMeanUsd?: number;
  historicalSampleCount?: number;
};

/** Actions an agent declares when it claims to be moving value and nothing else. */
const PLAIN_TRANSFER_ACTIONS = new Set([
  "transfer",
  "send",
  "payment",
  "pay",
  "native_transfer",
  "withdraw",
]);

const HEX_ADDRESS = /^0x[0-9a-f]{40}$/;

function isHexAddress(value: string): boolean {
  return HEX_ADDRESS.test(value.toLowerCase());
}

function sharedPrefixLength(a: string, b: string): number {
  let i = 0;

  while (i < a.length && i < b.length && a[i] === b[i]) {
    i += 1;
  }

  return i;
}

function sharedSuffixLength(a: string, b: string): number {
  let i = 0;

  while (
    i < a.length &&
    i < b.length &&
    a[a.length - 1 - i] === b[b.length - 1 - i]
  ) {
    i += 1;
  }

  return i;
}

export type LookalikeMatch = {
  candidate: string;
  lookalikeOf: string;
  sharedPrefixChars: number;
  sharedSuffixChars: number;
};

/**
 * Finds allowlisted addresses that `candidate` was probably ground to imitate.
 *
 * Only hex addresses are compared. An ENS name on the allowlist has no hex body
 * to look like, and comparing against its resolved address is the name
 * resolver's job.
 */
export function findLookalike(
  candidate: string,
  allowlist: readonly string[],
): LookalikeMatch | undefined {
  const lowered = candidate.toLowerCase();

  if (!isHexAddress(lowered)) {
    return undefined;
  }

  // Strip `0x` so the shared prefix is real address entropy rather than the two
  // characters every address begins with.
  const candidateBody = lowered.slice(2);
  let best: LookalikeMatch | undefined;

  for (const entry of allowlist) {
    const known = entry.toLowerCase();

    if (!isHexAddress(known) || known === lowered) {
      continue;
    }

    const knownBody = known.slice(2);
    const prefix = sharedPrefixLength(candidateBody, knownBody);
    const suffix = sharedSuffixLength(candidateBody, knownBody);

    if (prefix < POISON_PREFIX_CHARS && suffix < POISON_SUFFIX_CHARS) {
      continue;
    }

    // Either end alone is weak evidence; both ends together is the signature of
    // the attack, so require one end at the threshold and the other non-trivial.
    const strongEnough =
      (prefix >= POISON_PREFIX_CHARS && suffix >= POISON_SUFFIX_CHARS) ||
      prefix >= POISON_PREFIX_CHARS + 4 ||
      suffix >= POISON_SUFFIX_CHARS + 4;

    if (!strongEnough) {
      continue;
    }

    const match: LookalikeMatch = {
      candidate: lowered,
      lookalikeOf: known,
      sharedPrefixChars: prefix,
      sharedSuffixChars: suffix,
    };

    if (
      !best ||
      match.sharedPrefixChars + match.sharedSuffixChars >
        best.sharedPrefixChars + best.sharedSuffixChars
    ) {
      best = match;
    }
  }

  return best;
}

function signal(
  id: LocalRiskSignalId,
  explanation: string,
  evidence?: Record<string, unknown>,
  weightOverride?: number,
): RiskSignal {
  return {
    id,
    weight: weightOverride ?? RISK_SIGNAL_WEIGHTS[id],
    explanation,
    ...(evidence === undefined ? {} : { evidence }),
  };
}

function safeBigInt(value: string): bigint {
  try {
    return BigInt(value);
  } catch {
    return 0n;
  }
}

/**
 * Allowance values at or above this are treated as unlimited in practice.
 *
 * `2^256-1` is the canonical infinite approval, but `2^128` of any real token is
 * already more than the total supply of anything that exists, so grinding a
 * slightly smaller constant must not evade the signal.
 */
const EFFECTIVELY_UNLIMITED = 2n ** 128n;

export function computeLocalSignals(input: LocalSignalInput): RiskSignal[] {
  const signals: RiskSignal[] = [];

  const allowlist = input.capability.recipients.allow;
  const denylist = new Set(
    input.capability.recipients.deny.map((entry) => entry.toLowerCase()),
  );
  const allowSet = new Set(allowlist.map((entry) => entry.toLowerCase()));

  const calls = flattenCall(input.decodedCall);

  // Everyone this transaction actually hands value or authority to, drawn from
  // the calldata rather than from the intent.
  const recipients = new Set<string>();

  for (const call of calls) {
    for (const recipient of call.recipients) {
      recipients.add(recipient.toLowerCase());
    }
  }

  if (input.to !== undefined && input.decodedCall.kind === "NATIVE_TRANSFER") {
    recipients.add(input.to.toLowerCase());
  }

  // --- Counterparty -------------------------------------------------------

  const unknownRecipients = [...recipients].filter(
    (recipient) => !allowSet.has(recipient),
  );

  if (unknownRecipients.length > 0) {
    signals.push(
      signal(
        "RECIPIENT_NOT_ON_ALLOWLIST",
        `${unknownRecipients.length} recipient(s) are not on this capability's allowlist`,
        { recipients: unknownRecipients },
      ),
    );
  }

  for (const recipient of recipients) {
    const lookalike = findLookalike(recipient, allowlist);

    if (lookalike) {
      signals.push(
        signal(
          "ADDRESS_POISONING_LOOKALIKE",
          `Recipient ${lookalike.candidate} shares its first ${lookalike.sharedPrefixChars} and last ${lookalike.sharedSuffixChars} characters with the allowlisted address ${lookalike.lookalikeOf} but is a different address — the signature of an address-poisoning substitution`,
          { ...lookalike },
          // A longer shared run is stronger evidence of a ground vanity address.
          Math.min(
            85,
            RISK_SIGNAL_WEIGHTS.ADDRESS_POISONING_LOOKALIKE +
              2 *
                Math.max(
                  0,
                  lookalike.sharedPrefixChars +
                    lookalike.sharedSuffixChars -
                    (POISON_PREFIX_CHARS + POISON_SUFFIX_CHARS),
                ),
          ),
        ),
      );
    }
  }

  const burnRecipients = [...recipients].filter(
    (recipient) => recipient === ZERO_ADDRESS || recipient === DEAD_ADDRESS,
  );

  if (burnRecipients.length > 0 && !denylist.has(ZERO_ADDRESS)) {
    signals.push(
      signal(
        "BURN_ADDRESS_RECIPIENT",
        "Transaction sends value or authority to a burn address, which destroys it irrecoverably",
        { recipients: burnRecipients },
      ),
    );
  }

  if (input.from) {
    const from = input.from.toLowerCase();

    if (recipients.has(from)) {
      signals.push(
        signal(
          "SELF_TRANSFER",
          "The signer is also the recipient; the transaction moves nothing but still spends fees",
          { address: from },
        ),
      );
    }
  }

  // --- Calldata shape -----------------------------------------------------

  if (input.decodedCall.kind === "CONTRACT_CREATION") {
    signals.push(
      signal(
        "CONTRACT_CREATION",
        "Transaction deploys new code rather than calling an existing contract",
        { dataBytes: Math.max(0, (input.data.length - 2) / 2) },
      ),
    );
  }

  const declaredPlainTransfer =
    input.action !== undefined &&
    PLAIN_TRANSFER_ACTIONS.has(input.action.toLowerCase());

  if (
    declaredPlainTransfer &&
    input.data !== "0x" &&
    input.data.length > 2 &&
    input.decodedCall.kind !== "ERC20_TRANSFER"
  ) {
    signals.push(
      signal(
        "CALLDATA_ON_DECLARED_TRANSFER",
        `Action was declared as "${input.action}" but the transaction carries ${
          (input.data.length - 2) / 2
        } bytes of calldata, so it executes contract logic the declaration does not describe`,
        { action: input.action, selector: input.decodedCall.selector },
      ),
    );
  }

  for (const call of calls) {
    if (call.kind === "BATCH") {
      signals.push(
        signal(
          call.decoded ? "BATCH_WRAPPER" : "OPAQUE_BATCH_WRAPPER",
          call.decoded
            ? `Call is a ${call.signature} batch containing ${call.inner?.length ?? 0} inner call(s)`
            : `Call is a ${call.signature} batch whose contents Arx could not enumerate: ${call.note ?? "unknown reason"}`,
          { signature: call.signature, innerCount: call.inner?.length ?? 0 },
        ),
      );
    }
  }

  if (!input.decodedCall.decoded && input.decodedCall.kind !== "BATCH") {
    signals.push(
      signal(
        "UNDECODABLE_CALLDATA",
        `Arx could not decode the calldata: ${input.decodedCall.note ?? "unknown selector"}`,
        { selector: input.decodedCall.selector },
      ),
    );
  }

  // --- Allowances ---------------------------------------------------------

  for (const call of calls) {
    if (call.allowance === undefined) {
      continue;
    }

    const allowance = safeBigInt(call.allowance);

    if (allowance >= EFFECTIVELY_UNLIMITED) {
      signals.push(
        signal(
          "UNLIMITED_TOKEN_APPROVAL",
          allowance === UINT256_MAX
            ? `${call.signature ?? "Approval"} grants ${call.spender ?? "a spender"} an unlimited (2^256-1) allowance, which survives this transaction indefinitely`
            : `${call.signature ?? "Approval"} grants ${call.spender ?? "a spender"} an allowance of ${call.allowance}, beyond any real token supply`,
          {
            spender: call.spender,
            allowance: call.allowance,
            token: call.target,
          },
        ),
      );

      continue;
    }

    if (
      input.allowanceUsd !== undefined &&
      input.declaredValueUsd > 0 &&
      input.allowanceUsd > input.declaredValueUsd * 10
    ) {
      signals.push(
        signal(
          "APPROVAL_FAR_EXCEEDS_DECLARED",
          `Approval is worth about $${input.allowanceUsd.toFixed(2)} against a declared action value of $${input.declaredValueUsd.toFixed(2)}`,
          {
            allowanceUsd: input.allowanceUsd,
            declaredValueUsd: input.declaredValueUsd,
            spender: call.spender,
          },
        ),
      );
    }
  }

  // --- Value ---------------------------------------------------------------

  const pricingStatus =
    input.pricingStatus ??
    (input.valueUsd === undefined ? "UNPRICED" : "PRICED");

  if (pricingStatus === "UNPRICED") {
    signals.push(
      signal(
        "PRICE_UNAVAILABLE",
        "No usable price quote, so the transaction's real USD value is unknown and the USD ceilings could not be applied",
      ),
    );
  } else if (
    pricingStatus === "PRICED" &&
    input.valueUsd !== undefined &&
    input.declaredValueUsd > 0
  ) {
    const divergenceBps = Math.round(
      (Math.abs(input.valueUsd - input.declaredValueUsd) /
        input.declaredValueUsd) *
        10_000,
    );

    if (divergenceBps > input.capability.valueToleranceBps) {
      signals.push(
        signal(
          "DECLARED_VALUE_DIVERGENCE",
          `Agent declared $${input.declaredValueUsd} but the transaction actually moves about $${input.valueUsd.toFixed(2)} (${divergenceBps}bps divergence, tolerance ${input.capability.valueToleranceBps}bps)`,
          {
            declaredValueUsd: input.declaredValueUsd,
            valueUsd: input.valueUsd,
            divergenceBps,
            toleranceBps: input.capability.valueToleranceBps,
          },
        ),
      );
    }
  }

  if (
    pricingStatus === "PRICED" &&
    input.valueUsd !== undefined &&
    input.historicalMeanUsd !== undefined &&
    input.historicalMeanUsd > 0 &&
    (input.historicalSampleCount ?? 0) >= 3 &&
    input.valueUsd > input.historicalMeanUsd * 5
  ) {
    signals.push(
      signal(
        "VALUE_ABOVE_HISTORICAL_NORM",
        `Value of $${input.valueUsd.toFixed(2)} is ${(input.valueUsd / input.historicalMeanUsd).toFixed(1)}x this capability's historical mean of $${input.historicalMeanUsd.toFixed(2)}`,
        {
          valueUsd: input.valueUsd,
          historicalMeanUsd: input.historicalMeanUsd,
          samples: input.historicalSampleCount,
        },
      ),
    );
  }

  // --- Gas and fees --------------------------------------------------------

  const gasLimit = safeBigInt(input.gasLimit);
  const maxFee = safeBigInt(input.maxFeePerGas);
  const priorityFee = safeBigInt(input.maxPriorityFeePerGas);
  const maxGasLimit = safeBigInt(input.capability.limits.maxGasLimit);

  if (input.decodedCall.kind === "NATIVE_TRANSFER" && gasLimit > 50_000n) {
    signals.push(
      signal(
        "UNUSUAL_GAS_LIMIT",
        `A plain native transfer needs 21,000 gas but ${gasLimit} was requested, which suggests the recipient runs code on receipt`,
        { gasLimit: gasLimit.toString() },
      ),
    );
  } else if (maxGasLimit > 0n && gasLimit * 2n > maxGasLimit * 3n) {
    signals.push(
      signal(
        "UNUSUAL_GAS_LIMIT",
        `Requested gas limit ${gasLimit} is close to or above this capability's ceiling of ${maxGasLimit}`,
        { gasLimit: gasLimit.toString(), maxGasLimit: maxGasLimit.toString() },
      ),
    );
  }

  // A tip at more than half the total fee cap is not normal market behaviour;
  // it is what a transaction looks like when someone is paying for immediate
  // inclusion, e.g. racing a revocation.
  if (priorityFee > 0n && maxFee > 0n && priorityFee * 2n > maxFee) {
    signals.push(
      signal(
        "UNUSUAL_FEE_PARAMETERS",
        `Priority fee ${priorityFee} wei is more than half of the ${maxFee} wei fee cap, an unusually aggressive bid for inclusion`,
        {
          maxPriorityFeePerGas: priorityFee.toString(),
          maxFeePerGas: maxFee.toString(),
        },
      ),
    );
  } else if (maxFee === 0n && safeBigInt(input.valueWei) > 0n) {
    signals.push(
      signal(
        "UNUSUAL_FEE_PARAMETERS",
        "Fee cap is zero on a value-bearing transaction, which is not a transaction a validator would include as written",
        { maxFeePerGas: "0" },
      ),
    );
  }

  return signals;
}
