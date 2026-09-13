import type { PriceOracle, PriceQuote } from "../../core/seams";
import {
  baseUnitsToUsd,
  describeNativeAsset,
  describeToken,
  type AssetDescriptor,
} from "../../oracle/assets";
import { priceDecisionCode } from "../../oracle/price-oracle";
import {
  block,
  escalateFinding,
  info,
  type CheckContext,
  type FirewallFinding,
} from "../types";
import { flattenCall } from "./decode-calldata";

/**
 * Value binding: the agent's claim against the bytes.
 *
 * `intent.amountUsd` is an assertion made by the same process an attacker may
 * already control. Without this check, "move 1000 ETH but declare it as $1"
 * passes every USD ceiling in the system, because every USD ceiling was
 * comparing against the declaration rather than against the transaction.
 *
 * So the USD figure used for limits comes from the oracle applied to the value
 * actually encoded, the declaration is compared against it, and a divergence
 * beyond `valueToleranceBps` is treated as what it is: a false statement about
 * a payment.
 *
 * When no price can be obtained, this check does not fall silent — it escalates.
 * The wei ceilings in `limits.ts` still apply, so an unpriced transfer is
 * bounded even though it is unvalued, but it never proceeds autonomously.
 */

export type ValueComponent = {
  kind: "NATIVE" | "ERC20";
  asset: AssetDescriptor;
  /** Base-unit amount, decimal string. */
  amount: string;
  /** Token contract, for an ERC-20 component. */
  token?: string;
};

export type ValueBindingResult = {
  findings: FirewallFinding[];
  /** Oracle-derived USD value of everything this transaction moves. */
  valueUsd: number;
  /** False when the figure above is an unpriced zero rather than a measurement. */
  valuePriced: boolean;
  /**
   * Why `valueUsd` is what it is. `NOTHING_TO_PRICE` and `UNPRICED` both yield
   * zero and must not be confused: the first means the transaction genuinely
   * moves nothing priceable, the second means Arx could not find out.
   */
  pricingStatus: "PRICED" | "NOTHING_TO_PRICE" | "UNPRICED";
  priceQuotes: PriceQuote[];
  /** USD value of the largest allowance granted, when priceable. */
  allowanceUsd?: number;
  components: ValueComponent[];
};

export type ValueExtraction = {
  components: ValueComponent[];
  /** Assets whose amount is known but whose price Arx has no verified source for. */
  unpriceableTokens: string[];
  /** The largest priceable allowance the transaction grants, if any. */
  largestAllowance?: { amount: bigint; asset: AssetDescriptor };
};

/**
 * Pulls every priceable amount out of the transaction. No network, no oracle.
 *
 * Separated from the pricing step so the synchronous firewall path can reach
 * exactly the same conclusions about *what* is being moved even when it cannot
 * find out what it is worth.
 */
export function extractValueComponents(
  context: CheckContext,
): ValueExtraction {
  const { tx, decodedCall } = context;
  const components: ValueComponent[] = [];
  const unpriceableTokens: string[] = [];

  const nativeValue = toBigInt(tx.value) ?? 0n;

  if (nativeValue > 0n) {
    const native = describeNativeAsset(tx.chainId);

    if (native) {
      components.push({
        kind: "NATIVE",
        asset: native,
        amount: nativeValue.toString(),
      });
    } else {
      unpriceableTokens.push(`native currency of chain ${tx.chainId}`);
    }
  }

  // Allowance sizing is a separate question from value: an approval moves
  // nothing today, so it is reported for the risk engine and the approval
  // check rather than added to `valueUsd`.
  let largestAllowance: { amount: bigint; asset: AssetDescriptor } | undefined;

  for (const call of flattenCall(decodedCall)) {
    if (
      (call.kind === "ERC20_TRANSFER" || call.kind === "ERC20_TRANSFER_FROM") &&
      call.amount !== undefined &&
      call.target !== undefined
    ) {
      const amount = toBigInt(call.amount);

      if (amount === undefined || amount === 0n) {
        continue;
      }

      const token = describeToken(tx.chainId, call.target);

      if (!token) {
        unpriceableTokens.push(call.target);
        continue;
      }

      components.push({
        kind: "ERC20",
        asset: token,
        amount: amount.toString(),
        token: call.target,
      });
    }

    if (call.allowance !== undefined && call.target !== undefined) {
      const allowance = toBigInt(call.allowance);
      const token = describeToken(tx.chainId, call.target);

      if (
        allowance !== undefined &&
        allowance > 0n &&
        token &&
        (largestAllowance === undefined || allowance > largestAllowance.amount)
      ) {
        largestAllowance = { amount: allowance, asset: token };
      }
    }
  }

  return {
    components,
    unpriceableTokens,
    ...(largestAllowance === undefined ? {} : { largestAllowance }),
  };
}

/** The "nothing to price" outcome, shared by both paths. */
function nothingToPrice(
  declaredValueUsd: number,
  components: ValueComponent[],
): ValueBindingResult {
  return {
    findings: [
      info(
        "PRICE_UNAVAILABLE",
        `Transaction moves no native value and no priceable token amount, so the declared $${declaredValueUsd} could not be checked against the bytes; the wei, gas and fee ceilings still apply`,
        { declaredValueUsd },
      ),
    ],
    valueUsd: 0,
    valuePriced: true,
    pricingStatus: "NOTHING_TO_PRICE",
    priceQuotes: [],
    components,
  };
}

/**
 * Value binding with no oracle at hand.
 *
 * Used by the synchronous entry point. It reaches the same structural
 * conclusion — value that cannot be priced cannot be authorized autonomously —
 * so the absence of an oracle degrades the decision to ESCALATE rather than to
 * ALLOW.
 */
export function bindValueWithoutOracle(
  context: CheckContext,
): ValueBindingResult {
  const extraction = extractValueComponents(context);

  if (
    extraction.components.length === 0 &&
    extraction.unpriceableTokens.length === 0
  ) {
    return nothingToPrice(context.intent.amountUsd, extraction.components);
  }

  return {
    findings: [
      escalateFinding(
        "PRICE_UNAVAILABLE",
        "No price oracle was supplied to the firewall, so the transaction's real USD value is unknown; it cannot be authorized autonomously against a USD ceiling",
        { components: extraction.components.map(summarize) },
      ),
    ],
    valueUsd: 0,
    valuePriced: false,
    pricingStatus: "UNPRICED",
    priceQuotes: [],
    components: extraction.components,
  };
}

export async function checkValueBinding(
  context: CheckContext,
  options: { oracle?: PriceOracle } = {},
): Promise<ValueBindingResult> {
  const findings: FirewallFinding[] = [];
  const priceQuotes: PriceQuote[] = [];
  const { tx, capability, intent } = context;
  const declaredValueUsd = intent.amountUsd;

  const extraction = extractValueComponents(context);
  const { components, unpriceableTokens } = extraction;
  const largestAllowance = extraction.largestAllowance;

  if (components.length === 0 && unpriceableTokens.length === 0) {
    return nothingToPrice(declaredValueUsd, components);
  }

  const oracle = options.oracle;

  if (!oracle || !oracle.isReady()) {
    findings.push(
      escalateFinding(
        "PRICE_UNAVAILABLE",
        "No price oracle is available, so the transaction's real USD value is unknown; it cannot be authorized autonomously against a USD ceiling",
        { components: components.map(summarize) },
      ),
    );

    return {
      findings,
      valueUsd: 0,
      valuePriced: false,
      pricingStatus: "UNPRICED",
      priceQuotes,
      components,
    };
  }

  let valueUsd = 0;
  let allPriced = true;

  for (const component of components) {
    const quote = await oracle.getUsdPrice(component.asset.symbol, tx.chainId);

    if (quote.status === "UNAVAILABLE") {
      allPriced = false;

      const code = priceDecisionCode(quote.reason);

      findings.push(
        escalateFinding(
          code,
          code === "PRICE_STALE"
            ? `The only price available for ${component.asset.symbol} is older than Arx's staleness bound, so this transfer would be authorized against an out-of-date market`
            : `No usable price for ${component.asset.symbol} on chain ${tx.chainId} (${quote.reason}), so the transaction's USD value is unknown`,
          { asset: component.asset.symbol, reason: quote.reason },
        ),
      );

      continue;
    }

    priceQuotes.push(quote.value);

    valueUsd += baseUnitsToUsd(
      BigInt(component.amount),
      component.asset.decimals,
      quote.value.priceUsd,
    );
  }

  for (const token of unpriceableTokens) {
    allPriced = false;

    findings.push(
      escalateFinding(
        "PRICE_UNAVAILABLE",
        `${token} is not in Arx's verified asset registry, so the amount it moves cannot be valued in USD and the USD ceilings cannot be applied to it`,
        { token },
      ),
    );
  }

  if (largestAllowance) {
    const quote = await oracle.getUsdPrice(
      largestAllowance.asset.symbol,
      tx.chainId,
    );

    if (quote.status === "OK") {
      const allowanceUsd = baseUnitsToUsd(
        largestAllowance.amount,
        largestAllowance.asset.decimals,
        quote.value.priceUsd,
      );

      if (Number.isFinite(allowanceUsd)) {
        return finish(allowanceUsd);
      }
    }
  }

  return finish(undefined);

  function finish(allowanceUsd: number | undefined): ValueBindingResult {
    if (!allPriced) {
      return {
        findings,
        valueUsd,
        valuePriced: false,
        pricingStatus: "UNPRICED",
        priceQuotes,
        ...(allowanceUsd === undefined ? {} : { allowanceUsd }),
        components,
      };
    }

    // Both directions of divergence are reported. Under-declaring is the attack,
    // but an agent that over-declares is also making a false statement about a
    // payment, and an approval artifact a human reads must not carry one.
    const divergenceBps = Math.round(
      (Math.abs(valueUsd - declaredValueUsd) / declaredValueUsd) * 10_000,
    );

    if (divergenceBps > capability.valueToleranceBps) {
      findings.push(
        block(
          "VALUE_DECLARATION_MISMATCH",
          `Agent declared $${declaredValueUsd.toFixed(2)} but the transaction actually moves $${valueUsd.toFixed(2)} — a ${divergenceBps}bps divergence against a tolerance of ${capability.valueToleranceBps}bps. ${
            valueUsd > declaredValueUsd
              ? "The declaration understates the transaction, so every USD ceiling would have been evaluated against a figure the bytes do not support."
              : "The declaration overstates the transaction."
          }`,
          {
            declaredValueUsd,
            valueUsd,
            divergenceBps,
            toleranceBps: capability.valueToleranceBps,
            components: components.map(summarize),
            priceSources: priceQuotes.map((quote) => quote.source),
          },
        ),
      );
    }

    if (valueUsd > capability.maxAmountUsd) {
      findings.push(
        block(
          "AMOUNT_EXCEEDED",
          `Oracle-derived value $${valueUsd.toFixed(2)} exceeds this capability's ceiling of $${capability.maxAmountUsd.toFixed(2)} (the agent declared $${declaredValueUsd.toFixed(2)})`,
          {
            valueUsd,
            declaredValueUsd,
            maxAmountUsd: capability.maxAmountUsd,
            priceSources: priceQuotes.map((quote) => quote.source),
          },
        ),
      );
    }

    if (findings.every((finding) => finding.severity === "INFO")) {
      findings.push(
        info(
          "POLICY_APPROVED",
          `Transaction moves $${valueUsd.toFixed(2)} by oracle price, within ${divergenceBps}bps of the declared $${declaredValueUsd.toFixed(2)} (sources: ${priceQuotes.map((quote) => quote.source).join(", ") || "none"})`,
          {
            valueUsd,
            declaredValueUsd,
            divergenceBps,
            priceSources: priceQuotes.map((quote) => quote.source),
          },
        ),
      );
    }

    return {
      findings,
      valueUsd,
      valuePriced: true,
      pricingStatus: "PRICED",
      priceQuotes,
      ...(allowanceUsd === undefined ? {} : { allowanceUsd }),
      components,
    };
  }
}

function summarize(component: ValueComponent) {
  return {
    kind: component.kind,
    asset: component.asset.symbol,
    decimals: component.asset.decimals,
    amount: component.amount,
    ...(component.token === undefined ? {} : { token: component.token }),
  };
}

function toBigInt(value: string): bigint | undefined {
  try {
    return BigInt(value);
  } catch {
    return undefined;
  }
}
