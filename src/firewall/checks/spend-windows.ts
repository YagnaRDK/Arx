import type { SpendStore, SpendWindowUsage } from "../../storage/spend-store";
import {
  block,
  info,
  type CheckContext,
  type FirewallFinding,
} from "../types";

/**
 * Rolling-window spend accounting.
 *
 * A per-transaction ceiling alone bounds nothing over time: an agent with a
 * $100 limit can send a hundred $99 transactions. The window limits are what
 * make a capability a budget rather than a rate of one.
 *
 * The reservation semantics live in `SpendStore` — authority is consumed when an
 * approval is *issued*, not when it is signed — so what this check has to get
 * right is only the comparison, including the transaction being decided now.
 *
 * `0` means "no window limit configured", matching `humanApproval.requiredAboveUsd`.
 * That is safe here in a way it would not be for `maxValueWei`, because
 * `maxAmountUsd` is a required, positive field: every transaction is already
 * bounded per-transaction whether or not a window is set.
 */
export type SpendWindowResult = {
  findings: FirewallFinding[];
  usage?: SpendWindowUsage;
};

export function checkSpendWindows(
  context: CheckContext,
  options: { spendStore?: SpendStore; valueUsd: number; valuePriced: boolean },
): SpendWindowResult {
  const findings: FirewallFinding[] = [];
  const limits = context.capability.limits;

  const hasAmountLimit = limits.maxAmountUsdPerWindow > 0;
  const hasCountLimit = limits.maxTxPerWindow > 0;

  if (!hasAmountLimit && !hasCountLimit) {
    return { findings };
  }

  if (!options.spendStore) {
    // A configured budget that cannot be read is not a budget that has room.
    findings.push(
      block(
        "SPEND_WINDOW_EXCEEDED",
        "This capability carries rolling-window limits but no spend ledger is available to check them, so the remaining budget is unknown",
        {
          maxAmountUsdPerWindow: limits.maxAmountUsdPerWindow,
          maxTxPerWindow: limits.maxTxPerWindow,
        },
      ),
    );

    return { findings };
  }

  const usage = options.spendStore.usage(
    context.capability.capabilityId,
    limits.windowSeconds,
    context.now,
  );

  // An unpriced transfer consumes an unknown amount of a USD budget. Charging it
  // as $0 would let a price outage become unlimited spend, so the check refuses
  // instead; `value-binding.ts` has already escalated the missing price.
  if (hasAmountLimit && !options.valuePriced) {
    findings.push(
      block(
        "SPEND_WINDOW_EXCEEDED",
        `This capability has a $${limits.maxAmountUsdPerWindow} rolling budget, but this transaction's USD value is unknown, so it cannot be charged against it`,
        { usage, maxAmountUsdPerWindow: limits.maxAmountUsdPerWindow },
      ),
    );
  } else if (hasAmountLimit) {
    const projected = usage.amountUsd + options.valueUsd;

    if (projected > limits.maxAmountUsdPerWindow) {
      findings.push(
        block(
          "SPEND_WINDOW_EXCEEDED",
          `This transaction would bring spend in the last ${limits.windowSeconds}s to $${projected.toFixed(2)}, above the window limit of $${limits.maxAmountUsdPerWindow.toFixed(2)} ($${usage.amountUsd.toFixed(2)} already committed)`,
          {
            committedUsd: usage.amountUsd,
            transactionUsd: options.valueUsd,
            projectedUsd: projected,
            limitUsd: limits.maxAmountUsdPerWindow,
            windowSeconds: limits.windowSeconds,
            windowStart: usage.windowStart,
          },
        ),
      );
    }
  }

  if (hasCountLimit && usage.transactionCount + 1 > limits.maxTxPerWindow) {
    findings.push(
      block(
        "TX_COUNT_WINDOW_EXCEEDED",
        `This capability has already committed ${usage.transactionCount} transaction(s) in the last ${limits.windowSeconds}s, at its limit of ${limits.maxTxPerWindow}`,
        {
          committedCount: usage.transactionCount,
          limit: limits.maxTxPerWindow,
          windowSeconds: limits.windowSeconds,
          windowStart: usage.windowStart,
        },
      ),
    );
  }

  if (findings.length === 0) {
    findings.push(
      info(
        "POLICY_APPROVED",
        `Within the rolling window: $${usage.amountUsd.toFixed(2)} of $${limits.maxAmountUsdPerWindow.toFixed(2)} and ${usage.transactionCount} of ${limits.maxTxPerWindow} transaction(s) already committed`,
        { usage },
      ),
    );
  }

  return { findings, usage };
}
