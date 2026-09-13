import { requestApproval } from "../lib/flows";
import {
  ADDRESS,
  buildIntent,
  ethToWei,
  nativeTransfer,
  usdForWei,
} from "../lib/fixtures";
import type { Scenario } from "../lib/scenario";
import { formatUsd, formatWei, style } from "../lib/term";

/**
 * The agent's numbers are claims, not facts.
 *
 * `amountUsd` arrives in the request body. It is the easiest field in the whole
 * protocol to falsify, and every limit expressed in dollars is worthless if it
 * is checked against the claim instead of against the bytes. Here the agent
 * declares one dollar while moving a thousand ether.
 *
 * The capability used by this scenario is the only one in the suite carrying a
 * production-shaped 5% tolerance — and the lie is six orders of magnitude, so
 * the outcome does not depend on what price the oracle reports.
 */
export const declaredValueLie: Scenario = {
  name: "declared-value-lie",
  title: "Declared-value lie: $1 on the label, 1000 ETH in the bytes",
  kind: "ATTACK",
  story: [
    'The agent declares amountUsd: 1 — "a dollar, routine, below every',
    'threshold" — and attaches a transaction moving 1000 ETH.',
    "Every USD limit in the system would pass if the claim were trusted.",
  ],
  expectation:
    "DENY VALUE_DECLARATION_MISMATCH — the oracle value and the claim disagree",

  async run(ctx, trace): Promise<void> {
    const capability = ctx.seeds.valueBinding;
    const valueWei = ethToWei(1_000);

    const transaction = nativeTransfer(ADDRESS.treasury, valueWei);

    const intent = buildIntent({
      capabilityId: capability.capabilityId,
      nonce: ctx.nextNonce(capability.capabilityId),
      timestamp: ctx.now,
      amountUsd: 1,
      transaction,
    });

    trace.note(
      `claimed ${formatUsd(1)} vs ${formatWei(valueWei)} ≈ ${formatUsd(
        usdForWei(valueWei, ctx.ethUsd),
      )} at the demo's ${formatUsd(ctx.ethUsd)}/ETH reference`,
    );

    const result = await requestApproval(ctx, trace, intent);

    trace.expectVerdict("the request is refused", result, "DENY");

    // PRICE_UNAVAILABLE is accepted as an alternate because it is still the
    // fail-closed answer — an unreachable oracle must not widen what is
    // permitted. It is reported as an alternate, never as this control firing.
    trace.expectCode("refusal names the value binding", result, {
      code: "VALUE_DECLARATION_MISMATCH",
      alsoAcceptable: ["PRICE_UNAVAILABLE", "PRICE_STALE", "AMOUNT_EXCEEDED"],
    });

    if (!ctx.quiet) {
      trace.note(
        style.grey(
          "The transaction bytes are the fact; amountUsd is an assertion to be checked.",
        ),
      );
    }
  },
};
