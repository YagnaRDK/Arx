import { codeOf, verdictOf } from "../lib/api";
import { requestApproval } from "../lib/flows";
import { ADDRESS, buildIntent, nativeTransfer, weiForUsd } from "../lib/fixtures";
import type { Scenario } from "../lib/scenario";
import { formatUsd, kv, style } from "../lib/term";

const WINDOW_LIMIT_USD = 300;
const PER_PAYMENT_USD = 120;
const MAX_ATTEMPTS = 8;

/**
 * A budget, not a per-transaction limit.
 *
 * Per-transaction ceilings are trivially defeated by splitting: ten payments of
 * $99 against a $100 limit drains the account just as well as one payment of
 * $990. The control that actually bounds exposure is a rolling window, and it has
 * to count authority at *approval* time rather than at signing time — an
 * outstanding approval is a promise already made.
 *
 * The loop is deliberately adaptive rather than asserting "the third one fails":
 * the exact cut-off depends on the USD value the server's oracle assigns, which
 * this demo does not control. What it asserts is the shape of the answer — some
 * payments succeed, then the window closes with the specific code, and it stays
 * closed.
 */
export const spendWindow: Scenario = {
  name: "spend-window",
  title: `Spend window: a ${formatUsd(WINDOW_LIMIT_USD)}/day budget, exhausted`,
  kind: "CONTROL",
  story: [
    `The capability may move ${formatUsd(WINDOW_LIMIT_USD)} per 24 hours, to`,
    `allowlisted recipients only. The agent submits ${formatUsd(PER_PAYMENT_USD)}`,
    "payments, one after another, each individually permitted.",
  ],
  expectation:
    "at least one payment authorised, then DENY SPEND_WINDOW_EXCEEDED, and it stays denied",

  async run(ctx, trace): Promise<void> {
    const capability = ctx.seeds.spendWindow;

    let authorised = 0;
    let refusalCode: string | null = null;
    let refusalAttempt = 0;

    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
      const transaction = nativeTransfer(
        ADDRESS.treasury,
        weiForUsd(PER_PAYMENT_USD, ctx.ethUsd),
      );

      const intent = buildIntent({
        capabilityId: capability.capabilityId,
        nonce: ctx.nextNonce(capability.capabilityId),
        timestamp: ctx.now,
        amountUsd: PER_PAYMENT_USD,
        transaction,
      });

      const result = await requestApproval(
        ctx,
        trace,
        intent,
        `POST /approvals (payment ${attempt} of up to ${MAX_ATTEMPTS})`,
      );

      if (verdictOf(result) === "ALLOW") {
        authorised += 1;
        continue;
      }

      refusalCode = codeOf(result);
      refusalAttempt = attempt;
      break;
    }

    if (!ctx.quiet) {
      kv([
        ["authorised", `${authorised} payment(s)`],
        [
          "cumulative",
          `${formatUsd(authorised * PER_PAYMENT_USD)} against a ${formatUsd(
            WINDOW_LIMIT_USD,
          )} window`,
        ],
        ["refused at", refusalAttempt === 0 ? "never" : `payment ${refusalAttempt}`],
        ["refusal code", refusalCode ?? style.red("none")],
      ]);
    }

    trace.assert(
      "payments inside the budget are authorised",
      authorised >= 1,
      ">= 1 authorised",
      String(authorised),
    );

    trace.assert(
      "the window eventually closes",
      refusalCode !== null,
      `a refusal within ${MAX_ATTEMPTS} payments`,
      refusalCode === null ? "never refused" : refusalCode,
    );

    trace.assert(
      "the refusal names the spend window",
      refusalCode === "SPEND_WINDOW_EXCEEDED" ||
        refusalCode === "TX_COUNT_WINDOW_EXCEEDED",
      "SPEND_WINDOW_EXCEEDED | TX_COUNT_WINDOW_EXCEEDED",
      refusalCode ?? "none",
    );

    // A window that reopens on the next request is not a window.
    if (refusalCode !== null) {
      const retry = await requestApproval(
        ctx,
        trace,
        buildIntent({
          capabilityId: capability.capabilityId,
          nonce: ctx.nextNonce(capability.capabilityId),
          timestamp: ctx.now,
          amountUsd: PER_PAYMENT_USD,
          transaction: nativeTransfer(
            ADDRESS.treasury,
            weiForUsd(PER_PAYMENT_USD, ctx.ethUsd),
          ),
        }),
        "POST /approvals (retry after the window closed)",
      );

      trace.expectVerdict("the window stays closed", retry, "DENY");
    }
  },
};
