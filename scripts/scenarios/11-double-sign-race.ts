import { approvalOf, codeOf, type ApiResult } from "../lib/api";
import { requestApproval } from "../lib/flows";
import { ADDRESS, buildIntent, nativeTransfer, weiForUsd } from "../lib/fixtures";
import { BlockedError, type Scenario } from "../lib/scenario";
import { field, style } from "../lib/term";

/**
 * Concurrency, asserted rather than reasoned about.
 *
 * "Read the status, then update it" is the default way to write this code and it
 * is wrong: two requests can both read APPROVED before either writes. The window
 * is small, so the bug survives every sequential test and every code review that
 * reasons about it instead of racing it.
 *
 * So this scenario races it — two genuinely concurrent `/sign` calls on one
 * approval, issued with `Promise.all` — and asserts that exactly one wins.
 * Invariant 5 under concurrency.
 */
export const doubleSignRace: Scenario = {
  name: "double-sign-race",
  title: "Double-sign race: two concurrent /sign calls, one approval",
  kind: "ATTACK",
  story: [
    "A single approval, two signing requests dispatched in the same tick.",
    "If the approval's state transition is not atomic, both read APPROVED",
    "and the payment happens twice.",
  ],
  expectation: "exactly one signature succeeds; the other is refused with a conflict",

  async run(ctx, trace): Promise<void> {
    const capability = ctx.seeds.payments;
    const transaction = nativeTransfer(
      ADDRESS.vendor,
      weiForUsd(30, ctx.ethUsd),
    );

    const intent = buildIntent({
      capabilityId: capability.capabilityId,
      nonce: ctx.nextNonce(capability.capabilityId),
      timestamp: ctx.now,
      amountUsd: 30,
      transaction,
    });

    const approvalResult = await requestApproval(ctx, trace, intent);
    const approval = approvalOf(approvalResult);

    if (!approval) {
      throw new BlockedError(
        `Could not obtain an approval to race (HTTP ${approvalResult.status})`,
      );
    }

    const body = { approvalId: approval.approvalId, transaction };

    if (!ctx.quiet) {
      field(
        "request",
        style.bold("POST /sign x2 (Promise.all, identical bodies)"),
      );
    }

    const [first, second] = await Promise.all([
      ctx.client.post("/sign", body),
      ctx.client.post("/sign", body),
    ]);

    trace.requireRoute(first);

    const record = (label: string, result: ApiResult) => {
      trace.steps.push({
        label,
        method: result.method,
        path: result.path,
        status: result.status,
        code: codeOf(result),
        verdict: result.ok ? "ALLOW" : "DENY",
        reason: null,
        ms: result.ms,
      });

      if (!ctx.quiet) {
        field(
          "decision",
          `${label}  HTTP ${result.status}  ${
            result.ok
              ? style.green("SIGNED")
              : style.red(codeOf(result) ?? "refused")
          }`,
        );
      }
    };

    record("call A", first);
    record("call B", second);

    const successes = [first, second].filter(
      (result) => result.status >= 200 && result.status < 300,
    );
    const losers = [first, second].filter(
      (result) => !(result.status >= 200 && result.status < 300),
    );

    trace.assert(
      "exactly one signature succeeded",
      successes.length === 1,
      "1 success",
      `${successes.length} successes`,
    );

    if (losers.length === 1) {
      const loserCode = codeOf(losers[0]!);

      trace.assert(
        "the loser is refused with a specific conflict code",
        loserCode === "APPROVAL_STATE_CONFLICT" ||
          loserCode === "APPROVAL_ALREADY_CONSUMED" ||
          loserCode === "APPROVAL_INVALID",
        "APPROVAL_STATE_CONFLICT | APPROVAL_ALREADY_CONSUMED | APPROVAL_INVALID",
        loserCode ?? `none (HTTP ${losers[0]!.status})`,
      );
    }

    // Belt and braces: the approval must end up in exactly one terminal state.
    const after = await ctx.client.get(`/approvals/${approval.approvalId}`);
    const finalState = approvalOf(after);

    if (finalState?.status) {
      trace.assert(
        "the approval ends in a single terminal state",
        ["CONSUMED", "SIGNING_FAILED"].includes(finalState.status),
        "CONSUMED | SIGNING_FAILED",
        finalState.status,
      );
    }
  },
};
