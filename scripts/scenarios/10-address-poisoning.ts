import { riskOf } from "../lib/api";
import { requestApproval } from "../lib/flows";
import { ADDRESS, buildIntent, nativeTransfer, weiForUsd } from "../lib/fixtures";
import type { Scenario } from "../lib/scenario";
import { shortHex, style } from "../lib/term";

/**
 * Address poisoning targets the human, not the machine.
 *
 * An attacker seeds the victim's transaction history with an address that shares
 * the first and last few characters of a real counterparty. Every wallet, block
 * explorer and hardware-device screen truncates addresses in the middle, so the
 * two look identical everywhere a person would actually look. The victim
 * copy-pastes from history and pays the attacker.
 *
 * Arx's allowlist stops this by construction. What this scenario additionally
 * checks is whether the refusal *explains itself as poisoning* — because
 * "not on the allowlist" is correct but tells an operator nothing about why a
 * near-identical address just showed up in their traffic.
 */
export const addressPoisoning: Scenario = {
  name: "address-poisoning",
  title: "Address poisoning: a look-alike of the treasury address",
  kind: "ATTACK",
  story: [
    `allowlisted  ${ADDRESS.treasury}`,
    `submitted    ${ADDRESS.poisonedTreasury}`,
    `on a device screen both read  ${shortHex(ADDRESS.treasury, 4)}`,
  ],
  expectation:
    "refused or escalated, and the similarity to an allowlisted address is surfaced",

  async run(ctx, trace): Promise<void> {
    const capability = ctx.seeds.poisoning;
    const transaction = nativeTransfer(
      ADDRESS.poisonedTreasury,
      weiForUsd(40, ctx.ethUsd),
    );

    const intent = buildIntent({
      capabilityId: capability.capabilityId,
      nonce: ctx.nextNonce(capability.capabilityId),
      timestamp: ctx.now,
      amountUsd: 40,
      transaction,
    });

    const result = await requestApproval(ctx, trace, intent);

    trace.expectVerdict("the look-alike is not paid", result, [
      "DENY",
      "ESCALATE",
    ]);

    trace.expectCode("the refusal is specific", result, {
      code: "ADDRESS_POISONING_SUSPECTED",
      alsoAcceptable: [
        "RECIPIENT_NOT_ALLOWED",
        "HUMAN_APPROVAL_REQUIRED",
        "RISK_SCORE_EXCEEDED",
      ],
    });

    // Separate, weaker assertion: was the *reason* explained as poisoning
    // anywhere in the response — code, reason text, or a risk signal? The
    // allowlist already made this safe; this is about auditability.
    const risk = riskOf(result);
    const haystack = [
      result.rawBody,
      ...(risk?.signals.map((signal) => `${signal.id} ${signal.explanation}`) ??
        []),
    ]
      .join(" ")
      .toLowerCase();

    const explained =
      haystack.includes("poison") ||
      haystack.includes("look-alike") ||
      haystack.includes("lookalike") ||
      haystack.includes("similar");

    trace.assert(
      "the similarity is explained, not just rejected",
      explained,
      "a poisoning/similarity signal or code",
      explained ? "explained" : "only a generic allowlist denial",
    );

    if (!explained && !ctx.quiet) {
      trace.note(
        style.grey(
          "Safe, but an operator reading the log cannot tell this from an ordinary unknown recipient.",
        ),
      );
    }
  },
};
