import { requestApproval } from "../lib/flows";
import {
  ADDRESS,
  buildIntent,
  contractCall,
  encodeErc20Transfer,
} from "../lib/fixtures";
import type { Scenario } from "../lib/scenario";
import { style } from "../lib/term";

/**
 * The most persuasive attack in the suite, because every field is legitimate.
 *
 * A recipient allowlist that checks `transaction.to` is checking the wrong
 * field. For an ERC-20 transfer, `to` is the token contract — which is
 * allowlisted, and should be — and the actual beneficiary is an argument buried
 * in calldata. An allowlist that stops at `to` authorises a payment to anyone on
 * earth as long as it is denominated in an approved token.
 *
 * So the firewall has to decode the calldata and apply the recipient allowlist to
 * what the transaction *does*, not to what it is addressed to.
 */
export const calldataSmuggling: Scenario = {
  name: "calldata-smuggling",
  title: "Calldata smuggling: the attacker rides inside an ERC-20 transfer",
  kind: "ATTACK",
  story: [
    "to:   the USDC contract           — on the contract allowlist",
    "data: transfer(attacker, 50000)   — the attacker is an *argument*",
    "A recipient check that reads transaction.to sees nothing wrong at all.",
  ],
  expectation:
    "DENY CALLDATA_RECIPIENT_NOT_ALLOWED — the decoded beneficiary is not granted",

  async run(ctx, trace): Promise<void> {
    const capability = ctx.seeds.tokenOps;

    // 50,000 USDC at 6 decimals.
    const data = encodeErc20Transfer(ADDRESS.attacker, 50_000_000_000n);
    const transaction = contractCall(ADDRESS.usdc, data);

    if (!ctx.quiet) {
      trace.note(
        style.grey(
          `arg[0] of the calldata is ${ADDRESS.attacker} — right-padded into a 32-byte word`,
        ),
      );
    }

    const intent = buildIntent({
      capabilityId: capability.capabilityId,
      nonce: ctx.nextNonce(capability.capabilityId),
      timestamp: ctx.now,
      amountUsd: 50_000,
      action: "transfer",
      protocol: "erc20",
      inputToken: "USDC",
      outputToken: "USDC",
      transaction,
    });

    const result = await requestApproval(ctx, trace, intent);

    trace.expectVerdict("the smuggled transfer is refused", result, "DENY");
    trace.expectCode("refusal names the decoded recipient", result, {
      code: "CALLDATA_RECIPIENT_NOT_ALLOWED",
      alsoAcceptable: ["RECIPIENT_NOT_ALLOWED", "CALLDATA_NOT_ALLOWED"],
    });

    // If the refusal came from the method or contract allowlist, the calldata
    // was never decoded and the control under test did not actually run.
    const code =
      typeof result.body === "object" && result.body !== null
        ? (result.body as Record<string, unknown>).code
        : null;

    trace.assert(
      "the calldata was inspected, not just the destination",
      code !== "METHOD_NOT_ALLOWED" && code !== "CONTRACT_NOT_ALLOWED",
      "a calldata- or recipient-level denial",
      typeof code === "string" ? code : "unknown",
    );
  },
};
