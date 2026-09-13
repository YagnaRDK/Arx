import { evaluatePolicySet } from "../../types/policy-sets";
import {
  block,
  escalateFinding,
  info,
  type CheckContext,
  type FirewallFinding,
} from "../types";
import { flattenCall, type DecodedCall } from "./decode-calldata";
import type { ResolvedPolicySet } from "./recipient-resolution";

/**
 * The real payee lives inside the calldata.
 *
 * For an ERC-20 `transfer`, the transaction's `to` is the *token contract* and
 * the person being paid is the first argument. A firewall that only checks `to`
 * therefore treats an allowlisted token as an open payment channel: allow USDC
 * once and the agent can send USDC to anyone on earth. The same applies to
 * `transferFrom`, ERC-721 `safeTransferFrom`, and to every approval, where the
 * spender receives authority over the balance rather than the balance itself.
 *
 * The recipient policy is therefore applied to the addresses the decoder
 * extracted, at every depth of a batch.
 */

/** Kinds whose calldata names someone who ends up with value or authority. */
const KINDS_WITH_INNER_RECIPIENTS = new Set<DecodedCall["kind"]>([
  "ERC20_TRANSFER",
  "ERC20_TRANSFER_FROM",
  "ERC20_APPROVE",
  "ERC20_INCREASE_ALLOWANCE",
  "ERC20_PERMIT",
  "ERC721_SAFE_TRANSFER_FROM",
  "ERC721_SET_APPROVAL_FOR_ALL",
]);

export function checkCalldataRecipient(
  context: CheckContext,
  recipients: ResolvedPolicySet,
): FirewallFinding[] {
  const findings: FirewallFinding[] = [];
  const { capability, decodedCall } = context;

  const checked = new Set<string>();

  for (const call of flattenCall(decodedCall)) {
    if (!KINDS_WITH_INNER_RECIPIENTS.has(call.kind)) {
      continue;
    }

    for (const recipient of call.recipients) {
      const candidate = recipient.toLowerCase();

      if (checked.has(candidate)) {
        continue;
      }

      checked.add(candidate);

      const verdict = evaluatePolicySet(recipients.set, [candidate]);

      if (verdict.outcome === "ALLOWED") {
        continue;
      }

      const role = call.spender === candidate ? "spender" : "payee";

      findings.push(
        block(
          "CALLDATA_RECIPIENT_NOT_ALLOWED",
          verdict.reason === "EXPLICIT_DENY"
            ? `The ${role} encoded in the calldata of ${call.signature ?? call.selector} is ${candidate}, which is on this capability's denylist`
            : capability.recipients.allow.length === 0
              ? `The ${role} encoded in the calldata of ${call.signature ?? call.selector} is ${candidate}, and this capability's recipient allowlist is empty, which permits nobody`
              : `The ${role} encoded in the calldata of ${call.signature ?? call.selector} is ${candidate}, which is not on this capability's recipient allowlist — the contract this call targets (${call.target ?? "unknown"}) is not the party being paid`,
          {
            recipient: candidate,
            role,
            token: call.target,
            signature: call.signature,
            selector: call.selector,
            reason: verdict.reason,
            allowlist: capability.recipients.allow,
          },
        ),
      );
    }
  }

  if (findings.length === 0 && checked.size > 0) {
    if (recipients.unresolvedDeny.length > 0) {
      findings.push(
        escalateFinding(
          "CALLDATA_RECIPIENT_NOT_ALLOWED",
          `Calldata recipients match the allowlist, but ${recipients.unresolvedDeny.length} denylist entr(ies) could not be resolved: ${recipients.unresolvedDeny.join(", ")}`,
          { unresolvedDeny: recipients.unresolvedDeny },
        ),
      );
    } else {
      findings.push(
        info(
          "POLICY_APPROVED",
          `All ${checked.size} recipient(s) found inside the calldata satisfy the capability's recipient policy`,
          { recipients: [...checked] },
        ),
      );
    }
  }

  return findings;
}
