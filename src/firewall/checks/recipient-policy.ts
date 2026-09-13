import { evaluatePolicySet } from "../../types/policy-sets";
import {
  block,
  escalateFinding,
  info,
  movesNativeValue,
  type CheckContext,
  type FirewallFinding,
} from "../types";
import type { ResolvedPolicySet } from "./recipient-resolution";

/**
 * Who may receive native value.
 *
 * This is the check the headline attack walks straight through when it is
 * missing: a prompt-injected agent proposes a well-formed transfer to an address
 * the operator never authorized, every other field is legitimate, and without
 * this comparison the transaction is indistinguishable from a correct one.
 */
export function checkRecipientPolicy(
  context: CheckContext,
  recipients: ResolvedPolicySet,
): FirewallFinding[] {
  const { tx, capability } = context;

  // Contract creation has no recipient; `contract-creation.ts` owns that case.
  if (tx.to === undefined) {
    return [];
  }

  const nativeTransfer = movesNativeValue(tx);

  if (!nativeTransfer) {
    // A zero-value contract call is governed by the contract and method
    // policies, and by `calldata-recipient.ts` for any payee inside the
    // calldata. Nothing to say here.
    return [];
  }

  const findings: FirewallFinding[] = [];
  const candidate = tx.to.toLowerCase();
  const verdict = evaluatePolicySet(recipients.set, [candidate]);

  if (verdict.outcome === "DENIED") {
    if (verdict.reason === "EXPLICIT_DENY") {
      findings.push(
        block(
          "RECIPIENT_DENIED",
          `Recipient ${candidate} is on this capability's denylist`,
          { recipient: candidate },
        ),
      );

      return findings;
    }

    findings.push(
      block(
        "RECIPIENT_NOT_ALLOWED",
        capability.recipients.allow.length === 0
          ? `Recipient ${candidate} is not authorized: this capability's recipient allowlist is empty, which permits nobody`
          : `Recipient ${candidate} is not on this capability's recipient allowlist`,
        {
          recipient: candidate,
          allowlist: capability.recipients.allow,
          mode: capability.recipients.mode,
        },
      ),
    );

    if (recipients.unresolvedAllow.length > 0) {
      findings.push(
        info(
          "RECIPIENT_NOT_ALLOWED",
          `${recipients.unresolvedAllow.length} allowlist entr(ies) are names that could not be resolved, so they were not treated as matches: ${recipients.unresolvedAllow.join(", ")}`,
          { unresolved: recipients.unresolvedAllow },
        ),
      );
    }

    return findings;
  }

  // Allowed — but only conclusively if Arx could see the whole denylist.
  if (recipients.unresolvedDeny.length > 0) {
    findings.push(
      escalateFinding(
        "RECIPIENT_NOT_ALLOWED",
        `Recipient ${candidate} matches the allowlist, but ${recipients.unresolvedDeny.length} denylist entr(ies) could not be resolved, so Arx cannot prove the recipient is not denied: ${recipients.unresolvedDeny.join(", ")}`,
        { recipient: candidate, unresolvedDeny: recipients.unresolvedDeny },
      ),
    );

    return findings;
  }

  findings.push(
    info(
      "POLICY_APPROVED",
      `Recipient ${candidate} satisfies the capability's recipient policy`,
      { recipient: candidate, mode: recipients.set.mode },
    ),
  );

  return findings;
}
