import { evaluatePolicySet } from "../../types/policy-sets";
import {
  block,
  info,
  isContractCall,
  type CheckContext,
  type FirewallFinding,
} from "../types";
import { flattenCall } from "./decode-calldata";
import type { ResolvedPolicySet } from "./recipient-resolution";

/**
 * Which contracts the agent may call.
 *
 * Applied to the transaction's own `to` and, separately, to every distinct
 * target inside a batch. The second half is the part that is easy to omit: a
 * Multicall3 address on the contract allowlist would otherwise be a universal
 * proxy to every contract on the chain, since each inner call carries its own
 * target.
 */
export function checkContractPolicy(
  context: CheckContext,
  contracts: ResolvedPolicySet,
): FirewallFinding[] {
  const { tx, capability, decodedCall } = context;

  if (!isContractCall(tx) || tx.to === undefined) {
    return [];
  }

  const findings: FirewallFinding[] = [];

  const targets = new Set<string>([tx.to.toLowerCase()]);

  for (const call of flattenCall(decodedCall)) {
    if (call.target !== undefined) {
      targets.add(call.target.toLowerCase());
    }
  }

  for (const target of targets) {
    const verdict = evaluatePolicySet(contracts.set, [target]);

    if (verdict.outcome === "ALLOWED") {
      continue;
    }

    findings.push(
      block(
        "CONTRACT_NOT_ALLOWED",
        verdict.reason === "EXPLICIT_DENY"
          ? `Contract ${target} is on this capability's contract denylist`
          : capability.contracts.allow.length === 0
            ? `Contract ${target} is not authorized: this capability's contract allowlist is empty, which permits nobody`
            : `Contract ${target} is not on this capability's contract allowlist`,
        {
          contract: target,
          reason: verdict.reason,
          allowlist: capability.contracts.allow,
          mode: capability.contracts.mode,
          isOuterTarget: target === tx.to.toLowerCase(),
        },
      ),
    );
  }

  if (contracts.unresolvedDeny.length > 0 && findings.length === 0) {
    findings.push(
      info(
        "CONTRACT_NOT_ALLOWED",
        `${contracts.unresolvedDeny.length} contract denylist entr(ies) could not be resolved: ${contracts.unresolvedDeny.join(", ")}`,
        { unresolved: contracts.unresolvedDeny },
      ),
    );
  }

  if (findings.length === 0) {
    findings.push(
      info(
        "POLICY_APPROVED",
        `All ${targets.size} call target(s) satisfy the capability's contract policy`,
        { targets: [...targets] },
      ),
    );
  }

  return findings;
}
