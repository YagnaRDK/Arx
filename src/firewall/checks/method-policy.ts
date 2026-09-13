import { evaluatePolicySet } from "../../types/policy-sets";
import {
  block,
  escalateFinding,
  info,
  isContractCall,
  type CheckContext,
  type FirewallFinding,
} from "../types";
import {
  flattenCall,
  selectorForSignature,
  signatureForSelector,
  type DecodedCall,
} from "./decode-calldata";

/**
 * Which functions the agent may call.
 *
 * A capability's `methods` set is written by a human in whichever spelling is to
 * hand — `0xa9059cbb` or `transfer(address,uint256)` — so both are offered as
 * candidates for every call, and allowlist entries written as signatures are
 * also compared by their computed selector. Otherwise the same policy would
 * pass or fail depending on notation, which is a trap rather than a control.
 *
 * Every call in the tree is checked, not just the outermost one. A batch
 * wrapper whose own selector is allowed must never launder an inner method that
 * is not.
 */
export function checkMethodPolicy(context: CheckContext): FirewallFinding[] {
  const { tx, capability, decodedCall } = context;

  if (!isContractCall(tx)) {
    return [];
  }

  const findings: FirewallFinding[] = [];
  const restricted = capability.methods.mode === "ALLOWLIST";

  // Allowlist entries spelled as signatures also match by selector, and vice
  // versa, so the policy is notation-independent.
  const expandedAllow = expandMethodEntries(capability.methods.allow);
  const expandedDeny = expandMethodEntries(capability.methods.deny);

  const policySet = {
    mode: capability.methods.mode,
    allow: expandedAllow,
    deny: expandedDeny,
  };

  for (const call of flattenCall(decodedCall)) {
    if (call.kind === "NATIVE_TRANSFER" || call.kind === "CONTRACT_CREATION") {
      continue;
    }

    if (call.selector === undefined) {
      findings.push(
        block(
          "CALLDATA_NOT_ALLOWED",
          "A call in this transaction carries calldata with no readable function selector",
          { note: call.note },
        ),
      );

      continue;
    }

    const candidates = methodCandidates(call);
    const verdict = evaluatePolicySet(policySet, candidates);

    if (verdict.outcome === "DENIED") {
      findings.push(
        block(
          "METHOD_NOT_ALLOWED",
          verdict.reason === "EXPLICIT_DENY"
            ? `Method ${describe(call)} is on this capability's method denylist`
            : capability.methods.allow.length === 0
              ? `Method ${describe(call)} is not authorized: this capability's method allowlist is empty, which permits nothing`
              : `Method ${describe(call)} is not on this capability's method allowlist`,
          {
            selector: call.selector,
            signature: call.signature,
            target: call.target,
            reason: verdict.reason,
            allowlist: capability.methods.allow,
          },
        ),
      );

      continue;
    }

    // The selector is permitted, but Arx could not read the arguments. Under a
    // method-restricted capability that is a denial: allowing a call whose
    // payee and amount are opaque would make every other calldata check
    // decorative. Under an explicitly broad `ANY` capability it escalates
    // instead, because the operator asked for breadth but not for blindness.
    if (!call.decoded && call.kind !== "BATCH") {
      findings.push(
        restricted
          ? block(
              "CALLDATA_NOT_ALLOWED",
              `Arx cannot decode ${describe(call)}, so its recipient and amount cannot be checked, and this capability restricts methods`,
              { selector: call.selector, note: call.note, target: call.target },
            )
          : escalateFinding(
              "CALLDATA_NOT_ALLOWED",
              `Arx cannot decode ${describe(call)}; a human must confirm what it does`,
              { selector: call.selector, note: call.note, target: call.target },
            ),
      );
    }
  }

  if (findings.length === 0) {
    findings.push(
      info(
        "POLICY_APPROVED",
        "Every method invoked by this transaction satisfies the capability's method policy",
      ),
    );
  }

  return findings;
}

function describe(call: DecodedCall): string {
  return call.signature ?? call.selector ?? "an unknown method";
}

function methodCandidates(call: DecodedCall): string[] {
  const candidates: string[] = [];

  if (call.selector !== undefined) {
    candidates.push(call.selector.toLowerCase());
  }

  if (call.signature !== undefined) {
    candidates.push(call.signature);
  }

  // A known selector may have a canonical signature even when the arguments
  // failed to decode, so recover it from the registry too.
  if (call.signature === undefined && call.selector !== undefined) {
    const signature = signatureForSelector(call.selector);

    if (signature !== undefined) {
      candidates.push(signature);
    }
  }

  return candidates;
}

/**
 * Expands each policy entry into every spelling it could match.
 *
 * `transfer(address,uint256)` also matches as `0xa9059cbb`, so an operator who
 * wrote the signature is not silently bypassed by a call Arx identified only by
 * selector.
 */
function expandMethodEntries(entries: readonly string[]): string[] {
  const expanded = new Set<string>();

  for (const entry of entries) {
    expanded.add(entry.toLowerCase());

    if (entry.includes("(")) {
      const selector = selectorForSignature(entry);

      if (selector !== undefined) {
        expanded.add(selector.toLowerCase());
      }

      continue;
    }

    const signature = signatureForSelector(entry);

    if (signature !== undefined) {
      expanded.add(signature);
    }
  }

  return [...expanded];
}
