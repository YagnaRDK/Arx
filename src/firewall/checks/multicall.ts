import {
  block,
  info,
  type CheckContext,
  type FirewallFinding,
} from "../types";
import { flattenCall } from "./decode-calldata";

/**
 * Batch wrappers.
 *
 * A wrapper is only as trustworthy as Arx's ability to see through it. If the
 * inner calls can be enumerated, the method, contract and recipient checks each
 * walk the whole tree and apply the same rules at every depth — so a permitted
 * `multicall` cannot carry a forbidden `transfer` inside it.
 *
 * If they cannot be enumerated, the whole transaction is refused. The
 * alternative is to clear a wrapper on the strength of its own selector while
 * having no idea what it executes, which is precisely the laundering path this
 * check exists to close.
 */
export function checkMulticall(context: CheckContext): FirewallFinding[] {
  const findings: FirewallFinding[] = [];
  const calls = flattenCall(context.decodedCall);
  const batches = calls.filter((call) => call.kind === "BATCH");

  if (batches.length === 0) {
    return findings;
  }

  for (const batch of batches) {
    if (batch.decoded) {
      continue;
    }

    findings.push(
      block(
        "CALLDATA_NOT_ALLOWED",
        `Transaction wraps its calls in ${batch.signature ?? batch.selector ?? "a batch"} whose contents Arx could not enumerate (${batch.note ?? "unknown reason"}), so the methods and recipients inside it cannot be checked and the whole transaction is refused`,
        {
          selector: batch.selector,
          signature: batch.signature,
          target: batch.target,
          note: batch.note,
          innerCount: batch.inner?.length ?? 0,
        },
      ),
    );
  }

  if (findings.length === 0) {
    const innerCount = calls.length - batches.length;

    findings.push(
      info(
        "POLICY_APPROVED",
        `Batch expanded into ${innerCount} inner call(s); method, contract and recipient policy were applied to each`,
        {
          batches: batches.map((batch) => batch.signature ?? batch.selector),
          innerCount,
        },
      ),
    );
  }

  return findings;
}
