/**
 * Shared request flows and display helpers.
 *
 * Scenarios differ in what they are trying to prove, not in how they talk to
 * Arx, so the two calls every scenario makes — "ask for an approval" and "ask
 * the signer boundary to use it" — live here with the display formatting that
 * makes their inputs visible in a recording.
 */

import type { Intent } from "../../src/types/intent";
import type { EvmTransaction } from "../../src/types/transaction";

import { type ApiResult } from "./api";
import type { RunContext } from "./context";
import { ADDRESS, describeCalldata, usdForWei } from "./fixtures";
import { formatUsd, formatWei, style } from "./term";
import type { Trace } from "./scenario";

const ALLOWLISTED = new Set<string>(
  [ADDRESS.treasury, ADDRESS.vendor, ADDRESS.usdc].map((address) =>
    address.toLowerCase(),
  ),
);

function annotateAddress(address: string | undefined): string {
  if (!address) {
    return `${style.amber("(none — contract creation)")}`;
  }

  const lower = address.toLowerCase();

  if (lower === ADDRESS.attacker.toLowerCase()) {
    return `${address} ${style.red("<- attacker, NOT on the allowlist")}`;
  }

  if (lower === ADDRESS.poisonedTreasury.toLowerCase()) {
    return `${address} ${style.red("<- look-alike of the treasury address")}`;
  }

  if (ALLOWLISTED.has(lower)) {
    return `${address} ${style.green("<- allowlisted")}`;
  }

  return `${address} ${style.amber("<- not on the allowlist")}`;
}

/** The request detail block printed above every decision. */
export function intentDetail(
  ctx: RunContext,
  intent: Intent,
): Array<[string, string]> {
  const rows: Array<[string, string]> = [
    ["agent", intent.agentId],
    ["capability", intent.capabilityId],
    [
      "scope",
      `${intent.action} / ${intent.protocol} / chain ${intent.chainId} / nonce ${intent.nonce}`,
    ],
    ["declared", `${formatUsd(intent.amountUsd)} (the agent's own claim)`],
  ];

  const transaction = intent.transaction;

  if (transaction) {
    rows.push(["to", annotateAddress(transaction.to)]);
    rows.push([
      "value",
      `${formatWei(transaction.value)} ≈ ${formatUsd(
        usdForWei(transaction.value, ctx.ethUsd),
      )} at ${formatUsd(ctx.ethUsd)}/ETH`,
    ]);

    const calldata = describeCalldata(transaction.data);

    calldata.forEach((line, index) => {
      rows.push([index === 0 ? "calldata" : "", line]);
    });
  }

  return rows;
}

export async function requestApproval(
  ctx: RunContext,
  trace: Trace,
  intent: Intent,
  label = "POST /approvals",
): Promise<ApiResult> {
  return trace.requireRoute(
    await trace.call(label, intentDetail(ctx, intent), () =>
      ctx.client.post("/approvals", intent),
    ),
  );
}

export async function requestSignature(
  ctx: RunContext,
  trace: Trace,
  input: { approvalId: string; transaction: EvmTransaction },
  label = "POST /sign",
): Promise<ApiResult> {
  return trace.requireRoute(
    await trace.call(
      label,
      [
        ["approvalId", input.approvalId],
        ["to", annotateAddress(input.transaction.to)],
        ["value", formatWei(input.transaction.value)],
      ],
      () => ctx.client.post("/sign", input),
    ),
  );
}

/**
 * Asserts a signing response admits what actually signed it.
 *
 * Invariant 8: a mock signature is never presented as a real one. In the default
 * demo the signer mode is `mock`, so the response must say so somewhere — and
 * the assertion is inverted from the usual direction: it fails if the response
 * looks like a real signature when the server is running a mock.
 */
export function assertSignerHonesty(trace: Trace, result: ApiResult): void {
  const body = result.body as Record<string, any> | null;
  const text = result.rawBody.toLowerCase();

  const mode =
    (typeof body?.signer?.mode === "string" ? body.signer.mode : null) ??
    (typeof body?.signerMode === "string" ? body.signerMode : null) ??
    (typeof body?.signer?.adapter === "string" ? body.signer.adapter : null) ??
    null;

  const declaresMock =
    text.includes("mock") ||
    text.includes("emulated") ||
    text.includes("simulated");

  trace.assert(
    "signing response names the signer it used",
    mode !== null,
    "signer.mode or signer.adapter present",
    mode ?? "absent",
  );

  if (mode !== null && /mock/i.test(mode)) {
    trace.assert(
      "mock signature is labelled as a mock",
      declaresMock,
      "response mentions mock/emulated",
      declaresMock ? "labelled" : "NOT labelled",
    );
  }
}
