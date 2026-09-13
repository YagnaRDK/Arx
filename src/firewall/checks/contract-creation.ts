import { block, info, type CheckContext, type FirewallFinding } from "../types";

/**
 * Contract creation.
 *
 * Deploying code is a different authority from calling code: a deployment can
 * create the very contract a later transaction is allowed to call, so an agent
 * that can deploy can manufacture its own counterparty. `to` being absent is the
 * only signal, and it is gated by its own capability flag rather than folded
 * into the contract allowlist.
 */
export function checkContractCreation(
  context: CheckContext,
): FirewallFinding[] {
  const { tx, capability } = context;

  if (tx.to !== undefined) {
    return [];
  }

  if (!capability.allowContractCreation) {
    return [
      block(
        "CONTRACT_CREATION_NOT_ALLOWED",
        "Transaction has no `to` address, so it deploys a contract, and this capability does not grant contract creation",
        { initCodeBytes: Math.max(0, (tx.data.length - 2) / 2) },
      ),
    ];
  }

  return [
    info(
      "POLICY_APPROVED",
      "Transaction deploys a contract, which this capability explicitly permits",
      { initCodeBytes: Math.max(0, (tx.data.length - 2) / 2) },
    ),
  ];
}
