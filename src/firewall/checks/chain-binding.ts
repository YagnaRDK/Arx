import { block, info, type CheckContext, type FirewallFinding } from "../types";

/**
 * Chain binding.
 *
 * Three values must agree: the chain the agent declared, the chain the
 * transaction bytes are bound to, and the set of chains the capability covers.
 * If they can disagree, a capability scoped to a testnet authorizes a mainnet
 * transaction, because every later check reads the same fields without ever
 * asking which network they belong to.
 */
export function checkChainBinding(context: CheckContext): FirewallFinding[] {
  const findings: FirewallFinding[] = [];
  const { tx, intent, capability } = context;

  if (tx.chainId !== intent.chainId) {
    findings.push(
      block(
        "TRANSACTION_CHAIN_MISMATCH",
        `Transaction is bound to chain ${tx.chainId} but the intent declares chain ${intent.chainId}`,
        { transactionChainId: tx.chainId, intentChainId: intent.chainId },
      ),
    );
  }

  if (!capability.allowedChains.includes(tx.chainId)) {
    findings.push(
      block(
        "CHAIN_NOT_ALLOWED",
        `Chain ${tx.chainId} is not among this capability's allowed chains [${capability.allowedChains.join(", ")}]`,
        { chainId: tx.chainId, allowedChains: capability.allowedChains },
      ),
    );
  }

  if (findings.length === 0) {
    findings.push(
      info(
        "POLICY_APPROVED",
        `Chain ${tx.chainId} is bound consistently across intent, transaction and capability`,
      ),
    );
  }

  return findings;
}
