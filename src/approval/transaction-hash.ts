import { canonicalize } from "../crypto/canonical";
import { hashCanonical } from "../crypto/hash";
import type { NormalizedTransaction } from "../types/transaction";

/**
 * The hash an approval is bound to.
 *
 * This is the single value that makes "the transaction that was approved" and
 * "the transaction being signed" the same object. It commits to the agent, the
 * capability and every consequential transaction field, and to nothing
 * ephemeral: `createdAt` and request identifiers are excluded so a legitimate
 * retry still matches, while any change to a field that affects what the
 * transaction *does* produces a different hash and fails verification.
 */
export function hashNormalizedTransaction(
  transaction: NormalizedTransaction,
): string {
  return hashCanonical({
    transactionType: transaction.transactionType,
    agentId: transaction.agentId,
    capabilityId: transaction.capabilityId,
    transaction: transaction.transaction,
  });
}

/** The exact bytes `hashNormalizedTransaction` digests. Used by `/audit` to
 * show an operator precisely what was committed to. */
export function transactionPreimage(
  transaction: NormalizedTransaction,
): string {
  return canonicalize({
    transactionType: transaction.transactionType,
    agentId: transaction.agentId,
    capabilityId: transaction.capabilityId,
    transaction: transaction.transaction,
  });
}
