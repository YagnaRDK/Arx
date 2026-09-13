import { recoverAddress, type Hex } from "viem";

import { ArxError } from "../core/errors";
import { unsignedTransactionDigest } from "../ledger/tx-serialize";
import type { NormalizedTransaction } from "../types/transaction";

export type SignatureVerification = {
  verified: boolean;
  /** The digest the signature was checked against, recomputed by Arx. */
  digest: Hex;
  recoveredAddress: string;
  reportedAddress: string;
};

/**
 * Recovers the signer from a signature and compares it to the address the
 * device claimed.
 *
 * This is the step that makes the whole chain provable (invariant 3: the
 * transaction signed is byte-identical to the transaction approved). The digest
 * is recomputed here from the canonical transaction — never taken from the
 * adapter — so an adapter cannot hand back a signature over different bytes
 * together with a digest that makes it look correct.
 */
export async function verifyTransactionSignature(input: {
  transaction: NormalizedTransaction;
  r: string;
  s: string;
  yParity: 0 | 1;
  reportedAddress: string;
}): Promise<SignatureVerification> {
  const digest = unsignedTransactionDigest(input.transaction.transaction);

  let recoveredAddress: string;

  try {
    recoveredAddress = await recoverAddress({
      hash: digest,
      signature: {
        r: input.r as Hex,
        s: input.s as Hex,
        yParity: input.yParity,
      },
    });
  } catch (error) {
    throw new ArxError(
      "SIGNATURE_VERIFICATION_FAILED",
      "Signature could not be recovered against the approved transaction digest",
      {
        cause: error,
        details: { digest, transactionId: input.transaction.transactionId },
      },
    );
  }

  return {
    verified:
      recoveredAddress.toLowerCase() === input.reportedAddress.toLowerCase(),
    digest,
    recoveredAddress,
    reportedAddress: input.reportedAddress,
  };
}
