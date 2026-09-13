import { ArxError } from "../core/errors";
import type { NormalizedTransaction } from "../types/transaction";
import type {
  SignerAdapter,
  SignerResult,
  SignerStatus,
} from "./signer-types";
import { verifyTransactionSignature } from "./verify-signature";

/**
 * The one way into the signer boundary.
 *
 * Its job is not to sign — an adapter does that — but to refuse to hand back a
 * signature it has not proved. Every real signature is recovered against the
 * digest the service recomputes from the canonical transaction and compared to
 * the address the device reported. A mismatch is
 * `SIGNATURE_VERIFICATION_FAILED` and never a success, which is what makes
 * invariant 3 (the transaction signed is byte-identical to the transaction
 * approved) a checked property rather than a hope.
 */
export class SignerService {
  constructor(private readonly adapter: SignerAdapter) {}

  async getSignerInfo(): Promise<SignerStatus> {
    if (this.adapter.getStatus !== undefined) {
      return this.adapter.getStatus();
    }

    // An adapter with no status probe still has to declare what it is.
    try {
      const address = await this.adapter.getAddress();

      return {
        adapter: this.adapter.name,
        signatureType: this.adapter.signatureType,
        available: true,
        emulated: this.adapter.signatureType === "MOCK",
        address,
      };
    } catch (error) {
      return {
        adapter: this.adapter.name,
        signatureType: this.adapter.signatureType,
        available: false,
        emulated: this.adapter.signatureType === "MOCK",
        detail: error instanceof Error ? error.message : "Signer unavailable",
      };
    }
  }

  async sign(transaction: NormalizedTransaction): Promise<SignerResult> {
    const result = await this.adapter.signTransaction(transaction);

    if (result.transactionId !== transaction.transactionId) {
      // The adapter signed something other than what it was handed, or lost
      // track of which request this was.
      throw new ArxError(
        "SIGNATURE_VERIFICATION_FAILED",
        "Signer returned a result for a different transaction",
        {
          details: {
            expected: transaction.transactionId,
            received: result.transactionId,
          },
        },
      );
    }

    if (result.signatureType === "MOCK") {
      // Nothing to recover. `verified` stays false, and the MOCK label travels
      // with the result all the way to the API response.
      return { ...result, verified: false };
    }

    if (result.yParity === undefined) {
      throw new ArxError(
        "SIGNATURE_VERIFICATION_FAILED",
        "Real signature is missing the y-parity needed to recover the signer",
        { details: { adapter: result.adapter } },
      );
    }

    const verification = await verifyTransactionSignature({
      transaction,
      r: result.r,
      s: result.s,
      yParity: result.yParity,
      reportedAddress: result.signerAddress,
    });

    if (!verification.verified) {
      throw new ArxError(
        "SIGNATURE_VERIFICATION_FAILED",
        "The signature does not recover to the address the signer reported",
        {
          details: {
            adapter: result.adapter,
            digest: verification.digest,
            reportedAddress: verification.reportedAddress,
            recoveredAddress: verification.recoveredAddress,
          },
        },
      );
    }

    return {
      ...result,
      verified: true,
      signedDigest: verification.digest,
    };
  }
}
