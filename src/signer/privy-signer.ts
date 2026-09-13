import { ArxError } from "../core/errors";
import type { NormalizedTransaction } from "../types/transaction";
import type {
  SignerAdapter,
  SignerResult,
  SignerStatus,
} from "./signer-types";

/**
 * STUB — not implemented here.
 *
 * Privy is a delegated-wallet integration and belongs behind the integrations
 * seam, which another area of the codebase owns (`src/integrations`). This
 * placeholder exists only so `SIGNER_MODE=privy` is a configuration that
 * reports itself unavailable, rather than one that silently falls back to the
 * mock signer — a silent fallback would be the exact failure invariant 8
 * forbids.
 *
 * It reports `available: false` and refuses to sign. Replace it with the real
 * adapter when the integrations work lands; the `SignerAdapter` contract is all
 * it has to satisfy.
 */
export class PrivySignerAdapter implements SignerAdapter {
  readonly name = "privy-stub";
  readonly signatureType = "REAL" as const;

  async getStatus(): Promise<SignerStatus> {
    return {
      adapter: this.name,
      signatureType: "REAL",
      available: false,
      emulated: false,
      detail:
        "STUB: the Privy signer is not implemented. It is owned by the integrations layer (src/integrations), not the Ledger signer boundary.",
    };
  }

  async getAddress(): Promise<string> {
    throw this.unavailable();
  }

  async signTransaction(
    _transaction: NormalizedTransaction,
  ): Promise<SignerResult> {
    throw this.unavailable();
  }

  private unavailable(): ArxError {
    return new ArxError(
      "SIGNER_UNAVAILABLE",
      "The Privy signer adapter is a stub and cannot sign; set SIGNER_MODE to mock, speculos or dmk",
    );
  }
}
