import type { NormalizedTransaction } from "../types/transaction";
import type { SignerAdapter, SignerResult } from "./signer-types";

type SpeculosSignerConfig = {
  apiUrl: string;
  signerAddress: string;
};

export class SpeculosSignerAdapter implements SignerAdapter {
  readonly name = "speculos";

  constructor(private readonly config: SpeculosSignerConfig) {}

  async getAddress(): Promise<string> {
    return this.config.signerAddress;
  }

  async signTransaction(
    transaction: NormalizedTransaction,
  ): Promise<SignerResult> {
    /*
     * Speculos does not define one universal signing API.
     * The APDU protocol depends on the Ledger app loaded into it.
     *
     * This adapter currently verifies that the Speculos API
     * is reachable. The app-specific APDU signing command
     * will be implemented after loading the Ethereum app.
     */

    const response = await fetch(
      `${this.config.apiUrl}/events?currentscreenonly=true`,
    );

    if (!response.ok) {
      throw new Error(`Speculos API unavailable: HTTP ${response.status}`);
    }

    throw new Error(
      `Speculos is reachable, but app-specific signing APDU is not configured for transaction ${transaction.transactionId}`,
    );
  }
}
