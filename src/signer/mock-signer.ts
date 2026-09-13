import { createHash } from "node:crypto";

import type { NormalizedTransaction } from "../types/transaction";
import type { SignerAdapter, SignerResult } from "./signer-types";

export class MockSignerAdapter implements SignerAdapter {
  readonly name = "mock-signer";

  private readonly signerAddress = "0x0000000000000000000000000000000000000001";

  async getAddress(): Promise<string> {
    return this.signerAddress;
  }

  async signTransaction(
    transaction: NormalizedTransaction,
  ): Promise<SignerResult> {
    const serializedTransaction = JSON.stringify(transaction);

    const digest = createHash("sha256")
      .update(serializedTransaction)
      .digest("hex");

    return {
      signedTransaction: `0xmock_${digest}`,
      signerAddress: this.signerAddress,
      transactionId: transaction.transactionId,
    };
  }
}
