import type { NormalizedTransaction } from "../types/transaction";
import type { SignerAdapter, SignerResult } from "./signer-types";

export class SignerService {
  constructor(private readonly adapter: SignerAdapter) {}

  async getSignerInfo() {
    const address = await this.adapter.getAddress();

    return {
      adapter: this.adapter.name,
      address,
    };
  }

  async sign(transaction: NormalizedTransaction): Promise<SignerResult> {
    return this.adapter.signTransaction(transaction);
  }
}
