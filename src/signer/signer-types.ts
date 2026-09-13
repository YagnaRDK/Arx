import type { NormalizedTransaction } from "../types/transaction";

export type SignerResult = {
  signedTransaction: string;
  signerAddress: string;
  transactionId: string;
};

export interface SignerAdapter {
  readonly name: string;

  getAddress(): Promise<string>;

  signTransaction(transaction: NormalizedTransaction): Promise<SignerResult>;
}
