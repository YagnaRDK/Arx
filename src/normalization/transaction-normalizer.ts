import { randomUUID } from "node:crypto";

import {
  EvmTransactionSchema,
  type EvmTransaction,
  type NormalizedTransaction,
} from "../types/transaction";

type NormalizeInput = {
  agentId: string;
  capabilityId: string;
  transaction: unknown;
};

export class TransactionNormalizer {
  normalize(input: NormalizeInput): NormalizedTransaction {
    const transaction = EvmTransactionSchema.parse(input.transaction);

    return {
      transactionId: randomUUID(),
      agentId: input.agentId,
      capabilityId: input.capabilityId,
      transactionType: "EVM_TRANSACTION",
      transaction,
      createdAt: Math.floor(Date.now() / 1000),
    };
  }
}
