import type { EvaluationResult } from "../types/evaluation";
import type { NormalizedTransaction } from "../types/transaction";

export type FirewallDecision = {
  allowed: boolean;
  transaction?: NormalizedTransaction;
  result: EvaluationResult;
};

export class TransactionFirewall {
  process(
    transaction: NormalizedTransaction,
    result: EvaluationResult,
  ): FirewallDecision {
    if (!result.allowed) {
      return {
        allowed: false,
        result,
      };
    }

    return {
      allowed: true,
      transaction,
      result,
    };
  }
}
