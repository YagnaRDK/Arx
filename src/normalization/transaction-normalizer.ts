import { getAddress } from "viem";

import { ArxError } from "../core/errors";
import { canonicalize } from "../crypto/canonical";
import { sha256Hex } from "../crypto/hash";
import {
  EvmTransactionSchema,
  type EvmTransaction,
  type NormalizedTransaction,
} from "../types/transaction";

type NormalizeInput = {
  agentId: string;
  capabilityId: string;
  transaction: unknown;
  /** Injected for determinism in tests. */
  now?: number;
};

/**
 * Strips a leading-zero decimal string to its minimal form.
 *
 * Without this, `"0100"` and `"100"` describe the same value but hash
 * differently — which would let an attacker present a transaction that passes
 * every limit check under one spelling and is bound to an approval under
 * another.
 */
function normalizeUintString(value: string, field: string): string {
  if (!/^\d+$/.test(value)) {
    throw new ArxError(
      "INVALID_TRANSACTION",
      `${field} must be a non-negative integer string`,
    );
  }

  const trimmed = value.replace(/^0+(?=\d)/, "");

  // Reject values that cannot round-trip through a 256-bit integer.
  if (BigInt(trimmed) > 2n ** 256n - 1n) {
    throw new ArxError("INVALID_TRANSACTION", `${field} exceeds 2^256 - 1`);
  }

  return trimmed;
}

/**
 * Produces the single canonical form of a transaction.
 *
 * Two requests describing the same transaction must land on identical bytes
 * here, and any change to a consequential field must change them. Addresses are
 * lowercased (EIP-55 casing is a display concern, not an identity one), integer
 * strings are minimised, and calldata is lowercased.
 */
function canonicalizeTransaction(input: EvmTransaction): EvmTransaction {
  if (input.to !== undefined) {
    // Throws on an invalid address, so a malformed `to` cannot reach policy.
    getAddress(input.to);
  }

  return {
    chainId: input.chainId,
    ...(input.to === undefined ? {} : { to: input.to.toLowerCase() as `0x${string}` }),
    value: normalizeUintString(input.value, "value"),
    data: input.data.toLowerCase(),
    gasLimit: normalizeUintString(input.gasLimit, "gasLimit"),
    maxFeePerGas: normalizeUintString(input.maxFeePerGas, "maxFeePerGas"),
    maxPriorityFeePerGas: normalizeUintString(
      input.maxPriorityFeePerGas,
      "maxPriorityFeePerGas",
    ),
    nonce: input.nonce,
    type: input.type,
  };
}

export class TransactionNormalizer {
  normalize(input: NormalizeInput): NormalizedTransaction {
    const parsed = EvmTransactionSchema.safeParse(input.transaction);

    if (!parsed.success) {
      throw new ArxError(
        "INVALID_TRANSACTION",
        "Transaction failed schema validation",
        { details: parsed.error.flatten() },
      );
    }

    const transaction = canonicalizeTransaction(parsed.data);

    if (
      transaction.maxPriorityFeePerGas !== "0" &&
      BigInt(transaction.maxPriorityFeePerGas) > BigInt(transaction.maxFeePerGas)
    ) {
      throw new ArxError(
        "INVALID_TRANSACTION",
        "maxPriorityFeePerGas cannot exceed maxFeePerGas",
      );
    }

    return {
      transactionId: deriveTransactionId({
        agentId: input.agentId,
        capabilityId: input.capabilityId,
        transaction,
      }),
      agentId: input.agentId,
      capabilityId: input.capabilityId,
      transactionType: "EVM_TRANSACTION",
      transaction,
      createdAt: input.now ?? Math.floor(Date.now() / 1000),
    };
  }
}

/**
 * Deterministic transaction identity.
 *
 * Derived from the canonical content only — never a random UUID — so the same
 * logical request always resolves to the same identity, and `createdAt` is
 * deliberately excluded so a retry of the same transaction is recognisably the
 * same transaction.
 */
export function deriveTransactionId(input: {
  agentId: string;
  capabilityId: string;
  transaction: EvmTransaction;
}): string {
  return sha256Hex(
    canonicalize({
      agentId: input.agentId,
      capabilityId: input.capabilityId,
      transaction: input.transaction,
    }),
  );
}
