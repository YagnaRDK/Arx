/**
 * The bridge between Arx's normalized transaction and Ethereum wire bytes.
 *
 * All RLP and EIP-2718 envelope work is delegated to viem. Hand-rolling RLP at
 * a signing boundary means the bytes the device reviews and the bytes Arx
 * believes it approved can drift apart — invariant 3 forbids exactly that.
 */

import {
  keccak256,
  serializeTransaction,
  type Hex,
  type TransactionSerializable,
  type TransactionSerializableEIP1559,
  type TransactionSerializableLegacy,
} from "viem";

import { ArxError } from "../core/errors";
import type { EvmTransaction } from "../types/transaction";

export type Secp256k1Signature = {
  r: Hex;
  s: Hex;
  yParity: 0 | 1;
};

/**
 * Maps the canonical Arx transaction onto viem's serializable shape.
 *
 * Arx stores fees under EIP-1559 names for every transaction type, so a
 * `legacy` transaction takes its single `gasPrice` from `maxFeePerGas`. The
 * conversion is explicit and lossless in one direction only — which is why the
 * digest used for verification is always recomputed from this same function
 * rather than from anything an adapter reports back.
 */
export function toSerializableTransaction(
  transaction: EvmTransaction,
): TransactionSerializable {
  const to = transaction.to as Hex | undefined;

  if (transaction.type === "legacy") {
    const legacy: TransactionSerializableLegacy = {
      type: "legacy",
      chainId: transaction.chainId,
      nonce: transaction.nonce,
      gas: BigInt(transaction.gasLimit),
      gasPrice: BigInt(transaction.maxFeePerGas),
      value: BigInt(transaction.value),
      data: transaction.data as Hex,
      ...(to === undefined ? {} : { to }),
    };

    return legacy;
  }

  const eip1559: TransactionSerializableEIP1559 = {
    type: "eip1559",
    chainId: transaction.chainId,
    nonce: transaction.nonce,
    gas: BigInt(transaction.gasLimit),
    maxFeePerGas: BigInt(transaction.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(transaction.maxPriorityFeePerGas),
    value: BigInt(transaction.value),
    data: transaction.data as Hex,
    // An empty access list is the closed default: Arx does not let an agent
    // smuggle storage-access hints past the policy layer.
    accessList: [],
    ...(to === undefined ? {} : { to }),
  };

  return eip1559;
}

/**
 * The exact bytes streamed to the device: the unsigned serialization.
 *
 * For EIP-1559 this is `0x02 || rlp([...])`; for legacy with a chain ID it is
 * the EIP-155 form `rlp([..., chainId, 0, 0])`.
 */
export function serializeUnsigned(transaction: EvmTransaction): Hex {
  return serializeTransaction(toSerializableTransaction(transaction));
}

/**
 * The digest a correct signature must recover against.
 *
 * Recomputed from the canonical transaction on every verification, never taken
 * from the signer adapter: a compromised adapter could otherwise report a
 * digest that matches its own signature.
 */
export function unsignedTransactionDigest(transaction: EvmTransaction): Hex {
  return keccak256(serializeUnsigned(transaction));
}

/** Reassembles the broadcastable signed transaction. */
export function serializeSigned(
  transaction: EvmTransaction,
  signature: Secp256k1Signature,
): Hex {
  const serializable = toSerializableTransaction(transaction);

  if (signature.r.length !== 66 || signature.s.length !== 66) {
    throw new ArxError(
      "SIGNING_FAILED",
      "Signature r and s must each be 32 bytes",
    );
  }

  if (serializable.type === "legacy") {
    // viem's legacy serializer reads `signature.v`, not `yParity`: a legacy
    // transaction carries the chain ID inside `v` (EIP-155), so the parity
    // alone is not enough to serialize it. Passing the full EIP-155 value makes
    // viem take it verbatim rather than re-derive it.
    return serializeTransaction(serializable, {
      r: signature.r,
      s: signature.s,
      v: BigInt(serializable.chainId ?? 0) * 2n + 35n + BigInt(signature.yParity),
    });
  }

  return serializeTransaction(serializable, {
    r: signature.r,
    s: signature.s,
    yParity: signature.yParity,
  });
}
