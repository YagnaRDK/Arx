import { z } from "zod";

export const HexAddressSchema = z
  .string()
  .regex(/^0x[a-fA-F0-9]{40}$/, "Invalid EVM address");

export const EvmTransactionSchema = z.object({
  chainId: z.number().int().positive(),

  /**
   * Absent `to` means contract creation, which is a separate authority gated by
   * `capability.allowContractCreation`.
   */
  to: HexAddressSchema.optional(),

  value: z.string().regex(/^\d+$/, "Value must be an integer string"),
  data: z
    .string()
    .regex(/^0x([a-fA-F0-9]{2})*$/, "Invalid hexadecimal calldata"),
  gasLimit: z.string().regex(/^\d+$/, "Gas limit must be an integer string"),
  maxFeePerGas: z
    .string()
    .regex(/^\d+$/, "Max fee per gas must be an integer string"),
  maxPriorityFeePerGas: z
    .string()
    .regex(/^\d+$/, "Max priority fee per gas must be an integer string"),
  nonce: z.number().int().nonnegative(),

  /** EIP-1559 is the default; legacy is supported for chains that need it. */
  type: z.enum(["eip1559", "legacy"]).default("eip1559"),
});

export type EvmTransaction = z.infer<typeof EvmTransactionSchema>;

export const NormalizedTransactionSchema = z.object({
  /** Deterministic SHA-256 identity. Never a random UUID. */
  transactionId: z.string().min(1),
  agentId: z.string().min(1),
  capabilityId: z.string().min(1),
  transactionType: z.literal("EVM_TRANSACTION"),
  transaction: EvmTransactionSchema,
  createdAt: z.number().int().positive(),
});

export type NormalizedTransaction = z.infer<typeof NormalizedTransactionSchema>;
