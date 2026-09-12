import { z } from "zod";

export const EvmTransactionSchema = z.object({
  chainId: z.number().int().positive(),
  to: z.string().regex(/^0x[a-fA-F0-9]{40}$/, "Invalid EVM address"),
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
});

export type EvmTransaction = z.infer<typeof EvmTransactionSchema>;

export const NormalizedTransactionSchema = z.object({
  transactionId: z.string().min(1),
  agentId: z.string().min(1),
  capabilityId: z.string().min(1),
  transactionType: z.literal("EVM_TRANSACTION"),
  transaction: EvmTransactionSchema,
  createdAt: z.number().int().positive(),
});

export type NormalizedTransaction = z.infer<typeof NormalizedTransactionSchema>;
