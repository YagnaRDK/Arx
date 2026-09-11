import { z } from "zod";

export const IntentSchema = z.object({
  capabilityId: z.string().min(1),
  agentId: z.string().min(1),

  action: z.string().min(1),
  protocol: z.string().min(1),
  chainId: z.number().int(),

  inputToken: z.string().min(1),
  outputToken: z.string().min(1),

  amountUsd: z.number().positive(),
  slippageBps: z.number().int().nonnegative(),

  nonce: z.number().int().nonnegative(),
  timestamp: z.number().int().positive(),
});

export type Intent = z.infer<typeof IntentSchema>;
