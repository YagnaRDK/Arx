import { z } from "zod";

export const CapabilitySchema = z.object({
  capabilityId: z.string().min(1),
  agentId: z.string().min(1),

  allowedActions: z.array(z.string()).min(1),
  allowedProtocols: z.array(z.string()).min(1),
  allowedChains: z.array(z.number().int()).min(1),

  allowedTokens: z.object({
    input: z.array(z.string()).min(1),
    output: z.array(z.string()).min(1),
  }),

  maxAmountUsd: z.number().positive(),
  maxSlippageBps: z.number().int().nonnegative(),

  expiresAt: z.number().int().positive(),
  nonce: z.number().int().nonnegative(),

  status: z.enum(["ACTIVE", "EXPIRED", "REVOKED", "CONSUMED"]),

  usage: z.enum(["SINGLE_USE", "REUSABLE"]),
});

export type Capability = z.infer<typeof CapabilitySchema>;
