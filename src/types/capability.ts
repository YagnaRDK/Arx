import { z } from "zod";

export const CapabilityStatusSchema = z.enum([
  "ACTIVE",
  "EXPIRED",
  "REVOKED",
  "CONSUMED",
]);

export const CapabilityUsageSchema = z.enum(["SINGLE_USE", "REUSABLE"]);

export const CapabilitySchema = z.object({
  capabilityId: z.string().min(1),
  agentId: z.string().min(1),

  allowedActions: z.array(z.string().min(1)).min(1),
  allowedProtocols: z.array(z.string().min(1)).min(1),
  allowedChains: z.array(z.number().int().positive()).min(1),

  allowedTokens: z.object({
    input: z.array(z.string().min(1)).min(1),
    output: z.array(z.string().min(1)).min(1),
  }),

  maxAmountUsd: z.number().positive(),
  maxSlippageBps: z.number().int().nonnegative(),

  expiresAt: z.number().int().positive(),
  nonce: z.number().int().nonnegative(),

  status: CapabilityStatusSchema,
  usage: CapabilityUsageSchema,
});

export type Capability = z.infer<typeof CapabilitySchema>;
export type CapabilityStatus = z.infer<typeof CapabilityStatusSchema>;
export type CapabilityUsage = z.infer<typeof CapabilityUsageSchema>;
