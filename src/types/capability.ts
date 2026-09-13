import { z } from "zod";

import { PolicySetSchema } from "./policy-sets";

export const CapabilityStatusSchema = z.enum([
  "ACTIVE",
  "EXPIRED",
  "REVOKED",
  "CONSUMED",
]);

export const CapabilityUsageSchema = z.enum(["SINGLE_USE", "REUSABLE"]);

/** A non-negative integer expressed as a decimal string, for wei-scale values. */
const UintStringSchema = z
  .string()
  .regex(/^\d+$/, "Must be a non-negative integer string");

/**
 * Transaction-level ceilings.
 *
 * These are deliberately separate from `maxAmountUsd`: a USD ceiling depends on
 * a price oracle, while wei/gas ceilings are checkable from the transaction
 * alone. If the oracle is unavailable, the wei ceilings still hold.
 */
export const CapabilityLimitsSchema = z
  .object({
    /** Maximum native value (wei) a single transaction may move. */
    maxValueWei: UintStringSchema.default("0"),
    maxGasLimit: UintStringSchema.default("500000"),
    maxFeePerGasWei: UintStringSchema.default("500000000000"),

    /** Rolling-window spend ceiling, independent of the per-transaction cap. */
    maxAmountUsdPerWindow: z.number().nonnegative().default(0),
    windowSeconds: z.number().int().positive().default(86_400),
    maxTxPerWindow: z.number().int().nonnegative().default(0),
  })
  .prefault({});

export type CapabilityLimits = z.infer<typeof CapabilityLimitsSchema>;

/**
 * When a proposal must stop being autonomous and wait for a human.
 *
 * This is the escalation path rather than a rejection path: a transaction that
 * trips one of these rules is still authorizable, but only by a person at the
 * device.
 */
export const HumanApprovalPolicySchema = z
  .object({
    /** Any transaction valued above this (USD) escalates. 0 disables the rule. */
    requiredAboveUsd: z.number().nonnegative().default(0),
    /** Escalate when the recipient is not on the capability's allowlist. */
    requiredForUnknownRecipient: z.boolean().default(true),
    /** Escalate when the calldata calls one of these function signatures. */
    requiredForMethods: z.array(z.string().min(1)).default([]),
    /** Escalate when the computed risk score is at or above this value. */
    requiredAboveRiskScore: z.number().min(0).max(100).default(60),
    /** Escalate unconditionally — full human-in-the-loop mode. */
    alwaysRequired: z.boolean().default(false),
  })
  .prefault({});

export type HumanApprovalPolicy = z.infer<typeof HumanApprovalPolicySchema>;

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
  /** Capability is not usable before this time. Enables scheduled authority. */
  notBefore: z.number().int().positive().optional(),

  /**
   * The replay floor, not a counter. An intent's nonce must be at or above this
   * value, and each nonce may be used at most once per capability. See
   * `src/policy/nonce.ts` for why these two concerns are kept separate.
   */
  nonce: z.number().int().nonnegative(),

  status: CapabilityStatusSchema,
  usage: CapabilityUsageSchema,

  /**
   * Who may receive native value, as addresses or ENS names. Defaults to
   * fail-closed: with no entries, no recipient is authorized.
   */
  recipients: PolicySetSchema,
  /** Which contracts the agent may call. */
  contracts: PolicySetSchema,
  /**
   * Which functions the agent may call, as 4-byte selectors (`0xa9059cbb`) or
   * canonical signatures (`transfer(address,uint256)`).
   */
  methods: PolicySetSchema,

  limits: CapabilityLimitsSchema,
  humanApproval: HumanApprovalPolicySchema,

  /** Hard rejection ceiling for the risk engine, above the escalation rule. */
  maxRiskScore: z.number().min(0).max(100).default(80),

  /** Deploying a contract is a distinct authority from calling one. */
  allowContractCreation: z.boolean().default(false),

  /**
   * How far the transaction's oracle-derived USD value may differ from the
   * agent's own `amountUsd` claim before the mismatch is treated as a lie.
   */
  valueToleranceBps: z.number().int().nonnegative().default(500),

  /** Human-readable label for dashboards and device screens. */
  label: z.string().max(120).optional(),
});

export type Capability = z.infer<typeof CapabilitySchema>;
export type CapabilityStatus = z.infer<typeof CapabilityStatusSchema>;
export type CapabilityUsage = z.infer<typeof CapabilityUsageSchema>;
