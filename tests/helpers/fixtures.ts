import { encodeFunctionData } from "viem";

import { TransactionNormalizer } from "../../src/normalization/transaction-normalizer";
import { StaticPriceOracle } from "../../src/oracle/static-oracle";
import { CapabilitySchema, type Capability } from "../../src/types/capability";
import { IntentSchema, type Intent } from "../../src/types/intent";
import type {
  EvmTransaction,
  NormalizedTransaction,
} from "../../src/types/transaction";

/**
 * Shared fixtures for the control-coverage suites.
 *
 * Capabilities and intents are built through their Zod schemas rather than as
 * object literals. A literal would let a test opt out of the fail-closed
 * defaults (`recipients.mode: "ALLOWLIST"`, `maxValueWei: "0"`,
 * `allowContractCreation: false`), and a test that silently runs against
 * different defaults from production is not evidence about production.
 *
 * IMPORTANT: import this module only *after* the test file has set NODE_ENV and
 * DATABASE_PATH. Several project modules open bun:sqlite at import time and
 * `bun test` shares one module registry across every test file, so whichever
 * file imports first fixes the database path for the whole run.
 */

/** Fixed clock. Every decision in these suites is time-injected. */
export const NOW = 1_700_000_000;

export const CHAIN_ID = 11_155_111;
/** A chain the fixture capability does not cover. */
export const FOREIGN_CHAIN_ID = 1;

export const PAYEE = "0x1111111111111111111111111111111111111111";
export const ATTACKER = "0x2222222222222222222222222222222222222222";
export const SECOND_PAYEE = "0x3333333333333333333333333333333333333333";

/**
 * Circle's Sepolia USDC. It has to be a real, registry-known token: an unknown
 * token is unpriceable, which changes the decision from ALLOW to ESCALATE and
 * would make a value-binding test measure the wrong thing.
 */
export const USDC = "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238";
/** A token contract that is deliberately absent from Arx's asset registry. */
export const UNKNOWN_TOKEN = "0x9999999999999999999999999999999999999999";

export const MULTICALL3 = "0xca11bde05977b3631167028862be2a173976ca11";

export const AGENT_ID = "agent-fixture";
export const CAPABILITY_ID = "cap-fixture";

export const UINT256_MAX = 2n ** 256n - 1n;
/** The floor at which `approve-semantics.ts` calls an allowance unlimited. */
export const EFFECTIVELY_UNLIMITED = 2n ** 128n;

const ERC20_ABI = [
  {
    name: "transfer",
    type: "function",
    inputs: [{ type: "address" }, { type: "uint256" }],
    outputs: [],
  },
  {
    name: "transferFrom",
    type: "function",
    inputs: [{ type: "address" }, { type: "address" }, { type: "uint256" }],
    outputs: [],
  },
  {
    name: "approve",
    type: "function",
    inputs: [{ type: "address" }, { type: "uint256" }],
    outputs: [],
  },
  {
    name: "increaseAllowance",
    type: "function",
    inputs: [{ type: "address" }, { type: "uint256" }],
    outputs: [],
  },
  {
    name: "permit",
    type: "function",
    inputs: [
      { type: "address" },
      { type: "address" },
      { type: "uint256" },
      { type: "uint256" },
      { type: "uint8" },
      { type: "bytes32" },
      { type: "bytes32" },
    ],
    outputs: [],
  },
  {
    name: "safeTransferFrom",
    type: "function",
    inputs: [{ type: "address" }, { type: "address" }, { type: "uint256" }],
    outputs: [],
  },
  {
    name: "setApprovalForAll",
    type: "function",
    inputs: [{ type: "address" }, { type: "bool" }],
    outputs: [],
  },
] as const;

const BATCH_ABI = [
  {
    name: "multicall",
    type: "function",
    inputs: [{ type: "bytes[]" }],
    outputs: [],
  },
  {
    name: "aggregate3",
    type: "function",
    inputs: [
      {
        type: "tuple[]",
        components: [{ type: "address" }, { type: "bool" }, { type: "bytes" }],
      },
    ],
    outputs: [],
  },
  {
    // Uniswap's Universal Router. Its `bytes[]` are command parameters, not
    // nested calldata, so Arx cannot enumerate them — the opaque-batch case.
    name: "execute",
    type: "function",
    inputs: [{ type: "bytes" }, { type: "bytes[]" }],
    outputs: [],
  },
] as const;

/*
 * viem's `encodeFunctionData` is generic over a literal ABI, which cannot be
 * expressed for a runtime-chosen function name. The narrowing is dropped here
 * once, deliberately, rather than scattering casts through every test — the ABI
 * constants above are still the single source of the encoding.
 */
type EncodeFunctionData = (input: {
  abi: unknown;
  functionName: string;
  args: readonly unknown[];
}) => string;

const encode = encodeFunctionData as unknown as EncodeFunctionData;

/** ABI-encodes one ERC-20/721 call. Real encoding, not a hand-written hex blob. */
export function erc20(name: string, args: readonly unknown[]): string {
  return encode({ abi: ERC20_ABI, functionName: name, args });
}

export function batch(name: string, args: readonly unknown[]): string {
  return encode({ abi: BATCH_ABI, functionName: name, args });
}

/** The 4-byte selector of an encoded call. */
export function selectorOf(data: string): string {
  return data.slice(0, 10);
}

export const normalizer = new TransactionNormalizer();

/** A price oracle pinned to the fixture clock, so quotes are never stale. */
export function freshOracle(): StaticPriceOracle {
  return new StaticPriceOracle({ now: () => NOW });
}

export type CapabilityOverrides = Partial<
  Record<keyof Capability, unknown>
> & { [key: string]: unknown };

/**
 * A capability that permits exactly one thing: paying PAYEE, in native value or
 * in Sepolia USDC, on CHAIN_ID. Everything else is closed by default and each
 * test opens precisely the door it is testing.
 */
export function buildCapability(overrides: CapabilityOverrides = {}): Capability {
  return CapabilitySchema.parse({
    capabilityId: CAPABILITY_ID,
    agentId: AGENT_ID,

    allowedActions: ["TRANSFER", "APPROVE", "SWAP"],
    allowedProtocols: ["NATIVE", "ERC20"],
    allowedChains: [CHAIN_ID],

    allowedTokens: { input: ["ETH", "USDC"], output: ["ETH", "USDC"] },

    maxAmountUsd: 1_000,
    maxSlippageBps: 100,

    expiresAt: NOW + 3_600,
    nonce: 1,

    status: "ACTIVE",
    usage: "REUSABLE",

    recipients: { mode: "ALLOWLIST", allow: [PAYEE], deny: [] },
    contracts: { mode: "ALLOWLIST", allow: [USDC], deny: [] },
    methods: {
      mode: "ALLOWLIST",
      allow: ["transfer(address,uint256)"],
      deny: [],
    },

    limits: {
      // 1 ETH. Deliberately explicit: the schema default is "0", which grants
      // no authority over native value at all.
      maxValueWei: "1000000000000000000",
      maxGasLimit: "500000",
      maxFeePerGasWei: "500000000000",
    },

    ...overrides,
  });
}

export function buildIntent(overrides: Partial<Intent> = {}): Intent {
  return IntentSchema.parse({
    capabilityId: CAPABILITY_ID,
    agentId: AGENT_ID,

    action: "SWAP",
    protocol: "NATIVE",
    chainId: CHAIN_ID,

    inputToken: "ETH",
    outputToken: "ETH",

    // 0.01 ETH at the static table's $3,200 is exactly $32.
    amountUsd: 32,
    slippageBps: 0,

    nonce: 1,
    timestamp: NOW,

    ...overrides,
  });
}

export type TransactionOverrides = Partial<EvmTransaction> & {
  to?: string | undefined;
};

/**
 * A canonical 0.01 ETH transfer to PAYEE.
 *
 * Gas is 21,000 and the tip is a third of the fee cap so that the *baseline*
 * transaction scores zero risk: a fixture that trips UNUSUAL_GAS_LIMIT or
 * UNUSUAL_FEE_PARAMETERS would make every escalation assertion ambiguous.
 */
export function buildTransaction(
  overrides: TransactionOverrides = {},
  identity: { agentId?: string; capabilityId?: string } = {},
): NormalizedTransaction {
  return normalizer.normalize({
    agentId: identity.agentId ?? AGENT_ID,
    capabilityId: identity.capabilityId ?? CAPABILITY_ID,
    now: NOW,
    transaction: {
      chainId: CHAIN_ID,
      to: PAYEE,
      value: "10000000000000000",
      data: "0x",
      gasLimit: "21000",
      maxFeePerGas: "30000000000",
      maxPriorityFeePerGas: "1000000000",
      nonce: 0,
      ...overrides,
    },
  });
}

/** A zero-value contract call, the shape every calldata test needs. */
export function buildCall(
  to: string,
  data: string,
  overrides: TransactionOverrides = {},
): NormalizedTransaction {
  return buildTransaction({
    to,
    value: "0",
    data,
    gasLimit: "120000",
    ...overrides,
  });
}
