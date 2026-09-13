/**
 * The demo world: agents, addresses, capabilities, and transaction builders.
 *
 * Everything here is fixed data. No network call, no random address, no API key
 * — a clean clone produces the same scenario inputs on every run, which is what
 * lets the suite assert exact decision codes instead of merely printing what
 * happened.
 */

import type { Capability } from "../../src/types/capability";
import type { EvmTransaction } from "../../src/types/transaction";
import type { Intent } from "../../src/types/intent";

export const CHAIN_ID = 11_155_111; // Sepolia
export const WRONG_CHAIN_ID = 1;

export const AGENT_ID = "agent-treasury-bot";

/**
 * Addresses are hand-picked so that the address-poisoning scenario is visually
 * convincing: `poisonedTreasury` shares the first and last four hex characters
 * with `treasury`, which is exactly the shape of a real poisoning attack against
 * a human skimming a truncated address on a device screen.
 */
export const ADDRESS = {
  treasury: "0x1111111111111111111111111111111111111111",
  vendor: "0x2222222222222222222222222222222222222222",
  spender: "0x3333333333333333333333333333333333333333",
  attacker: "0xbad0bad0bad0bad0bad0bad0bad0bad0bad0bad0",
  poisonedTreasury: "0x1111aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1111",
  /** Sepolia USDC. Allowlisted as a contract the agent may call. */
  usdc: "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238",
} as const;

export const SELECTOR = {
  transfer: "0xa9059cbb",
  approve: "0x095ea7b3",
} as const;

export const MAX_UINT256 = 2n ** 256n - 1n;

const GWEI = 1_000_000_000n;
const ETH = 10n ** 18n;

function hex32(value: string | bigint): string {
  const raw =
    typeof value === "bigint"
      ? value.toString(16)
      : value.replace(/^0x/, "").toLowerCase();

  if (raw.length > 64) {
    throw new Error(`Value does not fit in 32 bytes: ${raw}`);
  }

  return raw.padStart(64, "0");
}

/** ERC-20 `transfer(address,uint256)` calldata, encoded by hand so the demo can
 * print the exact byte layout it is asking Arx to inspect. */
export function encodeErc20Transfer(to: string, amount: bigint): string {
  return `${SELECTOR.transfer}${hex32(to)}${hex32(amount)}`;
}

/** ERC-20 `approve(address,uint256)` calldata. */
export function encodeErc20Approve(spender: string, amount: bigint): string {
  return `${SELECTOR.approve}${hex32(spender)}${hex32(amount)}`;
}

/** Splits calldata into selector and 32-byte words for display. */
export function describeCalldata(data: string): string[] {
  const body = data.replace(/^0x/, "");

  if (body.length < 8) {
    return [data === "0x" ? "0x (empty — native value transfer)" : data];
  }

  const lines = [`selector  0x${body.slice(0, 8)}`];

  for (let offset = 8, index = 0; offset < body.length; offset += 64, index++) {
    lines.push(`arg[${index}]    0x${body.slice(offset, offset + 64)}`);
  }

  return lines;
}

/** USD -> wei at a given ETH price, at six decimal places of ETH precision. */
export function weiForUsd(usd: number, ethUsd: number): string {
  if (!(ethUsd > 0)) {
    throw new Error("ETH price must be positive");
  }

  const microEth = BigInt(Math.max(1, Math.round((usd / ethUsd) * 1e6)));

  return (microEth * 10n ** 12n).toString();
}

export function usdForWei(wei: string, ethUsd: number): number {
  return (Number(BigInt(wei) / 10n ** 12n) / 1e6) * ethUsd;
}

export function ethToWei(eth: number): string {
  return (BigInt(Math.round(eth * 1e6)) * 10n ** 12n).toString();
}

// --- Transactions ----------------------------------------------------------

export type TxOverrides = Partial<EvmTransaction>;

/** A native-value transfer. 21000 gas, 30 gwei — inside the default ceilings. */
export function nativeTransfer(
  to: string,
  valueWei: string,
  overrides: TxOverrides = {},
): EvmTransaction {
  return {
    chainId: CHAIN_ID,
    to,
    value: valueWei,
    data: "0x",
    gasLimit: "21000",
    maxFeePerGas: (30n * GWEI).toString(),
    maxPriorityFeePerGas: (2n * GWEI).toString(),
    nonce: 0,
    type: "eip1559",
    ...overrides,
  };
}

/** A contract call. Native value is zero: the payload is the whole payload. */
export function contractCall(
  to: string,
  data: string,
  overrides: TxOverrides = {},
): EvmTransaction {
  return {
    chainId: CHAIN_ID,
    to,
    value: "0",
    data,
    gasLimit: "120000",
    maxFeePerGas: (30n * GWEI).toString(),
    maxPriorityFeePerGas: (2n * GWEI).toString(),
    nonce: 0,
    type: "eip1559",
    ...overrides,
  };
}

// --- Intents ---------------------------------------------------------------

export type IntentInput = {
  capabilityId: string;
  nonce: number;
  timestamp: number;
  amountUsd: number;
  transaction?: EvmTransaction;
  agentId?: string;
  action?: string;
  protocol?: string;
  chainId?: number;
  inputToken?: string;
  outputToken?: string;
  slippageBps?: number;
  ttlSeconds?: number;
  intentId?: string;
};

export function buildIntent(input: IntentInput): Intent {
  return {
    capabilityId: input.capabilityId,
    agentId: input.agentId ?? AGENT_ID,
    action: input.action ?? "transfer",
    protocol: input.protocol ?? "native",
    chainId: input.chainId ?? CHAIN_ID,
    inputToken: input.inputToken ?? "ETH",
    outputToken: input.outputToken ?? "ETH",
    amountUsd: input.amountUsd,
    slippageBps: input.slippageBps ?? 0,
    nonce: input.nonce,
    timestamp: input.timestamp,
    ...(input.ttlSeconds === undefined ? {} : { ttlSeconds: input.ttlSeconds }),
    ...(input.intentId === undefined ? {} : { intentId: input.intentId }),
    ...(input.transaction === undefined
      ? {}
      : { transaction: input.transaction }),
  };
}

// --- Capabilities ----------------------------------------------------------

/**
 * Why several of these set deliberately loose ceilings.
 *
 * Each scenario isolates one control. A capability used to demonstrate calldata
 * smuggling must not trip the USD window limit first, or the demo would prove
 * the wrong thing. So every capability below is least-privilege in the dimension
 * its scenario is about and generous in the others, and the dimension under test
 * is stated in `label`.
 *
 * `valueToleranceBps` is the clearest example: most capabilities set it wide,
 * because the demo cannot know what ETH price the server's oracle reports. The
 * declared-value-lie capability sets the production-shaped 500 bps, and the lie
 * it catches is six orders of magnitude — no price assumption can rescue it.
 */
export type CapabilitySeed = Capability & { capabilityId: string };

const WIDE_WINDOW = {
  maxAmountUsdPerWindow: 100_000_000,
  windowSeconds: 86_400,
  maxTxPerWindow: 10_000,
};

function baseCapability(
  capabilityId: string,
  expiresAt: number,
  overrides: Partial<Capability> = {},
): CapabilitySeed {
  const capability: Capability = {
    capabilityId,
    agentId: AGENT_ID,

    allowedActions: ["transfer", "payment", "approve"],
    allowedProtocols: ["native", "erc20"],
    allowedChains: [CHAIN_ID],
    allowedTokens: {
      input: ["ETH", "USDC"],
      output: ["ETH", "USDC"],
    },

    maxAmountUsd: 5_000_000,
    maxSlippageBps: 50,

    expiresAt,
    nonce: 1,

    status: "ACTIVE",
    usage: "REUSABLE",

    recipients: {
      mode: "ALLOWLIST",
      allow: [ADDRESS.treasury, ADDRESS.vendor],
      deny: [],
    },
    contracts: {
      mode: "ALLOWLIST",
      allow: [ADDRESS.usdc],
      deny: [],
    },
    methods: {
      mode: "ALLOWLIST",
      allow: [
        "transfer(address,uint256)",
        SELECTOR.transfer,
        "approve(address,uint256)",
        SELECTOR.approve,
      ],
      deny: [],
    },

    limits: {
      maxValueWei: (1_000n * ETH).toString(),
      maxGasLimit: "500000",
      maxFeePerGasWei: (500n * GWEI).toString(),
      ...WIDE_WINDOW,
    },

    humanApproval: {
      requiredAboveUsd: 1_000,
      requiredForUnknownRecipient: true,
      requiredForMethods: [],
      // 100 means "only a maximal score escalates", so a risk signal cannot
      // turn a scenario about some other control into an escalation.
      requiredAboveRiskScore: 100,
      alwaysRequired: false,
    },

    maxRiskScore: 100,
    allowContractCreation: false,
    valueToleranceBps: 1_000_000,

    label: "Demo capability",
    ...overrides,
  };

  return capability as CapabilitySeed;
}

export type SeedSet = {
  payments: CapabilitySeed;
  highValue: CapabilitySeed;
  tokenOps: CapabilitySeed;
  valueBinding: CapabilitySeed;
  spendWindow: CapabilitySeed;
  revocable: CapabilitySeed;
  poisoning: CapabilitySeed;
  expired: CapabilitySeed;
};

/**
 * @param tag suffix that keeps capability ids unique per run, so a second run
 *   against a persistent database is not a nonce replay of the first.
 * @param now injected so the seed set is a pure function of its inputs.
 */
export function buildSeedSet(tag: string, now: number): SeedSet {
  const day = now + 86_400;

  return {
    payments: baseCapability(`cap-payments-${tag}`, day, {
      label: "Treasury payments — allowlisted recipients, <$1k autonomous",
      limits: {
        maxValueWei: (10n * ETH).toString(),
        maxGasLimit: "500000",
        maxFeePerGasWei: (500n * GWEI).toString(),
        ...WIDE_WINDOW,
      },
    }),

    highValue: baseCapability(`cap-highvalue-${tag}`, day, {
      label: "High-value payments — escalates above $50 to a human",
      humanApproval: {
        requiredAboveUsd: 50,
        requiredForUnknownRecipient: true,
        requiredForMethods: [],
        requiredAboveRiskScore: 100,
        alwaysRequired: false,
      },
      limits: {
        maxValueWei: (10_000n * ETH).toString(),
        maxGasLimit: "500000",
        maxFeePerGasWei: (500n * GWEI).toString(),
        ...WIDE_WINDOW,
      },
    }),

    tokenOps: baseCapability(`cap-tokenops-${tag}`, day, {
      label:
        "ERC-20 operations — may call USDC, may not move native value",
      allowedProtocols: ["erc20"],
      // The spender is allowlisted deliberately. The unlimited-approval
      // scenario is about the *amount*, and an unlisted spender would be
      // refused one check earlier by the calldata recipient rule — proving a
      // different control than the one under test.
      recipients: {
        mode: "ALLOWLIST",
        allow: [ADDRESS.treasury, ADDRESS.vendor, ADDRESS.spender],
        deny: [],
      },
      // Zero native value is the least-privilege position for a token-only
      // grant: every authorised action is a contract call, so any native value
      // in the transaction is out of scope by construction.
      limits: {
        maxValueWei: "0",
        maxGasLimit: "500000",
        maxFeePerGasWei: (500n * GWEI).toString(),
        ...WIDE_WINDOW,
      },
      humanApproval: {
        requiredAboveUsd: 0,
        requiredForUnknownRecipient: true,
        requiredForMethods: [],
        requiredAboveRiskScore: 100,
        alwaysRequired: false,
      },
    }),

    valueBinding: baseCapability(`cap-valuebind-${tag}`, day, {
      label:
        "Value binding — production-shaped 5% tolerance on declared USD",
      valueToleranceBps: 500,
      limits: {
        maxValueWei: (5_000n * ETH).toString(),
        maxGasLimit: "500000",
        maxFeePerGasWei: (500n * GWEI).toString(),
        ...WIDE_WINDOW,
      },
      humanApproval: {
        requiredAboveUsd: 0,
        requiredForUnknownRecipient: true,
        requiredForMethods: [],
        requiredAboveRiskScore: 100,
        alwaysRequired: false,
      },
    }),

    spendWindow: baseCapability(`cap-spendwindow-${tag}`, day, {
      label: "Daily budget — $300 per 24h rolling window",
      limits: {
        maxValueWei: (1_000n * ETH).toString(),
        maxGasLimit: "500000",
        maxFeePerGasWei: (500n * GWEI).toString(),
        maxAmountUsdPerWindow: 300,
        windowSeconds: 86_400,
        maxTxPerWindow: 100,
      },
      humanApproval: {
        requiredAboveUsd: 0,
        requiredForUnknownRecipient: true,
        requiredForMethods: [],
        requiredAboveRiskScore: 100,
        alwaysRequired: false,
      },
    }),

    revocable: baseCapability(`cap-revocable-${tag}`, day, {
      label: "Revocation drill — revoked while an approval is in flight",
    }),

    poisoning: baseCapability(`cap-poisoning-${tag}`, day, {
      label: "Address poisoning drill — single allowlisted recipient",
      recipients: {
        mode: "ALLOWLIST",
        allow: [ADDRESS.treasury],
        deny: [],
      },
    }),

    /** Already expired at seed time. Invariant 6 in one request. */
    expired: baseCapability(`cap-expired-${tag}`, Math.max(1, now - 3_600), {
      label: "Expired grant — authority lapsed one hour ago",
    }),
  };
}

export function seedList(set: SeedSet): CapabilitySeed[] {
  return Object.values(set);
}
