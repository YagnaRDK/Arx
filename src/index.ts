import { PolicyEngine } from "./policy/policy-engine";
import type { Capability } from "./types/capability";
import type { Intent } from "./types/intent";

const capability: Capability = {
  capabilityId: "cap-001",
  agentId: "agent-001",

  allowedActions: ["SWAP"],
  allowedProtocols: ["UNISWAP"],
  allowedChains: [11155111],

  allowedTokens: {
    input: ["USDC"],
    output: ["WETH"],
  },

  maxAmountUsd: 100,
  maxSlippageBps: 200,

  expiresAt: 2000000000,
  nonce: 1,

  status: "ACTIVE",
  usage: "REUSABLE",
};

const intent: Intent = {
  capabilityId: "cap-001",
  agentId: "agent-001",

  action: "SWAP",
  protocol: "UNISWAP",
  chainId: 11155111,

  inputToken: "USDC",
  outputToken: "WETH",

  amountUsd: 50,
  slippageBps: 100,

  nonce: 1,
  timestamp: Math.floor(Date.now() / 1000),
};

const engine = new PolicyEngine();

const result = engine.evaluate(capability, intent);

console.log("Policy Decision:");
console.log(result);
