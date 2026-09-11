import { describe, expect, it } from "vitest";
import { PolicyEngine } from "../src/policy/policy-engine";
import type { Capability } from "../src/types/capability";
import type { Intent } from "../src/types/intent";

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

const validIntent: Intent = {
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
  timestamp: 1700000000,
};

describe("Arx Policy Engine", () => {
  it("allows a valid intent", () => {
    const engine = new PolicyEngine();

    const result = engine.evaluate(capability, validIntent, 1700000000);

    expect(result.allowed).toBe(true);
  });

  it("rejects an amount above the limit", () => {
    const engine = new PolicyEngine();

    const result = engine.evaluate(
      capability,
      {
        ...validIntent,
        amountUsd: 150,
      },
      1700000000,
    );

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("amount");
  });

  it("rejects excessive slippage", () => {
    const engine = new PolicyEngine();

    const result = engine.evaluate(
      capability,
      {
        ...validIntent,
        slippageBps: 300,
      },
      1700000000,
    );

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("Slippage");
  });

  it("rejects an unauthorized protocol", () => {
    const engine = new PolicyEngine();

    const result = engine.evaluate(
      capability,
      {
        ...validIntent,
        protocol: "UNKNOWN_PROTOCOL",
      },
      1700000000,
    );

    expect(result.allowed).toBe(false);
  });

  it("rejects an unauthorized chain", () => {
    const engine = new PolicyEngine();

    const result = engine.evaluate(
      capability,
      {
        ...validIntent,
        chainId: 1,
      },
      1700000000,
    );

    expect(result.allowed).toBe(false);
  });

  it("rejects an unauthorized token", () => {
    const engine = new PolicyEngine();

    const result = engine.evaluate(
      capability,
      {
        ...validIntent,
        inputToken: "DAI",
      },
      1700000000,
    );

    expect(result.allowed).toBe(false);
  });

  it("rejects an expired capability", () => {
    const engine = new PolicyEngine();

    const result = engine.evaluate(capability, validIntent, 2100000000);

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("expired");
  });

  it("rejects an incorrect agent", () => {
    const engine = new PolicyEngine();

    const result = engine.evaluate(
      capability,
      {
        ...validIntent,
        agentId: "malicious-agent",
      },
      1700000000,
    );

    expect(result.allowed).toBe(false);
  });

  it("rejects an incorrect nonce", () => {
    const engine = new PolicyEngine();

    const result = engine.evaluate(
      capability,
      {
        ...validIntent,
        nonce: 2,
      },
      1700000000,
    );

    expect(result.allowed).toBe(false);
  });
});
