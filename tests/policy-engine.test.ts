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
  const engine = new PolicyEngine();

  it("allows a valid intent", () => {
    const result = engine.evaluate(capability, validIntent, false, 1700000000);

    expect(result).toEqual({
      allowed: true,
      code: "POLICY_APPROVED",
      reason: "Intent satisfies all policy rules",
    });
  });

  it("rejects an incorrect capability ID", () => {
    const result = engine.evaluate(
      capability,
      {
        ...validIntent,
        capabilityId: "wrong-capability",
      },
      false,
      1700000000,
    );

    expect(result.code).toBe("CAPABILITY_ID_MISMATCH");
  });

  it("rejects an incorrect agent", () => {
    const result = engine.evaluate(
      capability,
      {
        ...validIntent,
        agentId: "malicious-agent",
      },
      false,
      1700000000,
    );

    expect(result.code).toBe("AGENT_MISMATCH");
  });

  it("rejects an unauthorized action", () => {
    const result = engine.evaluate(
      capability,
      {
        ...validIntent,
        action: "TRANSFER",
      },
      false,
      1700000000,
    );

    expect(result.code).toBe("ACTION_NOT_ALLOWED");
  });

  it("rejects an unauthorized protocol", () => {
    const result = engine.evaluate(
      capability,
      {
        ...validIntent,
        protocol: "UNKNOWN_PROTOCOL",
      },
      false,
      1700000000,
    );

    expect(result.code).toBe("PROTOCOL_NOT_ALLOWED");
  });

  it("rejects an unauthorized chain", () => {
    const result = engine.evaluate(
      capability,
      {
        ...validIntent,
        chainId: 1,
      },
      false,
      1700000000,
    );

    expect(result.code).toBe("CHAIN_NOT_ALLOWED");
  });

  it("rejects an unauthorized input token", () => {
    const result = engine.evaluate(
      capability,
      {
        ...validIntent,
        inputToken: "DAI",
      },
      false,
      1700000000,
    );

    expect(result.code).toBe("INPUT_TOKEN_NOT_ALLOWED");
  });

  it("rejects an unauthorized output token", () => {
    const result = engine.evaluate(
      capability,
      {
        ...validIntent,
        outputToken: "DAI",
      },
      false,
      1700000000,
    );

    expect(result.code).toBe("OUTPUT_TOKEN_NOT_ALLOWED");
  });

  it("rejects an excessive amount", () => {
    const result = engine.evaluate(
      capability,
      {
        ...validIntent,
        amountUsd: 150,
      },
      false,
      1700000000,
    );

    expect(result.code).toBe("AMOUNT_EXCEEDED");
  });

  it("rejects excessive slippage", () => {
    const result = engine.evaluate(
      capability,
      {
        ...validIntent,
        slippageBps: 300,
      },
      false,
      1700000000,
    );

    expect(result.code).toBe("SLIPPAGE_EXCEEDED");
  });

  it("rejects an invalid nonce", () => {
    const result = engine.evaluate(
      capability,
      {
        ...validIntent,
        nonce: 2,
      },
      false,
      1700000000,
    );

    expect(result.code).toBe("INVALID_NONCE");
  });

  it("rejects an expired capability", () => {
    const result = engine.evaluate(capability, validIntent, false, 2100000000);

    expect(result.code).toBe("CAPABILITY_EXPIRED");
  });

  it("rejects a revoked capability", () => {
    const result = engine.evaluate(
      {
        ...capability,
        status: "REVOKED",
      },
      validIntent,
      false,
      1700000000,
    );

    expect(result.code).toBe("CAPABILITY_REVOKED");
  });

  it("rejects a consumed capability", () => {
    const result = engine.evaluate(
      {
        ...capability,
        status: "CONSUMED",
      },
      validIntent,
      false,
      1700000000,
    );

    expect(result.code).toBe("CAPABILITY_CONSUMED");
  });

  it("rejects a replayed intent", () => {
    const result = engine.evaluate(capability, validIntent, true, 1700000000);

    expect(result.code).toBe("REPLAY_DETECTED");
  });
});
