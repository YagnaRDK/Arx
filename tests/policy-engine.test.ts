import { describe, expect, it } from "bun:test";

import { PolicyEngine } from "../src/policy/policy-engine";
import { CapabilitySchema, type Capability } from "../src/types/capability";
import { IntentSchema, type Intent } from "../src/types/intent";

const NOW = 1_700_000_000;

/**
 * Built through the schema rather than as a literal, so these tests exercise the
 * same fail-closed defaults a capability created over the API would get.
 */
const capability: Capability = CapabilitySchema.parse({
  capabilityId: "cap-001",
  agentId: "agent-001",

  allowedActions: ["SWAP"],
  allowedProtocols: ["UNISWAP"],
  allowedChains: [11155111],

  allowedTokens: { input: ["USDC"], output: ["WETH"] },

  maxAmountUsd: 100,
  maxSlippageBps: 200,

  expiresAt: 2_000_000_000,
  nonce: 1,

  status: "ACTIVE",
  usage: "REUSABLE",
});

const validIntent: Intent = IntentSchema.parse({
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
  timestamp: NOW,
});

const engine = new PolicyEngine();

function evaluate(
  overrides: Partial<Intent> = {},
  capabilityOverrides: Partial<Capability> = {},
  context: Parameters<PolicyEngine["evaluate"]>[2] = false,
  now = NOW,
) {
  return engine.evaluate(
    { ...capability, ...capabilityOverrides },
    { ...validIntent, ...overrides },
    context,
    now,
  );
}

describe("Arx policy engine", () => {
  it("allows an intent inside the granted authority", () => {
    const result = evaluate();

    expect(result.allowed).toBe(true);
    expect(result.code).toBe("POLICY_APPROVED");
    expect(result.decision).toBe("ALLOW");
  });

  describe("capability binding", () => {
    it("rejects a mismatched capability ID", () => {
      expect(evaluate({ capabilityId: "wrong-capability" }).code).toBe(
        "CAPABILITY_ID_MISMATCH",
      );
    });

    it("rejects a different agent using the capability", () => {
      expect(evaluate({ agentId: "malicious-agent" }).code).toBe(
        "AGENT_MISMATCH",
      );
    });
  });

  describe("capability lifecycle", () => {
    it("rejects a revoked capability", () => {
      expect(evaluate({}, { status: "REVOKED" }).code).toBe(
        "CAPABILITY_REVOKED",
      );
    });

    it("rejects a consumed capability", () => {
      expect(evaluate({}, { status: "CONSUMED" }).code).toBe(
        "CAPABILITY_CONSUMED",
      );
    });

    it("rejects an expired capability", () => {
      expect(evaluate({}, {}, false, 2_100_000_000).code).toBe(
        "CAPABILITY_EXPIRED",
      );
    });

    it("rejects a capability that is not yet valid", () => {
      expect(evaluate({}, { notBefore: NOW + 60 }).code).toBe(
        "CAPABILITY_NOT_YET_VALID",
      );
    });

    it("allows a capability once notBefore has passed", () => {
      expect(evaluate({}, { notBefore: NOW - 1 }).allowed).toBe(true);
    });

    it("rejects at the exact expiry second", () => {
      // Expiry is inclusive: at expiresAt the grant is already over.
      expect(
        evaluate({}, { expiresAt: NOW }, false, NOW).code,
      ).toBe("CAPABILITY_EXPIRED");
      expect(evaluate({}, { expiresAt: NOW + 1 }, false, NOW).allowed).toBe(
        true,
      );
    });
  });

  describe("scope", () => {
    it("rejects an action outside the grant", () => {
      expect(evaluate({ action: "TRANSFER" }).code).toBe("ACTION_NOT_ALLOWED");
    });

    it("rejects a protocol outside the grant", () => {
      expect(evaluate({ protocol: "UNKNOWN_PROTOCOL" }).code).toBe(
        "PROTOCOL_NOT_ALLOWED",
      );
    });

    it("rejects a chain outside the grant", () => {
      expect(evaluate({ chainId: 1 }).code).toBe("CHAIN_NOT_ALLOWED");
    });

    it("rejects an input token outside the grant", () => {
      expect(evaluate({ inputToken: "DAI" }).code).toBe(
        "INPUT_TOKEN_NOT_ALLOWED",
      );
    });

    it("rejects an output token outside the grant", () => {
      expect(evaluate({ outputToken: "DAI" }).code).toBe(
        "OUTPUT_TOKEN_NOT_ALLOWED",
      );
    });
  });

  describe("ceilings", () => {
    it("rejects an amount above the limit", () => {
      expect(evaluate({ amountUsd: 150 }).code).toBe("AMOUNT_EXCEEDED");
    });

    it("allows an amount exactly at the limit", () => {
      expect(evaluate({ amountUsd: 100 }).allowed).toBe(true);
    });

    it("rejects an amount one cent over the limit", () => {
      expect(evaluate({ amountUsd: 100.01 }).code).toBe("AMOUNT_EXCEEDED");
    });

    it("rejects slippage above the limit", () => {
      expect(evaluate({ slippageBps: 300 }).code).toBe("SLIPPAGE_EXCEEDED");
    });

    it("allows slippage exactly at the limit", () => {
      expect(evaluate({ slippageBps: 200 }).allowed).toBe(true);
    });
  });

  describe("nonce semantics", () => {
    // The nonce floor and the per-action counter are deliberately separate
    // concerns. Conflating them was the original design flaw: it made a
    // reusable capability single-use in practice.

    it("rejects a nonce below the capability's floor", () => {
      expect(evaluate({ nonce: 0 }).code).toBe("INVALID_NONCE");
    });

    it("allows a nonce above the floor on a reusable capability", () => {
      // The point of the redesign: a reusable grant keeps authorizing new
      // actions rather than being exhausted by its first one.
      expect(evaluate({ nonce: 7 }).allowed).toBe(true);
    });

    it("rejects a nonce that was already used", () => {
      expect(evaluate({ nonce: 5 }, {}, { isReplay: true }).code).toBe(
        "REPLAY_DETECTED",
      );
    });

    it("requires a strictly increasing nonce", () => {
      // An unused nonce below the high-water mark is still refused, so an
      // intent captured off the wire cannot be held and replayed later.
      expect(
        evaluate({ nonce: 4 }, {}, { highestAcceptedNonce: 9 }).code,
      ).toBe("NONCE_REUSED");
      expect(
        evaluate({ nonce: 9 }, {}, { highestAcceptedNonce: 9 }).code,
      ).toBe("NONCE_REUSED");
      expect(
        evaluate({ nonce: 10 }, {}, { highestAcceptedNonce: 9 }).allowed,
      ).toBe(true);
    });

    it("accepts only the floor nonce on a single-use capability", () => {
      const single = { usage: "SINGLE_USE" as const };

      expect(evaluate({ nonce: 1 }, single).allowed).toBe(true);
      expect(evaluate({ nonce: 2 }, single).code).toBe("INVALID_NONCE");
    });
  });

  describe("freshness", () => {
    it("rejects a timestamp beyond the skew tolerance", () => {
      expect(
        evaluate({ timestamp: NOW + 4000 }, {}, { maxClockSkewSeconds: 300 })
          .code,
      ).toBe("INTENT_TIMESTAMP_SKEWED");
    });

    it("tolerates a timestamp inside the skew window", () => {
      expect(
        evaluate({ timestamp: NOW + 100 }, {}, { maxClockSkewSeconds: 300 })
          .allowed,
      ).toBe(true);
    });

    it("rejects an intent past its own TTL", () => {
      expect(
        evaluate({ timestamp: NOW - 600, ttlSeconds: 60 }).code,
      ).toBe("INTENT_EXPIRED");
    });

    it("allows an intent inside its TTL", () => {
      expect(
        evaluate({ timestamp: NOW - 30, ttlSeconds: 60 }).allowed,
      ).toBe(true);
    });
  });

  describe("determinism", () => {
    it("returns an identical decision for identical inputs", () => {
      // Reproducibility is what makes an audit record meaningful: a recorded
      // decision must be re-derivable from the recorded inputs.
      const first = evaluate({ nonce: 3 });
      const second = evaluate({ nonce: 3 });

      expect(first).toEqual(second);
    });

    it("accepts the legacy boolean third argument", () => {
      expect(engine.evaluate(capability, validIntent, true, NOW).code).toBe(
        "REPLAY_DETECTED",
      );
    });
  });
});
