import { describe, expect, it } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { CapabilityBroker, capabilityPolicyHash } from "../src/broker/capability-broker";
import { SealedSecretStore } from "../src/broker/sealed-secret-store";
import { ArxError } from "../src/core/errors";
import { CapabilitySchema, type Capability } from "../src/types/capability";

const NOW = 1_700_000_000;

function makeCapability(overrides: Record<string, unknown> = {}): Capability {
  return CapabilitySchema.parse({
    capabilityId: "cap-broker",
    agentId: "agent-1",
    allowedActions: ["CALL_API"],
    allowedProtocols: ["HTTP"],
    allowedChains: [11155111],
    allowedTokens: { input: ["USDC"], output: ["USDC"] },
    maxAmountUsd: 10,
    maxSlippageBps: 0,
    expiresAt: NOW + 86_400,
    nonce: 0,
    status: "ACTIVE",
    usage: "REUSABLE",
    ...overrides,
  });
}

/**
 * Forces the local-dev seal backend so these tests run with no Ledger device.
 * The distinction is asserted explicitly below: a local seal must never report
 * itself as hardware-rooted.
 */
function makeBroker() {
  const dir = mkdtempSync(join(tmpdir(), "arx-broker-"));

  const store = new SealedSecretStore({
    path: join(dir, "sealed.json"),
    localPassphrase: "test-passphrase-not-a-real-secret",
  });

  return { broker: new CapabilityBroker(store), store };
}

describe("capability broker", () => {
  it("seals a secret without retaining its plaintext", async () => {
    const { store } = makeBroker();
    await store.seal({ name: "upstream-api-key", secret: "sk-live-abc123" });

    const listed = store.list();

    expect(listed).toHaveLength(1);
    expect(JSON.stringify(listed)).not.toContain("sk-live-abc123");
    // Metadata deliberately excludes ciphertext as well as plaintext.
    expect(Object.keys(listed[0]!)).not.toContain("ciphertext");
  });

  it("round-trips a sealed secret", async () => {
    const { store } = makeBroker();
    await store.seal({ name: "k", secret: "sk-live-abc123" });

    const unsealed = await store.unseal("k");

    expect(unsealed.secret).toBe("sk-live-abc123");
  });

  it("reports a local seal as not hardware-rooted", async () => {
    // The whole point of the label: a development seal must never be mistaken
    // for a Key Ring seal.
    const { store } = makeBroker();
    await store.seal({ name: "k", secret: "s" });

    const unsealed = await store.unseal("k");

    expect(unsealed.backend).toBe("local-dev");
    expect(unsealed.hardwareRooted).toBe(false);
  });

  it("issues a token that contains no secret material", async () => {
    const { broker, store } = makeBroker();
    await store.seal({ name: "upstream-api-key", secret: "sk-live-abc123" });

    const issued = broker.issue({
      capability: makeCapability(),
      grants: ["upstream-api-key"],
      now: NOW,
    });

    expect(JSON.stringify(issued)).not.toContain("sk-live-abc123");
    expect(issued.token.grants).toEqual(["upstream-api-key"]);
  });

  it("refuses to grant a secret that does not exist", () => {
    const { broker } = makeBroker();

    expect(() =>
      broker.issue({
        capability: makeCapability(),
        grants: ["nonexistent"],
        now: NOW,
      }),
    ).toThrow(ArxError);
  });

  it("uses a secret without returning it to the caller", async () => {
    const { broker, store } = makeBroker();
    await store.seal({ name: "k", secret: "sk-live-abc123" });

    const issued = broker.issue({
      capability: makeCapability(),
      grants: ["k"],
      now: NOW,
    });

    const { result, provenance } = await broker.withSecret({
      bearer: issued.bearer,
      capability: makeCapability(),
      secretName: "k",
      // A realistic use: the secret authenticates a call, and only the call's
      // outcome flows back to the agent.
      use: async (secret) => ({ authorized: secret.startsWith("sk-live") }),
      now: NOW,
    });

    expect(result).toEqual({ authorized: true });
    expect(JSON.stringify(result)).not.toContain("sk-live-abc123");
    expect(provenance.hardwareRooted).toBe(false);
  });

  it("refuses a secret the token does not grant", async () => {
    const { broker, store } = makeBroker();
    await store.seal({ name: "granted", secret: "a" });
    await store.seal({ name: "ungranted", secret: "b" });

    const issued = broker.issue({
      capability: makeCapability(),
      grants: ["granted"],
      now: NOW,
    });

    await expect(
      broker.withSecret({
        bearer: issued.bearer,
        capability: makeCapability(),
        secretName: "ungranted",
        use: async (secret) => secret,
        now: NOW,
      }),
    ).rejects.toThrow(ArxError);
  });

  describe("token validation fails closed", () => {
    it("rejects a malformed bearer", () => {
      const { broker } = makeBroker();

      expect(() =>
        broker.verify({ bearer: "garbage", capability: makeCapability(), now: NOW }),
      ).toThrow(ArxError);
    });

    it("rejects an unknown token id", () => {
      const { broker } = makeBroker();

      expect(() =>
        broker.verify({
          bearer: `arx_ct_${"0".repeat(36)}_${"a".repeat(32)}`,
          capability: makeCapability(),
          now: NOW,
        }),
      ).toThrow(ArxError);
    });

    it("rejects a tampered checksum", async () => {
      const { broker, store } = makeBroker();
      await store.seal({ name: "k", secret: "s" });

      const issued = broker.issue({
        capability: makeCapability(),
        grants: ["k"],
        now: NOW,
      });

      const parts = issued.bearer.split("_");
      const tampered = `${parts[0]}_${parts[1]}_${parts[2]}_${"f".repeat(32)}`;

      expect(() =>
        broker.verify({ bearer: tampered, capability: makeCapability(), now: NOW }),
      ).toThrow(ArxError);
    });

    it("rejects an expired token", async () => {
      const { broker, store } = makeBroker();
      await store.seal({ name: "k", secret: "s" });

      const issued = broker.issue({
        capability: makeCapability(),
        grants: ["k"],
        ttlSeconds: 60,
        now: NOW,
      });

      expect(() =>
        broker.verify({
          bearer: issued.bearer,
          capability: makeCapability(),
          now: NOW + 61,
        }),
      ).toThrow(ArxError);
    });

    it("never issues a token outliving its capability", async () => {
      const { broker, store } = makeBroker();
      await store.seal({ name: "k", secret: "s" });

      const issued = broker.issue({
        capability: makeCapability({ expiresAt: NOW + 30 }),
        grants: ["k"],
        ttlSeconds: 3600,
        now: NOW,
      });

      expect(issued.token.expiresAt).toBe(NOW + 30);
    });

    it("rejects a token once the capability is revoked", async () => {
      const { broker, store } = makeBroker();
      await store.seal({ name: "k", secret: "s" });

      const issued = broker.issue({
        capability: makeCapability(),
        grants: ["k"],
        now: NOW,
      });

      expect(() =>
        broker.verify({
          bearer: issued.bearer,
          capability: makeCapability({ status: "REVOKED" }),
          now: NOW,
        }),
      ).toThrow(ArxError);
    });

    it("rejects a token after the policy is narrowed", async () => {
      // Authority must not outlive the policy that justified it: tightening the
      // spend limit invalidates tokens minted under the looser one.
      const { broker, store } = makeBroker();
      await store.seal({ name: "k", secret: "s" });

      const issued = broker.issue({
        capability: makeCapability({ maxAmountUsd: 10 }),
        grants: ["k"],
        now: NOW,
      });

      expect(() =>
        broker.verify({
          bearer: issued.bearer,
          capability: makeCapability({ maxAmountUsd: 5 }),
          now: NOW,
        }),
      ).toThrow(ArxError);
    });

    it("rejects a token presented for another agent's capability", async () => {
      const { broker, store } = makeBroker();
      await store.seal({ name: "k", secret: "s" });

      const issued = broker.issue({
        capability: makeCapability(),
        grants: ["k"],
        now: NOW,
      });

      expect(() =>
        broker.verify({
          bearer: issued.bearer,
          capability: makeCapability({ capabilityId: "cap-other" }),
          now: NOW,
        }),
      ).toThrow(ArxError);
    });

    it("rejects a revoked token", async () => {
      const { broker, store } = makeBroker();
      await store.seal({ name: "k", secret: "s" });

      const issued = broker.issue({
        capability: makeCapability(),
        grants: ["k"],
        now: NOW,
      });

      expect(broker.revoke(issued.token.tokenId)).toBe(true);
      expect(() =>
        broker.verify({ bearer: issued.bearer, capability: makeCapability(), now: NOW }),
      ).toThrow(ArxError);
    });
  });

  describe("policy hash", () => {
    it("is stable for an unchanged policy", () => {
      expect(capabilityPolicyHash(makeCapability())).toBe(
        capabilityPolicyHash(makeCapability()),
      );
    });

    it("ignores cosmetic changes", () => {
      // A relabelled capability grants exactly the same authority, so live
      // tokens should survive the edit.
      expect(capabilityPolicyHash(makeCapability({ label: "Payments" }))).toBe(
        capabilityPolicyHash(makeCapability({ label: "Payments v2" })),
      );
    });

    it("changes when authority changes", () => {
      const base = capabilityPolicyHash(makeCapability());

      expect(capabilityPolicyHash(makeCapability({ maxAmountUsd: 11 }))).not.toBe(base);
      expect(
        capabilityPolicyHash(
          makeCapability({ recipients: { mode: "ANY", allow: [], deny: [] } }),
        ),
      ).not.toBe(base);
      expect(
        capabilityPolicyHash(makeCapability({ allowContractCreation: true })),
      ).not.toBe(base);
    });

    it("is insensitive to list ordering", () => {
      expect(
        capabilityPolicyHash(makeCapability({ allowedChains: [1, 11155111] })),
      ).toBe(capabilityPolicyHash(makeCapability({ allowedChains: [11155111, 1] })));
    });
  });
});
