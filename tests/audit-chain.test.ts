import { beforeEach, describe, expect, it } from "bun:test";

process.env.NODE_ENV = "test";
process.env.DATABASE_PATH = "./.test-data/audit-chain.sqlite";

const { db, resetDatabaseForTests } = await import("../src/db/database");
const { AuditStore, GENESIS_HASH } = await import(
  "../src/storage/audit-store"
);

const store = new AuditStore();

describe("tamper-evident audit chain", () => {
  beforeEach(() => {
    resetDatabaseForTests();
  });

  it("starts from the genesis hash", () => {
    expect(store.head()).toEqual({ seq: 0, hash: GENESIS_HASH });
    expect(store.verifyChain()).toMatchObject({ valid: true, entries: 0 });
  });

  it("links each entry to its predecessor", () => {
    const first = store.append({ eventType: "INTENT_RECEIVED", requestId: "r1" });
    const second = store.append({ eventType: "POLICY_EVALUATED", requestId: "r1" });

    expect(first.prevHash).toBe(GENESIS_HASH);
    expect(second.prevHash).toBe(first.entryHash);
    expect(second.seq).toBe(first.seq + 1);
  });

  it("verifies an untampered chain", () => {
    for (const eventType of [
      "INTENT_RECEIVED",
      "POLICY_EVALUATED",
      "FIREWALL_CHECKED",
      "APPROVAL_CREATED",
      "SIGNING_SUCCEEDED",
    ] as const) {
      store.append({ eventType, requestId: "r1" });
    }

    const result = store.verifyChain();

    expect(result.valid).toBe(true);
    expect(result).toMatchObject({ entries: 5 });
  });

  it("detects an edited historical entry", () => {
    // The scenario that matters: an attacker with database write access tries
    // to rewrite why a transaction was allowed.
    store.append({ eventType: "INTENT_RECEIVED", requestId: "r1" });
    store.append({
      eventType: "POLICY_EVALUATED",
      requestId: "r1",
      reason: "denied: recipient not allowed",
    });
    store.append({ eventType: "SIGNING_SUCCEEDED", requestId: "r1" });

    db.run("UPDATE audit_chain SET reason = 'approved' WHERE seq = 2");

    const result = store.verifyChain();

    expect(result.valid).toBe(false);
    expect(result).toMatchObject({ brokenAtSeq: 2, problem: "HASH_MISMATCH" });
  });

  it("detects a deleted entry", () => {
    store.append({ eventType: "INTENT_RECEIVED", requestId: "r1" });
    store.append({ eventType: "POLICY_EVALUATED", requestId: "r1" });
    store.append({ eventType: "SIGNING_SUCCEEDED", requestId: "r1" });

    db.run("DELETE FROM audit_chain WHERE seq = 2");

    const result = store.verifyChain();

    expect(result.valid).toBe(false);
    expect(result).toMatchObject({ problem: "SEQUENCE_GAP" });
  });

  it("detects a re-pointed predecessor link", () => {
    store.append({ eventType: "INTENT_RECEIVED", requestId: "r1" });
    store.append({ eventType: "POLICY_EVALUATED", requestId: "r1" });

    db.run(`UPDATE audit_chain SET prev_hash = '${GENESIS_HASH}' WHERE seq = 2`);

    expect(store.verifyChain()).toMatchObject({
      valid: false,
      brokenAtSeq: 2,
      problem: "BROKEN_LINK",
    });
  });

  it("detects an entry appended with a forged hash", () => {
    // Appending is not enough: a forged entry must also carry a hash that
    // recomputes, which requires the preimage to match.
    store.append({ eventType: "INTENT_RECEIVED", requestId: "r1" });
    const head = store.head();

    db.run(
      `INSERT INTO audit_chain (seq, event_type, decision, payload, prev_hash, entry_hash, timestamp)
       VALUES (2, 'SIGNING_SUCCEEDED', 'ALLOW', 'null', '${head.hash}', '0x${"f".repeat(64)}', 1700000000)`,
    );

    expect(store.verifyChain()).toMatchObject({
      valid: false,
      brokenAtSeq: 2,
      problem: "HASH_MISMATCH",
    });
  });

  it("retrieves the ordered trail for one request", () => {
    store.append({ eventType: "INTENT_RECEIVED", requestId: "r1" });
    store.append({ eventType: "INTENT_RECEIVED", requestId: "r2" });
    store.append({ eventType: "POLICY_EVALUATED", requestId: "r1" });

    const trail = store.byRequest("r1");

    expect(trail).toHaveLength(2);
    expect(trail[0]!.seq).toBeLessThan(trail[1]!.seq);
  });

  it("preserves the payload through a round trip", () => {
    const payload = { declaredAmountUsd: 10, nested: { a: [1, 2, 3] } };
    store.append({ eventType: "POLICY_EVALUATED", requestId: "r1", payload });

    expect(store.list(1)[0]!.payload).toEqual(payload);
    expect(store.verifyChain().valid).toBe(true);
  });

  it("stays verifiable across many appends", () => {
    for (let i = 0; i < 200; i += 1) {
      store.append({
        eventType: "POLICY_EVALUATED",
        requestId: `r${i}`,
        payload: { i },
      });
    }

    expect(store.verifyChain()).toMatchObject({ valid: true, entries: 200 });
  });
});
