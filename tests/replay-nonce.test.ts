import { beforeEach, describe, expect, it } from "bun:test";

/*
 * Replay control.
 *
 * Two separate questions, and conflating them was the original design flaw:
 *
 *   capability.nonce — a floor. The lowest nonce this grant will ever accept.
 *   intent.nonce     — a per-action counter. Strictly increasing, never reused.
 *
 * On top of both sits request idempotency, which answers a third question: is
 * this the *same* action arriving twice, or a different action wearing a used
 * identifier? A system that cannot tell those apart either pays twice or
 * refuses legitimate retries.
 */
process.env.NODE_ENV = "test";
process.env.DATABASE_PATH ??= "./.test-data/arx-suite.sqlite";

const { resetDatabaseForTests } = await import("../src/db/database");
const { ReplayStore } = await import("../src/storage/replay-store");
const { IdempotencyStore, hashIntentBody } = await import(
  "../src/storage/idempotency-store"
);
const { checkNonce, checkTimestamp } = await import("../src/policy/nonce");
const { intentIdentityPayload } = await import("../src/types/intent");
const { buildCapability, buildIntent, CAPABILITY_ID, AGENT_ID, NOW } =
  await import("./helpers/fixtures");

const replayStore = new ReplayStore();
const idempotencyStore = new IdempotencyStore();

beforeEach(() => {
  resetDatabaseForTests();
});

describe("nonce admissibility: the floor", () => {
  const capability = buildCapability({ nonce: 5, usage: "REUSABLE" });

  it("refuses a nonce below the floor", () => {
    expect(
      checkNonce({
        capability,
        nonce: 4,
        highestAccepted: null,
        alreadyUsed: false,
      }),
    ).toMatchObject({ ok: false, code: "INVALID_NONCE" });
  });

  it("accepts a nonce exactly at the floor", () => {
    expect(
      checkNonce({
        capability,
        nonce: 5,
        highestAccepted: null,
        alreadyUsed: false,
      }).ok,
    ).toBe(true);
  });

  it("accepts a nonce well above the floor on a reusable capability", () => {
    // The point of separating the two concerns: a reusable grant keeps
    // authorizing new actions instead of being exhausted by its first one.
    expect(
      checkNonce({
        capability,
        nonce: 5_000,
        highestAccepted: null,
        alreadyUsed: false,
      }).ok,
    ).toBe(true);
  });

  it("retires every outstanding lower nonce when the floor is raised", () => {
    const raised = buildCapability({ nonce: 100, usage: "REUSABLE" });

    expect(
      checkNonce({
        capability: raised,
        nonce: 99,
        highestAccepted: 50,
        alreadyUsed: false,
      }),
    ).toMatchObject({ ok: false, code: "INVALID_NONCE" });
  });
});

describe("nonce admissibility: strict increase", () => {
  const capability = buildCapability({ nonce: 1, usage: "REUSABLE" });

  it("refuses a nonce equal to the high-water mark", () => {
    expect(
      checkNonce({
        capability,
        nonce: 9,
        highestAccepted: 9,
        alreadyUsed: false,
      }),
    ).toMatchObject({ ok: false, code: "NONCE_REUSED" });
  });

  it("refuses an unused nonce below the high-water mark", () => {
    // Strict increase rather than merely "not previously seen": an intent
    // captured off the wire cannot be held and replayed later once the counter
    // has moved past it, even though its own nonce was never spent.
    expect(
      checkNonce({
        capability,
        nonce: 4,
        highestAccepted: 9,
        alreadyUsed: false,
      }),
    ).toMatchObject({ ok: false, code: "NONCE_REUSED" });
  });

  it("accepts the next nonce above the high-water mark", () => {
    expect(
      checkNonce({
        capability,
        nonce: 10,
        highestAccepted: 9,
        alreadyUsed: false,
      }).ok,
    ).toBe(true);
  });

  it("reports a spent nonce as a replay, distinctly from a low one", () => {
    // The codes matter: an operator reading the log has to be able to tell a
    // replayed intent from a misconfigured client.
    expect(
      checkNonce({
        capability,
        nonce: 10,
        highestAccepted: 9,
        alreadyUsed: true,
      }),
    ).toMatchObject({ ok: false, code: "REPLAY_DETECTED" });
  });
});

describe("nonce admissibility: single-use capabilities", () => {
  const capability = buildCapability({ nonce: 7, usage: "SINGLE_USE" });

  it("accepts only the floor nonce", () => {
    expect(
      checkNonce({
        capability,
        nonce: 7,
        highestAccepted: null,
        alreadyUsed: false,
      }).ok,
    ).toBe(true);
  });

  it("refuses a nonce above the floor", () => {
    // There is only ever one action, so the floor *is* the only admissible
    // value. Accepting a higher nonce would make a single-use grant reusable.
    expect(
      checkNonce({
        capability,
        nonce: 8,
        highestAccepted: null,
        alreadyUsed: false,
      }),
    ).toMatchObject({ ok: false, code: "INVALID_NONCE" });
  });

  it("refuses the floor nonce a second time", () => {
    expect(
      checkNonce({
        capability,
        nonce: 7,
        highestAccepted: 7,
        alreadyUsed: true,
      }),
    ).toMatchObject({ ok: false, code: "REPLAY_DETECTED" });
  });
});

describe("claimNonce is atomic", () => {
  it("lets exactly one of sixteen concurrent claims win", async () => {
    const results = await Promise.all(
      Array.from({ length: 16 }, async () =>
        replayStore.claimNonce(CAPABILITY_ID, AGENT_ID, 42, NOW),
      ),
    );

    expect(results.filter(Boolean)).toHaveLength(1);
    expect(replayStore.hasBeenProcessed(CAPABILITY_ID, AGENT_ID, 42)).toBe(
      true,
    );
    expect(replayStore.highestNonce(CAPABILITY_ID)).toBe(42);
  });

  it("refuses a second claim of the same nonce", () => {
    expect(replayStore.claimNonce(CAPABILITY_ID, AGENT_ID, 1, NOW)).toBe(true);
    expect(replayStore.claimNonce(CAPABILITY_ID, AGENT_ID, 1, NOW)).toBe(false);
  });

  it("keys the claim to the capability, not to the agent", () => {
    // A second agent presenting the same capability and nonce must not get a
    // fresh claim: the capability is the unit of authority.
    expect(replayStore.claimNonce(CAPABILITY_ID, AGENT_ID, 3, NOW)).toBe(true);
    expect(replayStore.claimNonce(CAPABILITY_ID, "other-agent", 3, NOW)).toBe(
      false,
    );
  });

  it("does not lower the high-water mark when an older nonce is claimed", () => {
    // `MAX(highest_nonce, excluded)` — otherwise claiming a low nonce would
    // reopen every nonce above it for replay.
    expect(replayStore.claimNonce(CAPABILITY_ID, AGENT_ID, 50, NOW)).toBe(true);
    expect(replayStore.claimNonce(CAPABILITY_ID, AGENT_ID, 20, NOW)).toBe(true);

    expect(replayStore.highestNonce(CAPABILITY_ID)).toBe(50);
  });

  it("reports no high-water mark before anything is claimed", () => {
    // `null` is not `0`: a capability whose floor is 0 must not look as though
    // nonce 0 was already spent.
    expect(replayStore.highestNonce(CAPABILITY_ID)).toBeNull();
  });

  it("keeps separate capabilities' counters independent", () => {
    replayStore.claimNonce(CAPABILITY_ID, AGENT_ID, 9, NOW);

    expect(replayStore.highestNonce("another-capability")).toBeNull();
    expect(replayStore.claimNonce("another-capability", AGENT_ID, 9, NOW)).toBe(
      true,
    );
  });
});

describe("intent freshness", () => {
  it("refuses a timestamp beyond the skew tolerance", () => {
    expect(
      checkTimestamp({
        timestamp: NOW + 301,
        now: NOW,
        maxSkewSeconds: 300,
      }),
    ).toMatchObject({ ok: false, code: "INTENT_TIMESTAMP_SKEWED" });
  });

  it("tolerates a timestamp exactly at the skew bound", () => {
    expect(
      checkTimestamp({
        timestamp: NOW + 300,
        now: NOW,
        maxSkewSeconds: 300,
      }).ok,
    ).toBe(true);
  });

  it("refuses an intent past its own TTL", () => {
    expect(
      checkTimestamp({
        timestamp: NOW - 61,
        ttlSeconds: 60,
        now: NOW,
        maxSkewSeconds: 300,
      }),
    ).toMatchObject({ ok: false, code: "INTENT_EXPIRED" });
  });

  it("accepts an intent at the last second of its TTL", () => {
    expect(
      checkTimestamp({
        timestamp: NOW - 60,
        ttlSeconds: 60,
        now: NOW,
        maxSkewSeconds: 300,
      }).ok,
    ).toBe(true);
  });
});

describe("idempotency: the same action arriving twice", () => {
  const intent = buildIntent({ intentId: "pay-invoice-8891", nonce: 11 });
  const hash = hashIntentBody(intentIdentityPayload(intent));

  it("claims a fresh (capability, intentId) exactly once", () => {
    expect(
      idempotencyStore.begin(CAPABILITY_ID, "pay-invoice-8891", hash),
    ).toEqual({ kind: "FRESH" });
  });

  it("reports an in-flight duplicate as a pending replay, not a decision", () => {
    // A client that fires twice before the first response lands must not get a
    // second authorization, and must not be told the request succeeded either.
    idempotencyStore.begin(CAPABILITY_ID, "pay-invoice-8891", hash);

    const second = idempotencyStore.begin(
      CAPABILITY_ID,
      "pay-invoice-8891",
      hash,
    );

    expect(second).toMatchObject({ kind: "REPLAY", pending: true, status: 409 });
  });

  it("replays the original decision once it has been recorded", () => {
    idempotencyStore.begin(CAPABILITY_ID, "pay-invoice-8891", hash);
    idempotencyStore.complete(CAPABILITY_ID, "pay-invoice-8891", 201, {
      status: "APPROVED",
      approvalId: "approval-1",
    });

    const replay = idempotencyStore.begin(
      CAPABILITY_ID,
      "pay-invoice-8891",
      hash,
    );

    expect(replay).toMatchObject({ kind: "REPLAY", pending: false, status: 201 });
    expect((replay as { body: { approvalId: string } }).body.approvalId).toBe(
      "approval-1",
    );
  });

  it("ignores the intent timestamp when deciding whether a retry matches", () => {
    // A genuine retry legitimately carries a fresh clock reading. Committing to
    // it would turn every retry into a conflict.
    const retried = buildIntent({
      intentId: "pay-invoice-8891",
      nonce: 11,
      timestamp: NOW + 120,
    });

    expect(hashIntentBody(intentIdentityPayload(retried))).toBe(hash);
  });

  it("reports a different payload under a used intentId as a conflict", () => {
    // The case that must never be mistaken for a fresh authorization: an agent
    // (or an attacker steering one) reusing an id for a different payment.
    idempotencyStore.begin(CAPABILITY_ID, "pay-invoice-8891", hash);

    const different = buildIntent({
      intentId: "pay-invoice-8891",
      nonce: 11,
      amountUsd: 900,
    });

    expect(
      idempotencyStore.begin(
        CAPABILITY_ID,
        "pay-invoice-8891",
        hashIntentBody(intentIdentityPayload(different)),
      ),
    ).toEqual({ kind: "CONFLICT" });
  });

  it("treats a changed recipient as a conflict, not a retry", () => {
    const original = buildIntent({
      intentId: "pay-invoice-9",
      nonce: 12,
      transaction: {
        chainId: 11_155_111,
        to: "0x1111111111111111111111111111111111111111",
        value: "1",
        data: "0x",
        gasLimit: "21000",
        maxFeePerGas: "30000000000",
        maxPriorityFeePerGas: "1000000000",
        nonce: 0,
        type: "eip1559",
      },
    });

    const swapped = buildIntent({
      intentId: "pay-invoice-9",
      nonce: 12,
      transaction: {
        ...original.transaction!,
        to: "0x2222222222222222222222222222222222222222",
      },
    });

    idempotencyStore.begin(
      CAPABILITY_ID,
      "pay-invoice-9",
      hashIntentBody(intentIdentityPayload(original)),
    );

    expect(
      idempotencyStore.begin(
        CAPABILITY_ID,
        "pay-invoice-9",
        hashIntentBody(intentIdentityPayload(swapped)),
      ),
    ).toEqual({ kind: "CONFLICT" });
  });

  it("scopes an intentId to its capability", () => {
    idempotencyStore.begin(CAPABILITY_ID, "pay-invoice-8891", hash);

    expect(
      idempotencyStore.begin("other-capability", "pay-invoice-8891", hash),
    ).toEqual({ kind: "FRESH" });
  });

  it("refuses to overwrite a response a retry has already been served", () => {
    idempotencyStore.begin(CAPABILITY_ID, "pay-invoice-8891", hash);

    expect(
      idempotencyStore.complete(CAPABILITY_ID, "pay-invoice-8891", 201, {
        first: true,
      }),
    ).toBe(true);
    expect(
      idempotencyStore.complete(CAPABILITY_ID, "pay-invoice-8891", 200, {
        second: true,
      }),
    ).toBe(false);
    expect(idempotencyStore.get(CAPABILITY_ID, "pay-invoice-8891")?.body).toEqual(
      { first: true },
    );
  });

  it("releases only a still-pending claim when abandoning", () => {
    // Abandoning a completed record would erase a served response and unlock a
    // second authorization.
    idempotencyStore.begin(CAPABILITY_ID, "pay-invoice-8891", hash);
    idempotencyStore.complete(CAPABILITY_ID, "pay-invoice-8891", 201, {});

    expect(idempotencyStore.abandon(CAPABILITY_ID, "pay-invoice-8891")).toBe(
      false,
    );
    expect(
      idempotencyStore.begin(CAPABILITY_ID, "pay-invoice-8891", hash),
    ).toMatchObject({ kind: "REPLAY", status: 201 });
  });

  it("lets a crashed handler's claim be retried after abandonment", () => {
    idempotencyStore.begin(CAPABILITY_ID, "pay-invoice-8891", hash);

    expect(idempotencyStore.abandon(CAPABILITY_ID, "pay-invoice-8891")).toBe(
      true,
    );
    expect(
      idempotencyStore.begin(CAPABILITY_ID, "pay-invoice-8891", hash),
    ).toEqual({ kind: "FRESH" });
  });

  it("lets exactly one of eight concurrent identical requests be FRESH", async () => {
    const outcomes = await Promise.all(
      Array.from({ length: 8 }, async () =>
        idempotencyStore.begin(CAPABILITY_ID, "burst", hash),
      ),
    );

    expect(outcomes.filter((outcome) => outcome.kind === "FRESH")).toHaveLength(
      1,
    );
    expect(
      outcomes.filter((outcome) => outcome.kind === "REPLAY"),
    ).toHaveLength(7);
  });

  it("refuses status 0, which is reserved for the pending marker", () => {
    idempotencyStore.begin(CAPABILITY_ID, "pay-invoice-8891", hash);

    expect(() =>
      idempotencyStore.complete(CAPABILITY_ID, "pay-invoice-8891", 0, {}),
    ).toThrow();
  });
});
