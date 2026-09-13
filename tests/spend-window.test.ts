import { beforeEach, describe, expect, it } from "bun:test";

/*
 * Rolling-window spend accounting.
 *
 * A per-transaction ceiling bounds nothing over time: an agent with a $100 limit
 * can send a hundred $99 transactions. The window limits are what make a
 * capability a budget rather than a rate of one.
 *
 * The reservation semantics are the interesting part. Authority is consumed when
 * an approval is *issued*, not when it is signed — an outstanding approval is a
 * promise Arx has already made. So a row is RESERVED at approval, SETTLED once a
 * signature exists, and RELEASED if the approval expires, is rejected, or
 * signing fails. That last case is the one worth guarding: a user declining on
 * the device must not silently burn the day's budget.
 */
process.env.NODE_ENV = "test";
process.env.DATABASE_PATH ??= "./.test-data/arx-suite.sqlite";

const { resetDatabaseForTests } = await import("../src/db/database");
const { SpendStore } = await import("../src/storage/spend-store");
const { ApprovalStore } = await import("../src/storage/approval-store");
const { ApprovalService } = await import("../src/approval/approval-service");
const { HumanApprovalQueue, controlPlaneOperator } = await import(
  "../src/approval/human-approval"
);
const { ApprovalExpirySweeper } = await import(
  "../src/approval/expiry-sweeper"
);
const { AuthorizationKey } = await import("../src/crypto/authorization-key");
const { TransactionFirewall } = await import(
  "../src/firewall/transaction-firewall"
);
const { allow, escalate } = await import("../src/types/evaluation");
const {
  AGENT_ID,
  CAPABILITY_ID,
  NOW,
  buildCapability,
  buildIntent,
  buildTransaction,
  freshOracle,
} = await import("./helpers/fixtures");

const spendStore = new SpendStore();
const approvalStore = new ApprovalStore();
const approvalService = new ApprovalService(
  approvalStore,
  new AuthorizationKey(),
);
const queue = new HumanApprovalQueue({ approvalStore, spendStore });

const WINDOW_SECONDS = 86_400;
const transaction = buildTransaction();

function reserve(approvalId: string, amountUsd: number, now = NOW): boolean {
  return spendStore.reserve({
    capabilityId: CAPABILITY_ID,
    agentId: AGENT_ID,
    approvalId,
    amountUsd,
    valueWei: "10000000000000000",
    now,
  });
}

function usage(now = NOW) {
  return spendStore.usage(CAPABILITY_ID, WINDOW_SECONDS, now);
}

beforeEach(() => {
  resetDatabaseForTests();
});

describe("the spend ledger", () => {
  it("counts a reservation against the window immediately", () => {
    // Counting only signatures would let an agent stockpile ten approvals
    // against a one-transaction budget and then redeem them all.
    expect(reserve("approval-1", 40)).toBe(true);

    expect(usage()).toMatchObject({ amountUsd: 40, transactionCount: 1 });
  });

  it("keeps a settled reservation counted", () => {
    // The money has left. It must not stop counting because the state changed.
    reserve("approval-1", 40);

    expect(spendStore.settle("approval-1", NOW)).toBe(true);
    expect(usage()).toMatchObject({ amountUsd: 40, transactionCount: 1 });
  });

  it("stops counting a released reservation", () => {
    reserve("approval-1", 40);

    expect(spendStore.release("approval-1", NOW)).toBe(true);
    expect(usage()).toMatchObject({ amountUsd: 0, transactionCount: 0 });
  });

  it("retains a released row for the audit trail", () => {
    // Released is not deleted: an operator has to be able to see that the
    // budget was reserved and then given back.
    reserve("approval-1", 40);
    spendStore.release("approval-1", NOW);

    const rows = spendStore.list(CAPABILITY_ID);

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ state: "RELEASED", amount_usd: 40 });
  });

  it("refuses to settle a row it already released, and vice versa", () => {
    // Both transitions are compare-and-swap on RESERVED, so a late settle
    // cannot re-charge a budget that was handed back.
    reserve("approval-1", 40);

    expect(spendStore.release("approval-1", NOW)).toBe(true);
    expect(spendStore.settle("approval-1", NOW)).toBe(false);
    expect(usage().amountUsd).toBe(0);

    reserve("approval-2", 10);

    expect(spendStore.settle("approval-2", NOW)).toBe(true);
    expect(spendStore.release("approval-2", NOW)).toBe(false);
    expect(usage().amountUsd).toBe(10);
  });

  it("reserves an approval at most once", () => {
    // `approval_id` is UNIQUE, so a retried reserve cannot double-charge one
    // approval.
    expect(reserve("approval-1", 40)).toBe(true);
    expect(reserve("approval-1", 40)).toBe(false);
    expect(usage().amountUsd).toBe(40);
  });

  it("keeps separate capabilities' budgets independent", () => {
    reserve("approval-1", 40);

    expect(spendStore.usage("another-capability", WINDOW_SECONDS, NOW)).toMatchObject(
      { amountUsd: 0, transactionCount: 0 },
    );
  });

  it("reports a release that matched nothing as false", () => {
    expect(spendStore.release("no-such-approval", NOW)).toBe(false);
  });
});

describe("window boundary arithmetic", () => {
  it("counts a row created exactly at the window start", () => {
    reserve("approval-edge", 40, NOW - WINDOW_SECONDS);

    expect(usage(NOW)).toMatchObject({
      amountUsd: 40,
      windowStart: NOW - WINDOW_SECONDS,
    });
  });

  it("drops a row created one second before the window start", () => {
    reserve("approval-old", 40, NOW - WINDOW_SECONDS - 1);

    expect(usage(NOW).amountUsd).toBe(0);
  });

  it("lets spend fall out of the window as time moves", () => {
    reserve("approval-1", 90, NOW);

    expect(usage(NOW).amountUsd).toBe(90);
    expect(usage(NOW + WINDOW_SECONDS).amountUsd).toBe(90);
    expect(usage(NOW + WINDOW_SECONDS + 1).amountUsd).toBe(0);
  });

  it("sums only the rows inside the window", () => {
    reserve("in-1", 10, NOW - 10);
    reserve("in-2", 20, NOW - WINDOW_SECONDS);
    reserve("out-1", 1_000, NOW - WINDOW_SECONDS - 5);

    expect(usage(NOW)).toMatchObject({ amountUsd: 30, transactionCount: 2 });
  });

  it("honours a short window", () => {
    reserve("approval-1", 40, NOW - 30);

    expect(spendStore.usage(CAPABILITY_ID, 60, NOW).amountUsd).toBe(40);
    expect(spendStore.usage(CAPABILITY_ID, 10, NOW).amountUsd).toBe(0);
  });
});

describe("the firewall's window comparison", () => {
  const firewall = new TransactionFirewall({
    priceOracle: freshOracle(),
    spendStore,
  });

  const capability = buildCapability({
    maxAmountUsd: 1_000,
    limits: {
      maxValueWei: "1000000000000000000",
      maxGasLimit: "500000",
      maxFeePerGasWei: "500000000000",
      maxAmountUsdPerWindow: 100,
      maxTxPerWindow: 3,
      windowSeconds: WINDOW_SECONDS,
    },
  });

  /** The fixture transaction is worth exactly $32.00 at the static price. */
  async function inspect(overrides: { capability?: typeof capability } = {}) {
    return firewall.inspect({
      transaction,
      intent: buildIntent({ amountUsd: 32 }),
      capability: overrides.capability ?? capability,
      policyResult: allow("capability permits this intent"),
      now: NOW,
    });
  }

  function blockCodes(decision: Awaited<ReturnType<typeof inspect>>): string[] {
    return decision.findings
      .filter((finding) => finding.severity === "BLOCK")
      .map((finding) => finding.code);
  }

  it("permits a transaction that fits the remaining headroom", async () => {
    reserve("earlier", 60);

    const decision = await inspect();

    expect(blockCodes(decision)).toEqual([]);
    expect(decision.decision).toBe("ALLOW");
  });

  it("permits a transaction that lands exactly on the limit", async () => {
    reserve("earlier", 68);

    // 68 + 32 = 100, exactly the window limit.
    expect(blockCodes(await inspect())).toEqual([]);
  });

  it("blocks a transaction one cent past the limit", async () => {
    reserve("earlier", 68.01);

    const decision = await inspect();

    expect(decision.result.code).toBe("SPEND_WINDOW_EXCEEDED");
    expect(decision.decision).toBe("DENY");
  });

  it("counts only reservations still inside the window", async () => {
    reserve("stale", 95, NOW - WINDOW_SECONDS - 1);

    expect(blockCodes(await inspect())).toEqual([]);
  });

  it("frees headroom again once a reservation is released", async () => {
    reserve("rejected", 95);

    expect(blockCodes(await inspect())).toContain("SPEND_WINDOW_EXCEEDED");

    spendStore.release("rejected", NOW);

    expect(blockCodes(await inspect())).toEqual([]);
  });

  it("blocks on the transaction-count limit independently of the amount", async () => {
    reserve("one", 1);
    reserve("two", 1);
    reserve("three", 1);

    const decision = await inspect();

    expect(blockCodes(decision)).toContain("TX_COUNT_WINDOW_EXCEEDED");
  });

  it("permits the last transaction the count limit allows", async () => {
    reserve("one", 1);
    reserve("two", 1);

    expect(blockCodes(await inspect())).toEqual([]);
  });

  it("refuses to charge an unpriced transaction against a USD budget", async () => {
    /*
     * A price outage must not become unlimited spend. Charging an unknown
     * amount as $0 would do exactly that, so the check refuses instead — the
     * missing price has already been escalated by `value-binding.ts`, and this
     * is the blocking half that stops the budget being bypassed.
     */
    const unpriced = new TransactionFirewall({ spendStore });

    const decision = await unpriced.inspect({
      transaction,
      intent: buildIntent({ amountUsd: 32 }),
      capability,
      policyResult: allow("capability permits this intent"),
      now: NOW,
    });

    expect(decision.decision).toBe("DENY");
    expect(blockCodes(decision)).toContain("SPEND_WINDOW_EXCEEDED");
    expect(decision.result.reason).toContain("unknown");
  });

  it("blocks when a budget is configured but no ledger is available", async () => {
    // A configured budget that cannot be read is not a budget that has room.
    const ledgerless = new TransactionFirewall({ priceOracle: freshOracle() });

    const decision = await ledgerless.inspect({
      transaction,
      intent: buildIntent({ amountUsd: 32 }),
      capability,
      policyResult: allow("capability permits this intent"),
      now: NOW,
    });

    expect(decision.decision).toBe("DENY");
    expect(decision.result.code).toBe("SPEND_WINDOW_EXCEEDED");
    expect(decision.result.reason).toContain("no spend ledger");
  });

  it("skips the window check entirely when no window is configured", async () => {
    // `0` means "no window limit", which is safe only because `maxAmountUsd` is
    // required and positive: every transaction is already bounded per-transaction.
    const noWindow = buildCapability({
      maxAmountUsd: 1_000,
      limits: {
        maxValueWei: "1000000000000000000",
        maxGasLimit: "500000",
        maxFeePerGasWei: "500000000000",
      },
    });

    reserve("earlier", 10_000);

    expect(blockCodes(await inspect({ capability: noWindow }))).toEqual([]);
  });
});

describe("one unit of headroom under concurrency", () => {
  const firewall = new TransactionFirewall({
    priceOracle: freshOracle(),
    spendStore,
  });

  const capability = buildCapability({
    maxAmountUsd: 1_000,
    limits: {
      maxValueWei: "1000000000000000000",
      maxGasLimit: "500000",
      maxFeePerGasWei: "500000000000",
      maxAmountUsdPerWindow: 40,
      maxTxPerWindow: 1,
      windowSeconds: WINDOW_SECONDS,
    },
  });

  async function decide() {
    return firewall.inspect({
      transaction,
      intent: buildIntent({ amountUsd: 32 }),
      capability,
      policyResult: allow("capability permits this intent"),
      now: NOW,
    });
  }

  it("admits the first claimant and refuses the next", async () => {
    const first = await decide();
    expect(first.decision).toBe("ALLOW");

    // The reservation is what the next decision sees.
    reserve("first", 32);

    const second = await decide();
    expect(second.decision).toBe("DENY");
    expect(
      second.findings
        .filter((finding) => finding.severity === "BLOCK")
        .map((finding) => finding.code),
    ).toEqual(
      expect.arrayContaining([
        "SPEND_WINDOW_EXCEEDED",
        "TX_COUNT_WINDOW_EXCEEDED",
      ]),
    );
  });

  it("shows that the ledger itself does not enforce headroom", async () => {
    /*
     * Deliberately documented rather than asserted away: `reserve` is an
     * INSERT, not a check-and-insert. The headroom comparison lives in
     * `checkSpendWindows`, which runs earlier in the request, so two requests
     * that both pass the check before either reserves will both be admitted.
     *
     * See the parallel-approval case in `tests/end-to-end.test.ts` for what
     * that means over HTTP.
     */
    const results = await Promise.all([
      (async () => reserve("race-a", 32))(),
      (async () => reserve("race-b", 32))(),
    ]);

    expect(results).toEqual([true, true]);
    expect(usage().amountUsd).toBe(64);
  });
});

describe("release on failure: a declined device must not burn the budget", () => {
  function issueApproval(
    kind: "AUTO" | "HUMAN",
    options: { capabilityExpiresAt?: number } = {},
  ) {
    const approval = approvalService.createApproval({
      requestId: `req-${crypto.randomUUID()}`,
      capabilityId: CAPABILITY_ID,
      agentId: AGENT_ID,
      transaction,
      decision:
        kind === "AUTO"
          ? allow("within the granted authority")
          : escalate("value is above the autonomous ceiling"),
      capabilityExpiresAt: options.capabilityExpiresAt ?? NOW + 3_600,
      now: NOW,
      valueUsd: 32,
      riskScore: kind === "AUTO" ? 0 : 70,
    });

    reserve(approval.approvalId, 32);

    return approval;
  }

  it("settles the reservation when a signature is produced", () => {
    const approval = issueApproval("AUTO");

    approvalService.claimForSigning(approval.approvalId);
    approvalService.markSigned(approval.approvalId);
    spendStore.settle(approval.approvalId, NOW);

    expect(usage()).toMatchObject({ amountUsd: 32, transactionCount: 1 });
  });

  it("releases the reservation when signing fails", () => {
    // The device rejection case: no value moved, so no budget was spent.
    const approval = issueApproval("AUTO");

    approvalService.claimForSigning(approval.approvalId);
    approvalService.markSigningFailed(approval.approvalId);
    spendStore.release(approval.approvalId, NOW);

    expect(usage().amountUsd).toBe(0);
    expect(approvalService.get(approval.approvalId)?.status).toBe(
      "SIGNING_FAILED",
    );
  });

  it("releases the reservation when a human rejects the escalation", () => {
    // The queue does this itself, so a rejected proposal cannot permanently
    // consume the agent's budget.
    const approval = issueApproval("HUMAN");

    expect(usage().amountUsd).toBe(32);

    queue.reject(
      approval.approvalId,
      controlPlaneOperator("operator-1"),
      "not a known supplier",
      { now: NOW },
    );

    expect(usage().amountUsd).toBe(0);
  });

  it("keeps the reservation when a human grants the escalation", () => {
    const approval = issueApproval("HUMAN");

    queue.approve(approval.approvalId, controlPlaneOperator("operator-1"), {
      now: NOW,
    });

    expect(usage().amountUsd).toBe(32);
  });

  it("releases the reservation when an escalation is never decided", () => {
    /*
     * Expiry has two halves and doing only the first is a real bug: marking the
     * approval EXPIRED stops it authorizing a signature, but the reserved row
     * would keep counting, so an agent whose escalations nobody got round to
     * would be slowly strangled by a budget it never spent.
     */
    const approval = issueApproval("HUMAN", { capabilityExpiresAt: NOW + 60 });
    const sweeper = new ApprovalExpirySweeper({
      approvalStore,
      spendStore,
      clock: () => NOW + 61,
    });

    const result = sweeper.sweep();

    expect(result).toMatchObject({ expired: 1, released: 1 });
    expect(approvalService.get(approval.approvalId)?.status).toBe("EXPIRED");
    expect(usage().amountUsd).toBe(0);
  });

  it("does not release a reservation for an approval that is mid-signing", () => {
    // Handing back budget for a transaction that is about to be signed would be
    // a different bug from the one the sweeper fixes.
    const approval = issueApproval("AUTO", { capabilityExpiresAt: NOW + 60 });

    approvalService.claimForSigning(approval.approvalId);

    const sweeper = new ApprovalExpirySweeper({
      approvalStore,
      spendStore,
      clock: () => NOW + 61,
    });

    expect(sweeper.sweep()).toMatchObject({ expired: 0, released: 0 });
    expect(usage().amountUsd).toBe(32);
    expect(approvalService.get(approval.approvalId)?.status).toBe("SIGNING");
  });

  it("sweeps repeatedly without double-releasing", () => {
    const approval = issueApproval("AUTO", { capabilityExpiresAt: NOW + 60 });
    const sweeper = new ApprovalExpirySweeper({
      approvalStore,
      spendStore,
      clock: () => NOW + 61,
    });

    expect(sweeper.sweep()).toMatchObject({ expired: 1, released: 1 });
    expect(sweeper.sweep()).toMatchObject({ expired: 0, released: 0 });
    expect(usage().amountUsd).toBe(0);
    expect(approvalService.get(approval.approvalId)?.status).toBe("EXPIRED");
  });
});
