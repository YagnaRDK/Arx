import { describe, expect, it } from "bun:test";

/*
 * Value binding: the agent's declaration against oracle truth.
 *
 * `intent.amountUsd` is an assertion made by the same process an attacker may
 * already be steering. Every USD ceiling in Arx is only a ceiling if the figure
 * it compares against comes from the bytes and an oracle, never from the claim.
 *
 * The other half of this file is the failure mode that matters more: what
 * happens when the oracle cannot answer. An unavailable or stale price must
 * escalate, never permit — a dependency outage that silently widens authority is
 * worse than an outage that stops work.
 */
process.env.NODE_ENV = "test";
process.env.DATABASE_PATH ??= "./.test-data/arx-suite.sqlite";

const { TransactionFirewall } = await import(
  "../src/firewall/transaction-firewall"
);
const { CompositePriceOracle, PRICE_STALE_REASON, PRICE_UNAVAILABLE_REASON } =
  await import("../src/oracle/price-oracle");
const { allow } = await import("../src/types/evaluation");
const fixtures = await import("./helpers/fixtures");

type Availability<T> =
  | { status: "OK"; value: T }
  | { status: "UNAVAILABLE"; reason: string; retryable: boolean };

type PriceQuote = {
  asset: string;
  priceUsd: number;
  source: string;
  updatedAt: number;
};

const {
  EFFECTIVELY_UNLIMITED,
  NOW,
  PAYEE,
  UNKNOWN_TOKEN,
  USDC,
  buildCall,
  buildCapability,
  buildIntent,
  buildTransaction,
  erc20,
  freshOracle,
} = fixtures;

/** 0.01 ETH. At the static table's $3,200/ETH this is exactly $32.00. */
const POINT_ZERO_ONE_ETH = "10000000000000000";
const ONE_ETH = "1000000000000000000";
const ETH_PRICE_USD = 3_200;

type Oracle = {
  readonly name: string;
  isReady(): boolean;
  getUsdPrice(
    asset: string,
    chainId: number,
  ): Promise<Availability<PriceQuote>>;
};

/** An adapter that always answers, with a quote timestamped as told. */
function feed(options: {
  priceUsd?: number;
  updatedAt?: number;
  ready?: boolean;
}): Oracle {
  return {
    name: "test-feed",
    isReady: () => options.ready ?? true,
    async getUsdPrice(asset) {
      return {
        status: "OK",
        value: {
          asset,
          priceUsd: options.priceUsd ?? ETH_PRICE_USD,
          source: "test-feed",
          updatedAt: options.updatedAt ?? NOW,
        },
      };
    },
  };
}

/** An adapter that never answers. Not an error — an honest "I do not know". */
function silentFeed(reason: string): Oracle {
  return {
    name: "silent-feed",
    isReady: () => true,
    async getUsdPrice() {
      return { status: "UNAVAILABLE", reason, retryable: true };
    },
  };
}

async function inspect(input: {
  oracle?: Oracle;
  transaction?: ReturnType<typeof buildTransaction>;
  intent?: ReturnType<typeof buildIntent>;
  capability?: ReturnType<typeof buildCapability>;
}) {
  const firewall = new TransactionFirewall(
    input.oracle === undefined ? {} : { priceOracle: input.oracle as never },
  );

  return firewall.inspect({
    transaction: input.transaction ?? buildTransaction(),
    intent: input.intent ?? buildIntent(),
    capability: input.capability ?? buildCapability(),
    policyResult: allow("capability permits this intent"),
    now: NOW,
  });
}

type Decision = Awaited<ReturnType<typeof inspect>>;

function codesOf(decision: Decision, severity: "BLOCK" | "ESCALATE"): string[] {
  return decision.findings
    .filter((finding) => finding.severity === severity)
    .map((finding) => finding.code);
}

describe("value binding: the declaration against the bytes", () => {
  it("prices native value from the bytes, not from the claim", async () => {
    const decision = await inspect({
      oracle: freshOracle() as never,
      intent: buildIntent({ amountUsd: 32 }),
    });

    expect(decision.valueUsd).toBeCloseTo(32, 6);
    expect(decision.declaredValueUsd).toBe(32);
    expect(decision.valuePriced).toBe(true);
    expect(decision.decision).toBe("ALLOW");
    // The source travels with the decision: a table lookup must be visible as
    // a table lookup.
    expect(decision.priceQuotes.map((quote) => quote.source)).toEqual([
      "static-table",
    ]);
  });

  it("blocks a declaration that understates the transaction", async () => {
    // "Move 1 ETH but declare it as $1" is the attack this check exists for:
    // without it every USD ceiling is compared against the attacker's number.
    const decision = await inspect({
      oracle: freshOracle() as never,
      transaction: buildTransaction({ value: ONE_ETH }),
      intent: buildIntent({ amountUsd: 1 }),
      capability: buildCapability({ maxAmountUsd: 100_000 }),
    });

    expect(decision.decision).toBe("DENY");
    expect(decision.result.code).toBe("VALUE_DECLARATION_MISMATCH");
    expect(decision.result.reason).toContain("understates");
  });

  it("blocks a declaration that overstates the transaction", async () => {
    // Both directions are reported. An approval artifact a human reads must
    // not carry a false statement about a payment, in either direction.
    const decision = await inspect({
      oracle: freshOracle() as never,
      transaction: buildTransaction({ value: POINT_ZERO_ONE_ETH }),
      intent: buildIntent({ amountUsd: 500 }),
      capability: buildCapability({ maxAmountUsd: 100_000 }),
    });

    expect(decision.result.code).toBe("VALUE_DECLARATION_MISMATCH");
    expect(decision.result.reason).toContain("overstates");
  });

  it("prices an ERC-20 transfer from the calldata amount", async () => {
    const decision = await inspect({
      oracle: freshOracle() as never,
      transaction: buildCall(USDC, erc20("transfer", [PAYEE, 25_000_000n])),
      intent: buildIntent({ amountUsd: 25 }),
    });

    // 25,000,000 base units of a 6-decimal token at $1.00.
    expect(decision.valueUsd).toBeCloseTo(25, 6);
    expect(decision.decision).toBe("ALLOW");
  });

  it("catches a lie about an ERC-20 amount", async () => {
    const decision = await inspect({
      oracle: freshOracle() as never,
      transaction: buildCall(USDC, erc20("transfer", [PAYEE, 900_000_000n])),
      intent: buildIntent({ amountUsd: 25 }),
      capability: buildCapability({ maxAmountUsd: 100_000 }),
    });

    expect(decision.result.code).toBe("VALUE_DECLARATION_MISMATCH");
    expect(decision.valueUsd).toBeCloseTo(900, 6);
  });
});

describe("value binding: tolerance boundaries", () => {
  // 500bps is the schema default. The divergence is measured against the
  // *declared* figure, so the boundary is asymmetric around the true value.
  const capability = buildCapability({
    maxAmountUsd: 100_000,
    valueToleranceBps: 500,
  });

  /** The bps figure `value-binding.ts` computes, reproduced here exactly. */
  function divergenceBps(valueUsd: number, declaredUsd: number): number {
    return Math.round(
      (Math.abs(valueUsd - declaredUsd) / declaredUsd) * 10_000,
    );
  }

  it("permits an under-declaration exactly at the tolerance", async () => {
    const declared = 32 / 1.05;

    expect(divergenceBps(32, declared)).toBe(500);

    const decision = await inspect({
      oracle: freshOracle() as never,
      capability,
      intent: buildIntent({ amountUsd: declared }),
    });

    expect(codesOf(decision, "BLOCK")).toEqual([]);
  });

  it("blocks an under-declaration one basis point past the tolerance", async () => {
    const declared = 30.47;

    expect(divergenceBps(32, declared)).toBe(502);

    const decision = await inspect({
      oracle: freshOracle() as never,
      capability,
      intent: buildIntent({ amountUsd: declared }),
    });

    expect(decision.result.code).toBe("VALUE_DECLARATION_MISMATCH");
  });

  it("permits an over-declaration exactly at the tolerance", async () => {
    const declared = 32 / 0.95;

    expect(divergenceBps(32, declared)).toBe(500);

    const decision = await inspect({
      oracle: freshOracle() as never,
      capability,
      intent: buildIntent({ amountUsd: declared }),
    });

    expect(codesOf(decision, "BLOCK")).toEqual([]);
  });

  it("blocks an over-declaration past the tolerance", async () => {
    const declared = 33.9;

    expect(divergenceBps(32, declared)).toBeGreaterThan(500);

    const decision = await inspect({
      oracle: freshOracle() as never,
      capability,
      intent: buildIntent({ amountUsd: declared }),
    });

    expect(decision.result.code).toBe("VALUE_DECLARATION_MISMATCH");
  });

  it("honours a zero tolerance as exact agreement", async () => {
    const exact = await inspect({
      oracle: freshOracle() as never,
      capability: buildCapability({
        maxAmountUsd: 100_000,
        valueToleranceBps: 0,
      }),
      intent: buildIntent({ amountUsd: 32 }),
    });

    const offByOneCent = await inspect({
      oracle: freshOracle() as never,
      capability: buildCapability({
        maxAmountUsd: 100_000,
        valueToleranceBps: 0,
      }),
      intent: buildIntent({ amountUsd: 32.01 }),
    });

    expect(codesOf(exact, "BLOCK")).toEqual([]);
    expect(offByOneCent.result.code).toBe("VALUE_DECLARATION_MISMATCH");
  });
});

describe("value binding: maxAmountUsd is enforced against the oracle", () => {
  it("blocks on the oracle figure even when the declaration is honest and under the cap", async () => {
    // The declaration here is *truthful* — it just happens to be the bytes that
    // exceed the ceiling. If the comparison used the claim, an agent could pass
    // by lying; if it used only the claim's honesty, this would pass by luck.
    const decision = await inspect({
      oracle: freshOracle() as never,
      transaction: buildTransaction({ value: ONE_ETH }),
      intent: buildIntent({ amountUsd: ETH_PRICE_USD }),
      capability: buildCapability({
        maxAmountUsd: 1_000,
        limits: { maxValueWei: "100000000000000000000" },
      }),
    });

    expect(decision.decision).toBe("DENY");
    expect(codesOf(decision, "BLOCK")).toContain("AMOUNT_EXCEEDED");
    expect(decision.result.reason).toContain("Oracle-derived");
  });

  it("blocks on the oracle figure when the declaration is a lie under the cap", async () => {
    const decision = await inspect({
      oracle: freshOracle() as never,
      transaction: buildTransaction({ value: ONE_ETH }),
      intent: buildIntent({ amountUsd: 10 }),
      capability: buildCapability({
        maxAmountUsd: 1_000,
        limits: { maxValueWei: "100000000000000000000" },
      }),
    });

    // Both findings fire, and both are blocks: the lie and the breach.
    expect(codesOf(decision, "BLOCK")).toContain("AMOUNT_EXCEEDED");
    expect(codesOf(decision, "BLOCK")).toContain("VALUE_DECLARATION_MISMATCH");
  });

  it("permits the oracle figure exactly at the cap", async () => {
    const decision = await inspect({
      oracle: feed({ priceUsd: 100 }),
      transaction: buildTransaction({ value: ONE_ETH }),
      intent: buildIntent({ amountUsd: 100 }),
      capability: buildCapability({
        maxAmountUsd: 100,
        limits: { maxValueWei: "100000000000000000000" },
      }),
    });

    expect(codesOf(decision, "BLOCK")).toEqual([]);
  });
});

describe("value binding: an oracle that cannot answer never permits", () => {
  it("escalates when no oracle is wired at all", async () => {
    const decision = await inspect({ oracle: undefined });

    expect(decision.decision).toBe("ESCALATE");
    expect(decision.valuePriced).toBe(false);
    expect(decision.valueUsd).toBe(0);
    expect(codesOf(decision, "ESCALATE")).toContain("PRICE_UNAVAILABLE");
  });

  it("escalates when the oracle reports itself not ready", async () => {
    const decision = await inspect({ oracle: feed({ ready: false }) });

    expect(decision.decision).toBe("ESCALATE");
    expect(decision.valuePriced).toBe(false);
  });

  it("escalates when every adapter returns UNAVAILABLE", async () => {
    const decision = await inspect({
      oracle: new CompositePriceOracle(
        [silentFeed(PRICE_UNAVAILABLE_REASON) as never],
        { now: () => NOW },
      ) as never,
    });

    expect(decision.decision).toBe("ESCALATE");
    expect(codesOf(decision, "ESCALATE")).toContain("PRICE_UNAVAILABLE");
    expect(decision.valuePriced).toBe(false);
  });

  it("treats a stale quote as unavailable, not as a value", async () => {
    // The distinction this test defends: a stale price is not "old but usable".
    // Using it would authorize against last week's market, and — worse — it
    // would make `valuePriced` true and re-enable every USD ceiling on a number
    // nobody should trust.
    const stale = new CompositePriceOracle(
      [feed({ updatedAt: NOW - 100_000 }) as never],
      { maxAgeSeconds: 60, now: () => NOW },
    );

    const decision = await inspect({ oracle: stale as never });

    expect(decision.decision).toBe("ESCALATE");
    expect(codesOf(decision, "ESCALATE")).toContain("PRICE_STALE");
    expect(decision.valuePriced).toBe(false);
    expect(decision.valueUsd).toBe(0);
    // Nothing was quoted, so nothing may be reported as a source.
    expect(decision.priceQuotes).toEqual([]);
  });

  it("reports PRICE_STALE distinctly from PRICE_UNAVAILABLE", async () => {
    // An operator reading the audit log has to be able to tell "the feed was
    // old" from "nobody answered". Collapsing them hides which dependency broke.
    const staleOnly = new CompositePriceOracle(
      [silentFeed(PRICE_STALE_REASON) as never],
      { now: () => NOW },
    );

    const decision = await inspect({ oracle: staleOnly as never });

    expect(codesOf(decision, "ESCALATE")).toContain("PRICE_STALE");
    expect(codesOf(decision, "ESCALATE")).not.toContain("PRICE_UNAVAILABLE");
  });

  it("does not let a stale adapter shadow a fresh one", async () => {
    const composite = new CompositePriceOracle(
      [
        feed({ updatedAt: NOW - 100_000 }) as never,
        feed({ updatedAt: NOW, priceUsd: ETH_PRICE_USD }) as never,
      ],
      { maxAgeSeconds: 60, now: () => NOW },
    );

    const decision = await inspect({ oracle: composite as never });

    expect(decision.valuePriced).toBe(true);
    expect(decision.valueUsd).toBeCloseTo(32, 6);
    expect(decision.decision).toBe("ALLOW");
  });

  it("escalates a token that is not in Arx's verified asset registry", async () => {
    // Unknown means unknown. Pricing an unlisted token at $0 would let any
    // token transfer through every USD ceiling.
    const decision = await inspect({
      oracle: freshOracle() as never,
      capability: buildCapability({
        contracts: { mode: "ALLOWLIST", allow: [UNKNOWN_TOKEN], deny: [] },
      }),
      transaction: buildCall(
        UNKNOWN_TOKEN,
        erc20("transfer", [PAYEE, 5_000_000_000n]),
      ),
      intent: buildIntent({ amountUsd: 5_000 }),
    });

    expect(decision.valuePriced).toBe(false);
    expect(decision.decision).toBe("ESCALATE");
    expect(codesOf(decision, "ESCALATE")).toContain("PRICE_UNAVAILABLE");
  });

  it("does not apply maxAmountUsd to an unpriced transfer, and says so", async () => {
    // With no price there is no honest comparison to make. The wei ceiling is
    // what bounds this transaction, and the decision is ESCALATE rather than
    // ALLOW precisely because the USD ceiling could not run.
    const decision = await inspect({
      oracle: silentFeed(PRICE_UNAVAILABLE_REASON),
      transaction: buildTransaction({ value: ONE_ETH }),
      intent: buildIntent({ amountUsd: 3_200 }),
      capability: buildCapability({
        maxAmountUsd: 1,
        limits: { maxValueWei: "100000000000000000000" },
      }),
    });

    expect(codesOf(decision, "BLOCK")).not.toContain("AMOUNT_EXCEEDED");
    expect(decision.decision).toBe("ESCALATE");
    expect(decision.valuePriced).toBe(false);
  });

  it("still enforces the wei ceiling when pricing is unavailable", async () => {
    // The whole reason a capability carries both a USD and a wei ceiling: a
    // price outage degrades Arx from value-aware to value-bounded, never to
    // unbounded.
    const decision = await inspect({
      oracle: silentFeed(PRICE_UNAVAILABLE_REASON),
      transaction: buildTransaction({ value: "1000000000000000001" }),
      intent: buildIntent({ amountUsd: 3_200 }),
      capability: buildCapability({ maxAmountUsd: 100_000 }),
    });

    expect(decision.decision).toBe("DENY");
    expect(decision.result.code).toBe("VALUE_LIMIT_EXCEEDED");
  });

  it("does not confuse 'nothing to price' with 'could not price'", async () => {
    // A zero-value `approve` genuinely moves nothing priceable. Scoring that as
    // an unavailable price would fire PRICE_UNAVAILABLE on every legitimate
    // approval and teach an operator to ignore the signal.
    const decision = await inspect({
      oracle: freshOracle() as never,
      capability: buildCapability({
        methods: {
          mode: "ALLOWLIST",
          allow: ["approve(address,uint256)"],
          deny: [],
        },
      }),
      transaction: buildCall(USDC, erc20("approve", [PAYEE, 25_000_000n])),
      intent: buildIntent({ amountUsd: 25, action: "APPROVE" }),
    });

    expect(decision.valuePriced).toBe(true);
    expect(decision.valueUsd).toBe(0);
    expect(decision.riskSignals.map((signal) => signal.id)).not.toContain(
      "PRICE_UNAVAILABLE",
    );
    expect(decision.decision).toBe("ALLOW");
  });
});

describe("value binding: allowance sizing", () => {
  const approveCapability = buildCapability({
    methods: {
      mode: "ALLOWLIST",
      allow: ["approve(address,uint256)", "transfer(address,uint256)", "multicall(bytes[])"],
      deny: [],
    },
  });

  it("does not add an allowance to the value the transaction moves", async () => {
    // An approval moves nothing today. Counting it as spend would charge a
    // rolling budget for money that has not left.
    const decision = await inspect({
      oracle: freshOracle() as never,
      capability: approveCapability,
      transaction: buildCall(USDC, erc20("approve", [PAYEE, 900_000_000n])),
      intent: buildIntent({ amountUsd: 900, action: "APPROVE" }),
    });

    expect(decision.valueUsd).toBe(0);
  });

  it("escalates an allowance worth far more than the action it enables", async () => {
    // 1 USDC moved, against a 900 USDC standing allowance. The allowance is
    // priced here only because the same transaction *also* moves a priceable
    // amount — which is exactly the gap the next test records.
    const decision = await inspect({
      oracle: freshOracle() as never,
      capability: approveCapability,
      transaction: buildCall(
        USDC,
        fixtures.batch("multicall", [
          [
            erc20("transfer", [PAYEE, 1_000_000n]),
            erc20("approve", [PAYEE, 900_000_000n]),
          ],
        ]),
      ),
      intent: buildIntent({ amountUsd: 1, action: "APPROVE" }),
    });

    expect(codesOf(decision, "ESCALATE")).toContain(
      "UNLIMITED_APPROVAL_BLOCKED",
    );
    expect(decision.result.reason).toContain("10x");
    expect(decision.riskSignals.map((signal) => signal.id)).toContain(
      "APPROVAL_FAR_EXCEEDS_DECLARED",
    );
    expect(decision.decision).toBe("ESCALATE");
  });

  it("prices a bare approve's allowance, so a huge grant cannot pass as $0", async () => {
    /*
     * This was a real defect, found by attacking a running server and fixed.
     *
     * `checkValueBinding` took its `nothingToPrice(...)` early return before it
     * ever priced `extraction.largestAllowance`. A bare `approve` moves no
     * native value and no token amount, so `components` was empty and that
     * return was taken for the normal shape of an approval — leaving
     * `allowanceUsd` undefined, which made the far-excess escalation and the
     * APPROVAL_FAR_EXCEEDS_DECLARED risk signal unreachable.
     *
     * The consequence was that `approve(spender, 100_000_000 USDC)` to an
     * allowlisted spender was ALLOWed against a capability whose ceiling was
     * $500, because the transaction itself moved nothing. The guard now covers
     * the allowance, and the capability's USD ceiling applies to the authority
     * being granted rather than only to the value being moved.
     */
    const decision = await inspect({
      oracle: freshOracle() as never,
      capability: approveCapability,
      transaction: buildCall(
        USDC,
        // Just under the 2^128 unlimited threshold, so it is priced rather than
        // caught by the separate unlimited-approval block.
        erc20("approve", [PAYEE, EFFECTIVELY_UNLIMITED - 1n]),
      ),
      intent: buildIntent({ amountUsd: 1, action: "APPROVE" }),
    });

    expect(decision.decision).not.toBe("ALLOW");
  });

  it("applies the capability's USD ceiling to a standing allowance", async () => {
    // An allowance is a ceiling on future payments. Comparing it to the same
    // ceiling the operator set is the question that matters, and it is the one
    // that was never asked.
    const decision = await inspect({
      oracle: freshOracle() as never,
      capability: approveCapability,
      transaction: buildCall(
        USDC,
        // $10,000 of USDC against a capability far below that.
        erc20("approve", [PAYEE, 10_000_000_000n]),
      ),
      intent: buildIntent({ amountUsd: 10_000, action: "APPROVE" }),
    });

    expect(decision.decision).not.toBe("ALLOW");
    expect(codesOf(decision, "BLOCK")).toContain("AMOUNT_EXCEEDED");
  });

  it("still permits an honest approval inside the ceiling", async () => {
    // The fix must not make every approval a denial: an allowance that matches
    // the declaration and sits inside the ceiling is exactly what the
    // capability authorized.
    const decision = await inspect({
      oracle: freshOracle() as never,
      capability: approveCapability,
      transaction: buildCall(USDC, erc20("approve", [PAYEE, 40_000_000n])),
      intent: buildIntent({ amountUsd: 40, action: "APPROVE" }),
    });

    expect(decision.decision).toBe("ALLOW");
  });
});
