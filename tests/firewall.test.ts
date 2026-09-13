import { describe, expect, it } from "bun:test";

/*
 * The transaction firewall, check by check.
 *
 * `src/firewall/` is the layer that answers the question the policy engine
 * cannot: not "may the agent do this kind of thing?" but "do these bytes do what
 * the agent said, and to whom?". Every test here is written so that deleting the
 * check it covers makes it fail — a denial case *and* a permitted case for each,
 * because a firewall that denies everything is as useless as one that denies
 * nothing.
 *
 * Set before importing: `value-binding.ts` reaches `oracle/price-oracle`, which
 * opens bun:sqlite at import time, and `bun test` shares one module registry
 * across files.
 */
process.env.NODE_ENV = "test";
process.env.DATABASE_PATH ??= "./.test-data/arx-suite.sqlite";

const { TransactionFirewall } = await import(
  "../src/firewall/transaction-firewall"
);
const { allow, deny } = await import("../src/types/evaluation");
const fixtures = await import("./helpers/fixtures");

const {
  ATTACKER,
  CHAIN_ID,
  EFFECTIVELY_UNLIMITED,
  FOREIGN_CHAIN_ID,
  MULTICALL3,
  NOW,
  PAYEE,
  SECOND_PAYEE,
  UINT256_MAX,
  UNKNOWN_TOKEN,
  USDC,
  batch,
  buildCall,
  buildCapability,
  buildIntent,
  buildTransaction,
  erc20,
  freshOracle,
  selectorOf,
} = fixtures;

type Decision = Awaited<ReturnType<TransactionFirewallType["inspect"]>>;
type TransactionFirewallType = InstanceType<typeof TransactionFirewall>;

const firewall = new TransactionFirewall({ priceOracle: freshOracle() });

/** Runs the full-strength path with a clean policy verdict behind it. */
async function inspect(input: {
  transaction?: ReturnType<typeof buildTransaction>;
  intent?: ReturnType<typeof buildIntent>;
  capability?: ReturnType<typeof buildCapability>;
  policyResult?: ReturnType<typeof allow>;
}): Promise<Decision> {
  return firewall.inspect({
    transaction: input.transaction ?? buildTransaction(),
    intent: input.intent ?? buildIntent(),
    capability: input.capability ?? buildCapability(),
    policyResult: input.policyResult ?? allow("capability permits this intent"),
    now: NOW,
  });
}

function codesOf(decision: Decision, severity: "BLOCK" | "ESCALATE"): string[] {
  return decision.findings
    .filter((finding) => finding.severity === severity)
    .map((finding) => finding.code);
}

function signalIds(decision: Decision): string[] {
  return decision.riskSignals.map((signal) => signal.id);
}

describe("firewall: recipient allowlist", () => {
  it("permits native value to an allowlisted recipient", async () => {
    const decision = await inspect({});

    expect(decision.decision).toBe("ALLOW");
    expect(decision.allowed).toBe(true);
    // The bytes travel with the verdict, so nothing downstream re-derives them.
    expect(decision.transaction?.transaction.to).toBe(PAYEE);
  });

  it("blocks native value to an address nobody authorized", async () => {
    const decision = await inspect({
      transaction: buildTransaction({ to: ATTACKER }),
    });

    expect(decision.decision).toBe("DENY");
    expect(decision.result.code).toBe("RECIPIENT_NOT_ALLOWED");
    // A denial must not hand the caller a transaction it can go and sign.
    expect(decision.transaction).toBeUndefined();
  });

  it("blocks an empty allowlist, which permits nobody", async () => {
    const decision = await inspect({
      capability: buildCapability({
        recipients: { mode: "ALLOWLIST", allow: [], deny: [] },
      }),
    });

    expect(decision.result.code).toBe("RECIPIENT_NOT_ALLOWED");
    expect(decision.result.reason).toContain("empty");
  });

  it("lets a deny entry override an allow entry", async () => {
    // Revoking one address must never require rebuilding the allowlist, and
    // must beat `mode: "ANY"`.
    const decision = await inspect({
      capability: buildCapability({
        recipients: { mode: "ANY", allow: [PAYEE], deny: [PAYEE] },
      }),
    });

    expect(decision.result.code).toBe("RECIPIENT_DENIED");
  });

  it("compares addresses case-insensitively", async () => {
    // EIP-55 checksum casing is a display concern; it must not decide authority.
    const decision = await inspect({
      capability: buildCapability({
        recipients: { mode: "ALLOWLIST", allow: [PAYEE.toUpperCase().replace("0X", "0x")], deny: [] },
      }),
    });

    expect(decision.decision).toBe("ALLOW");
  });

  it("does not apply the recipient policy to a zero-value contract call", async () => {
    // `to` is the token here, not the payee. Applying the recipient list to it
    // would demand that every token contract be allowlisted as a payee, and
    // `calldata-recipient.ts` is what guards the real counterparty.
    const decision = await inspect({
      capability: buildCapability({
        recipients: { mode: "ALLOWLIST", allow: [PAYEE], deny: [] },
      }),
      transaction: buildCall(USDC, erc20("transfer", [PAYEE, 1_000_000n])),
      intent: buildIntent({ amountUsd: 1 }),
    });

    expect(decision.decision).toBe("ALLOW");
  });
});

describe("firewall: contract allowlist", () => {
  const callData = erc20("transfer", [PAYEE, 25_000_000n]);
  const intent = buildIntent({ amountUsd: 25 });

  it("permits a call to an allowlisted contract", async () => {
    const decision = await inspect({
      transaction: buildCall(USDC, callData),
      intent,
    });

    expect(decision.decision).toBe("ALLOW");
  });

  it("blocks a call to a contract outside the allowlist", async () => {
    const decision = await inspect({
      transaction: buildCall(SECOND_PAYEE, callData),
      intent,
    });

    expect(codesOf(decision, "BLOCK")).toContain("CONTRACT_NOT_ALLOWED");
    expect(decision.decision).toBe("DENY");
  });

  it("blocks an explicitly denied contract even under mode ANY", async () => {
    const decision = await inspect({
      capability: buildCapability({
        contracts: { mode: "ANY", allow: [], deny: [USDC] },
      }),
      transaction: buildCall(USDC, callData),
      intent,
    });

    expect(decision.result.code).toBe("CONTRACT_NOT_ALLOWED");
    expect(decision.result.reason).toContain("denylist");
  });
});

describe("firewall: method policy", () => {
  const transferData = erc20("transfer", [PAYEE, 25_000_000n]);
  const approveData = erc20("approve", [PAYEE, 25_000_000n]);
  const intent = buildIntent({ amountUsd: 25 });

  it("permits a method written as a canonical signature", async () => {
    const decision = await inspect({
      capability: buildCapability({
        methods: {
          mode: "ALLOWLIST",
          allow: ["transfer(address,uint256)"],
          deny: [],
        },
      }),
      transaction: buildCall(USDC, transferData),
      intent,
    });

    expect(decision.decision).toBe("ALLOW");
  });

  it("permits the same method written as a 4-byte selector", async () => {
    // The two spellings must be interchangeable, or the same policy passes or
    // fails depending on notation — a trap, not a control.
    expect(selectorOf(transferData)).toBe("0xa9059cbb");

    const decision = await inspect({
      capability: buildCapability({
        methods: { mode: "ALLOWLIST", allow: ["0xa9059cbb"], deny: [] },
      }),
      transaction: buildCall(USDC, transferData),
      intent,
    });

    expect(decision.decision).toBe("ALLOW");
  });

  it("blocks a method outside the allowlist", async () => {
    const decision = await inspect({
      capability: buildCapability({
        methods: {
          mode: "ALLOWLIST",
          allow: ["transfer(address,uint256)"],
          deny: [],
        },
      }),
      transaction: buildCall(USDC, approveData),
      intent: buildIntent({ amountUsd: 25, action: "APPROVE" }),
    });

    expect(decision.result.code).toBe("METHOD_NOT_ALLOWED");
  });

  it("blocks a selector-spelled denial of a signature-spelled call", async () => {
    // Deny written as a selector must still catch the call Arx identified by
    // signature, in both directions.
    const decision = await inspect({
      capability: buildCapability({
        methods: { mode: "ANY", allow: [], deny: ["0xa9059cbb"] },
      }),
      transaction: buildCall(USDC, transferData),
      intent,
    });

    expect(decision.result.code).toBe("METHOD_NOT_ALLOWED");
    expect(decision.result.reason).toContain("denylist");
  });

  it("blocks a signature-spelled denial of a call Arx names by selector", async () => {
    const decision = await inspect({
      capability: buildCapability({
        methods: {
          mode: "ANY",
          allow: [],
          deny: ["transfer(address,uint256)"],
        },
      }),
      transaction: buildCall(USDC, transferData),
      intent,
    });

    expect(decision.result.code).toBe("METHOD_NOT_ALLOWED");
  });

  it("blocks undecodable calldata under a method-restricted capability", async () => {
    // The selector is allowed but the arguments are unreadable, so the payee
    // and amount cannot be checked. Permitting it would make every other
    // calldata check decorative.
    const truncated = `${erc20("transfer", [PAYEE, 1n]).slice(0, 10)}deadbeef`;

    const decision = await inspect({
      capability: buildCapability({
        methods: { mode: "ALLOWLIST", allow: ["0xa9059cbb"], deny: [] },
      }),
      transaction: buildCall(USDC, truncated),
      intent: buildIntent({ amountUsd: 1 }),
    });

    expect(decision.decision).toBe("DENY");
    expect(codesOf(decision, "BLOCK")).toContain("CALLDATA_NOT_ALLOWED");
  });

  it("escalates undecodable calldata under a deliberately broad capability", async () => {
    // `mode: "ANY"` is the operator asking for breadth. It is not the operator
    // asking for blindness, so this escalates rather than passing.
    const truncated = `${erc20("transfer", [PAYEE, 1n]).slice(0, 10)}deadbeef`;

    const decision = await inspect({
      capability: buildCapability({
        methods: { mode: "ANY", allow: [], deny: [] },
      }),
      transaction: buildCall(USDC, truncated),
      intent: buildIntent({ amountUsd: 1 }),
    });

    expect(decision.decision).toBe("ESCALATE");
    expect(codesOf(decision, "ESCALATE")).toContain("CALLDATA_NOT_ALLOWED");
  });
});

describe("firewall: calldata recipient extraction", () => {
  const capability = buildCapability({
    methods: {
      mode: "ALLOWLIST",
      allow: [
        "transfer(address,uint256)",
        "transferFrom(address,address,uint256)",
        "approve(address,uint256)",
        "safeTransferFrom(address,address,uint256)",
        "increaseAllowance(address,uint256)",
        "setApprovalForAll(address,bool)",
      ],
      deny: [],
    },
  });

  const cases: Array<{
    name: string;
    data: (recipient: string) => string;
    role: "payee" | "spender";
  }> = [
    {
      name: "transfer",
      data: (to) => erc20("transfer", [to, 25_000_000n]),
      role: "payee",
    },
    {
      name: "transferFrom",
      data: (to) => erc20("transferFrom", [PAYEE, to, 25_000_000n]),
      role: "payee",
    },
    {
      name: "approve",
      data: (to) => erc20("approve", [to, 25_000_000n]),
      role: "spender",
    },
    {
      name: "safeTransferFrom",
      data: (to) => erc20("safeTransferFrom", [PAYEE, to, 7n]),
      role: "payee",
    },
  ];

  for (const testCase of cases) {
    it(`permits ${testCase.name} to an allowlisted address`, async () => {
      const decision = await inspect({
        capability,
        transaction: buildCall(USDC, testCase.data(PAYEE)),
        intent: buildIntent({ amountUsd: 25 }),
      });

      expect(decision.decision).toBe("ALLOW");
    });

    it(`blocks ${testCase.name} whose calldata names an attacker`, async () => {
      // The headline attack: the transaction's `to` is an allowlisted token, so
      // a firewall that only checks `to` treats that token as an open payment
      // channel to anyone on earth.
      const decision = await inspect({
        capability,
        transaction: buildCall(USDC, testCase.data(ATTACKER)),
        intent: buildIntent({ amountUsd: 25 }),
      });

      expect(decision.decision).toBe("DENY");
      expect(decision.result.code).toBe("CALLDATA_RECIPIENT_NOT_ALLOWED");
      expect(decision.result.reason).toContain(ATTACKER);
      expect(decision.result.reason).toContain(testCase.role);
    });
  }

  it("treats an ERC-721 blanket operator as a recipient of authority", async () => {
    const decision = await inspect({
      capability,
      transaction: buildCall(
        USDC,
        erc20("setApprovalForAll", [ATTACKER, true]),
      ),
      intent: buildIntent({ amountUsd: 1 }),
    });

    expect(decision.decision).toBe("DENY");
    expect(codesOf(decision, "BLOCK")).toContain(
      "CALLDATA_RECIPIENT_NOT_ALLOWED",
    );
  });
});

describe("firewall: approval semantics", () => {
  const capability = buildCapability({
    methods: {
      mode: "ALLOWLIST",
      allow: [
        "approve(address,uint256)",
        "increaseAllowance(address,uint256)",
        "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
        "setApprovalForAll(address,bool)",
      ],
      deny: [],
    },
  });

  const approveIntent = buildIntent({ amountUsd: 25, action: "APPROVE" });

  it("permits a bounded allowance to an allowlisted spender", async () => {
    const decision = await inspect({
      capability,
      transaction: buildCall(USDC, erc20("approve", [PAYEE, 25_000_000n])),
      intent: approveIntent,
    });

    expect(decision.decision).toBe("ALLOW");
  });

  it("blocks the canonical unlimited (2^256-1) approval", async () => {
    const decision = await inspect({
      capability,
      transaction: buildCall(USDC, erc20("approve", [PAYEE, UINT256_MAX])),
      intent: approveIntent,
    });

    expect(decision.decision).toBe("DENY");
    expect(decision.result.code).toBe("UNLIMITED_APPROVAL_BLOCKED");
    expect(signalIds(decision)).toContain("UNLIMITED_TOKEN_APPROVAL");
  });

  it("blocks an allowance ground just under 2^256-1", async () => {
    // The threshold is 2^128, not 2^256-1, precisely so a slightly smaller
    // constant cannot evade the check while remaining unlimited in effect.
    const decision = await inspect({
      capability,
      transaction: buildCall(
        USDC,
        erc20("approve", [PAYEE, EFFECTIVELY_UNLIMITED]),
      ),
      intent: approveIntent,
    });

    expect(decision.result.code).toBe("UNLIMITED_APPROVAL_BLOCKED");
  });

  it("permits an allowance one base unit below the unlimited threshold", async () => {
    const decision = await inspect({
      capability,
      transaction: buildCall(
        USDC,
        erc20("approve", [PAYEE, EFFECTIVELY_UNLIMITED - 1n]),
      ),
      intent: approveIntent,
    });

    // NOTE: this is the *boundary* of the block, not an endorsement — see the
    // unpriced-allowance gap recorded in `tests/value-binding.test.ts`.
    expect(codesOf(decision, "BLOCK")).not.toContain(
      "UNLIMITED_APPROVAL_BLOCKED",
    );
  });

  it("blocks an unlimited increaseAllowance as well as an approve", async () => {
    const decision = await inspect({
      capability,
      transaction: buildCall(
        USDC,
        erc20("increaseAllowance", [PAYEE, UINT256_MAX]),
      ),
      intent: approveIntent,
    });

    expect(decision.result.code).toBe("UNLIMITED_APPROVAL_BLOCKED");
  });

  it("blocks a blanket ERC-721 setApprovalForAll as an unlimited grant", async () => {
    const decision = await inspect({
      capability,
      transaction: buildCall(USDC, erc20("setApprovalForAll", [PAYEE, true])),
      intent: approveIntent,
    });

    expect(decision.result.code).toBe("UNLIMITED_APPROVAL_BLOCKED");
  });

  it("permits revoking an allowance (approve to zero)", async () => {
    // A revocation is the safest transaction there is. Blocking it would push
    // operators to disable the check.
    const decision = await inspect({
      capability,
      transaction: buildCall(USDC, erc20("approve", [PAYEE, 0n])),
      intent: approveIntent,
    });

    expect(decision.decision).toBe("ALLOW");
  });

  it("escalates an EIP-2612 permit even to an allowlisted spender", async () => {
    // A signature-based allowance takes effect without a further on-chain
    // decision, so Arx never sees it used. That is a human's call.
    const decision = await inspect({
      capability,
      transaction: buildCall(
        USDC,
        erc20("permit", [
          PAYEE,
          PAYEE,
          25_000_000n,
          BigInt(NOW + 600),
          27,
          `0x${"11".repeat(32)}`,
          `0x${"22".repeat(32)}`,
        ]),
      ),
      intent: approveIntent,
    });

    expect(decision.decision).toBe("ESCALATE");
    expect(codesOf(decision, "ESCALATE")).toContain(
      "UNLIMITED_APPROVAL_BLOCKED",
    );
    // An escalation carries the exact bytes a human is being asked to confirm.
    expect(decision.transaction).toBeDefined();
  });
});

describe("firewall: batch transparency", () => {
  const capability = buildCapability({
    contracts: { mode: "ALLOWLIST", allow: [USDC, MULTICALL3], deny: [] },
    methods: {
      mode: "ALLOWLIST",
      allow: [
        "transfer(address,uint256)",
        "multicall(bytes[])",
        "aggregate3((address,bool,bytes)[])",
        "execute(bytes,bytes[])",
      ],
      deny: [],
    },
  });

  it("permits a batch whose every inner call satisfies policy", async () => {
    const decision = await inspect({
      capability,
      transaction: buildCall(
        USDC,
        batch("multicall", [
          [
            erc20("transfer", [PAYEE, 1_000_000n]),
            erc20("transfer", [PAYEE, 2_000_000n]),
          ],
        ]),
      ),
      intent: buildIntent({ amountUsd: 3 }),
    });

    expect(decision.decision).toBe("ALLOW");
    expect(decision.valueUsd).toBeCloseTo(3, 6);
    expect(signalIds(decision)).toContain("BATCH_WRAPPER");
  });

  it("blocks a denied method nested inside a permitted multicall", async () => {
    // The laundering path: the wrapper's own selector is allowed, so a firewall
    // that stops at depth zero clears everything inside it.
    const decision = await inspect({
      capability,
      transaction: buildCall(
        USDC,
        batch("multicall", [
          [
            erc20("transfer", [PAYEE, 1_000_000n]),
            erc20("approve", [PAYEE, 1_000_000n]),
          ],
        ]),
      ),
      intent: buildIntent({ amountUsd: 1 }),
    });

    expect(decision.decision).toBe("DENY");
    expect(decision.result.code).toBe("METHOD_NOT_ALLOWED");
  });

  it("blocks an attacker payee nested inside a permitted multicall", async () => {
    const decision = await inspect({
      capability,
      transaction: buildCall(
        USDC,
        batch("multicall", [
          [
            erc20("transfer", [PAYEE, 1_000_000n]),
            erc20("transfer", [ATTACKER, 9_000_000n]),
          ],
        ]),
      ),
      intent: buildIntent({ amountUsd: 10 }),
    });

    expect(decision.result.code).toBe("CALLDATA_RECIPIENT_NOT_ALLOWED");
    expect(decision.result.reason).toContain(ATTACKER);
  });

  it("applies the contract policy to each inner target of an aggregate3", async () => {
    // Without this, one allowlisted Multicall3 address is a universal proxy to
    // every contract on the chain, because each inner call names its own target.
    const decision = await inspect({
      capability,
      transaction: buildCall(
        MULTICALL3,
        batch("aggregate3", [
          [[ATTACKER, false, erc20("transfer", [PAYEE, 1n])]],
        ]),
      ),
      intent: buildIntent({ amountUsd: 1 }),
    });

    expect(codesOf(decision, "BLOCK")).toContain("CONTRACT_NOT_ALLOWED");
    expect(decision.decision).toBe("DENY");
  });

  it("refuses a batch whose contents cannot be enumerated", async () => {
    // A wrapper Arx cannot see inside is not a wrapper Arx can clear. The
    // alternative is approving a selector while having no idea what it executes.
    const decision = await inspect({
      capability,
      transaction: buildCall(
        MULTICALL3,
        batch("execute", ["0x0a0b", ["0x1234"]]),
      ),
      intent: buildIntent({ amountUsd: 1 }),
    });

    expect(decision.decision).toBe("DENY");
    expect(codesOf(decision, "BLOCK")).toContain("CALLDATA_NOT_ALLOWED");
    expect(decision.result.reason).toContain("could not enumerate");
    expect(signalIds(decision)).toContain("OPAQUE_BATCH_WRAPPER");
  });
});

describe("firewall: wei, gas and fee ceilings", () => {
  // The point of these ceilings is that they need no oracle, so they still
  // hold when pricing is unavailable. Each is checked at the limit, one under
  // and one over.
  const capability = buildCapability({
    maxAmountUsd: 100_000,
    limits: {
      maxValueWei: "1000000000000000000",
      maxGasLimit: "500000",
      maxFeePerGasWei: "500000000000",
    },
  });

  const honest = (wei: bigint) =>
    buildIntent({ amountUsd: (Number(wei) / 1e18) * 3_200 });

  it("permits a value exactly at the wei ceiling", async () => {
    const decision = await inspect({
      capability,
      transaction: buildTransaction({ value: "1000000000000000000" }),
      intent: honest(10n ** 18n),
    });

    expect(codesOf(decision, "BLOCK")).toEqual([]);
  });

  it("permits a value one wei under the ceiling", async () => {
    const decision = await inspect({
      capability,
      transaction: buildTransaction({ value: "999999999999999999" }),
      intent: honest(10n ** 18n),
    });

    expect(codesOf(decision, "BLOCK")).toEqual([]);
  });

  it("blocks a value one wei over the ceiling", async () => {
    const decision = await inspect({
      capability,
      transaction: buildTransaction({ value: "1000000000000000001" }),
      intent: honest(10n ** 18n),
    });

    expect(decision.result.code).toBe("VALUE_LIMIT_EXCEEDED");
  });

  it("grants no authority over native value when maxValueWei is the default", async () => {
    // `"0"` is honoured literally: it is the closed position, not an unset one.
    const decision = await inspect({
      capability: buildCapability({ limits: {} }),
    });

    expect(decision.result.code).toBe("VALUE_LIMIT_EXCEEDED");
    expect(decision.result.reason).toContain("no authority over native value");
  });

  it("permits a gas limit exactly at the ceiling and blocks one over", async () => {
    const at = await inspect({
      capability,
      transaction: buildTransaction({ gasLimit: "500000" }),
    });
    const over = await inspect({
      capability,
      transaction: buildTransaction({ gasLimit: "500001" }),
    });

    expect(codesOf(at, "BLOCK")).toEqual([]);
    expect(over.result.code).toBe("GAS_LIMIT_EXCEEDED");
  });

  it("permits a fee cap exactly at the ceiling and blocks one over", async () => {
    const at = await inspect({
      capability,
      transaction: buildTransaction({ maxFeePerGas: "500000000000" }),
    });
    const over = await inspect({
      capability,
      transaction: buildTransaction({ maxFeePerGas: "500000000001" }),
    });

    expect(codesOf(at, "BLOCK")).toEqual([]);
    expect(over.result.code).toBe("FEE_LIMIT_EXCEEDED");
  });
});

describe("firewall: contract creation", () => {
  it("blocks a deployment when the capability does not grant it", async () => {
    // An agent that can deploy can manufacture its own counterparty, so this is
    // gated by its own flag rather than folded into the contract allowlist.
    const decision = await inspect({
      transaction: buildTransaction({
        to: undefined,
        value: "0",
        data: "0x60006000",
        gasLimit: "200000",
      }),
      intent: buildIntent({ amountUsd: 1 }),
    });

    expect(decision.decision).toBe("DENY");
    expect(decision.result.code).toBe("CONTRACT_CREATION_NOT_ALLOWED");
    expect(signalIds(decision)).toContain("CONTRACT_CREATION");
  });

  it("permits a deployment when the capability explicitly grants it", async () => {
    const decision = await inspect({
      capability: buildCapability({
        allowContractCreation: true,
        maxRiskScore: 90,
      }),
      transaction: buildTransaction({
        to: undefined,
        value: "0",
        data: "0x60006000",
        gasLimit: "200000",
      }),
      intent: buildIntent({ amountUsd: 1 }),
    });

    expect(decision.decision).toBe("ALLOW");
  });
});

describe("firewall: chain binding", () => {
  it("permits a chain agreed across intent, bytes and capability", async () => {
    const decision = await inspect({});

    expect(codesOf(decision, "BLOCK")).toEqual([]);
  });

  it("blocks bytes bound to a different chain from the declared intent", async () => {
    const decision = await inspect({
      transaction: buildTransaction({ chainId: FOREIGN_CHAIN_ID }),
      intent: buildIntent({ chainId: CHAIN_ID }),
    });

    expect(codesOf(decision, "BLOCK")).toContain("TRANSACTION_CHAIN_MISMATCH");
  });

  it("blocks a chain the capability does not cover, even when the intent agrees", async () => {
    // Otherwise a capability scoped to a testnet authorizes a mainnet payment.
    const decision = await inspect({
      transaction: buildTransaction({ chainId: FOREIGN_CHAIN_ID }),
      intent: buildIntent({ chainId: FOREIGN_CHAIN_ID }),
    });

    expect(codesOf(decision, "BLOCK")).toContain("CHAIN_NOT_ALLOWED");
  });
});

describe("firewall: compositions that matter", () => {
  it("blocks an allowlisted contract carrying an attacker payee", async () => {
    const decision = await inspect({
      transaction: buildCall(USDC, erc20("transfer", [ATTACKER, 25_000_000n])),
      intent: buildIntent({ amountUsd: 25 }),
    });

    expect(decision.decision).toBe("DENY");
    expect(decision.result.code).toBe("CALLDATA_RECIPIENT_NOT_ALLOWED");
    // The evidence names the token so an operator can see `to` was not the payee.
    expect(JSON.stringify(decision.findings)).toContain(USDC);
  });

  it("blocks a declared TRANSFER whose calldata is an approve", async () => {
    const decision = await inspect({
      transaction: buildCall(USDC, erc20("approve", [PAYEE, 25_000_000n])),
      intent: buildIntent({ action: "TRANSFER", amountUsd: 25 }),
    });

    expect(decision.decision).toBe("DENY");
    expect(decision.result.code).toBe("METHOD_NOT_ALLOWED");
  });

  it("scores a declared TRANSFER that carries contract logic", async () => {
    // Even where the method is permitted, the mismatch between the declaration
    // and the bytes is recorded, and a capability with a tighter escalation
    // threshold stops being autonomous because of it.
    const capability = buildCapability({
      methods: {
        mode: "ALLOWLIST",
        allow: ["approve(address,uint256)"],
        deny: [],
      },
      humanApproval: { requiredAboveRiskScore: 30 },
    });

    const decision = await inspect({
      capability,
      transaction: buildCall(USDC, erc20("approve", [PAYEE, 25_000_000n])),
      intent: buildIntent({ action: "TRANSFER", amountUsd: 25 }),
    });

    expect(signalIds(decision)).toContain("CALLDATA_ON_DECLARED_TRANSFER");
    expect(decision.decision).toBe("ESCALATE");
  });

  it("blocks an unpriceable token transfer rather than pricing it at zero", async () => {
    const decision = await inspect({
      capability: buildCapability({
        contracts: { mode: "ALLOWLIST", allow: [UNKNOWN_TOKEN], deny: [] },
      }),
      transaction: buildCall(
        UNKNOWN_TOKEN,
        erc20("transfer", [PAYEE, 25_000_000n]),
      ),
      intent: buildIntent({ amountUsd: 25 }),
    });

    expect(decision.valuePriced).toBe(false);
    expect(decision.decision).toBe("ESCALATE");
    expect(codesOf(decision, "ESCALATE")).toContain("PRICE_UNAVAILABLE");
  });
});

describe("firewall: severity resolution", () => {
  it("resolves a BLOCK ahead of every ESCALATE", async () => {
    // Risk is advisory and human approval is a gate, not a bypass: a failed
    // policy comparison cannot be rescued by routing it to a person.
    const decision = await inspect({
      capability: buildCapability({
        humanApproval: { alwaysRequired: true },
      }),
      transaction: buildTransaction({ to: ATTACKER }),
    });

    expect(codesOf(decision, "ESCALATE").length).toBeGreaterThan(0);
    expect(decision.decision).toBe("DENY");
    expect(decision.result.code).toBe("RECIPIENT_NOT_ALLOWED");
    expect(decision.transaction).toBeUndefined();
  });

  it("blocks above the hard risk ceiling instead of asking a human", async () => {
    // `maxRiskScore` says "no person at a device should be asked to look at
    // this at all" — a confirmation screen is a poor place to catch an
    // address-poisoning substitution, because the whole attack is looking right.
    const decision = await inspect({
      capability: buildCapability({
        maxRiskScore: 20,
        humanApproval: { requiredAboveRiskScore: 10 },
      }),
      transaction: buildTransaction({ to: ATTACKER }),
    });

    expect(codesOf(decision, "BLOCK")).toContain("RISK_SCORE_EXCEEDED");
    expect(decision.decision).toBe("DENY");
  });

  it("cannot be rescued by a zero risk score", async () => {
    const decision = await inspect({
      transaction: buildTransaction({ to: ATTACKER, value: "1" }),
      intent: buildIntent({ amountUsd: 0.0000032 }),
      capability: buildCapability({
        maxRiskScore: 100,
        humanApproval: { requiredForUnknownRecipient: false },
      }),
    });

    expect(decision.decision).toBe("DENY");
    expect(decision.result.code).toBe("RECIPIENT_NOT_ALLOWED");
  });
});

describe("firewall: a policy denial is never overturned", () => {
  it("returns the capability layer's verdict untouched", async () => {
    // The transaction below would otherwise pass every firewall check. The
    // firewall must add nothing and overturn nothing.
    const decision = await inspect({
      policyResult: deny(
        "ACTION_NOT_ALLOWED",
        "action TRANSFER is not in this capability's allowedActions",
      ) as never,
    });

    expect(decision.allowed).toBe(false);
    expect(decision.decision).toBe("DENY");
    expect(decision.result.code).toBe("ACTION_NOT_ALLOWED");
    expect(decision.transaction).toBeUndefined();
    // An audit reader must be able to tell "inspected and denied" from
    // "never inspected".
    expect(decision.findings).toHaveLength(1);
    expect(decision.findings[0]?.severity).toBe("INFO");
    expect(decision.findings[0]?.message).toContain(
      "no transaction-level check was run",
    );
    expect(decision.riskScore).toBe(0);
    expect(decision.valuePriced).toBe(false);
  });

  for (const code of [
    "CAPABILITY_EXPIRED",
    "CAPABILITY_REVOKED",
    "AGENT_MISMATCH",
    "REPLAY_DETECTED",
  ] as const) {
    it(`preserves ${code} rather than re-deciding it`, async () => {
      const decision = await inspect({
        policyResult: deny(code, "denied upstream") as never,
      });

      expect(decision.result.code).toBe(code);
      expect(decision.allowed).toBe(false);
    });
  }
});

describe("firewall: the compatibility shim", () => {
  it("says plainly that it enforced nothing when called without context", async () => {
    // `process()` with no capability is a passthrough. It must be impossible to
    // mistake for an inspection, or an audit log would show a transaction as
    // cleared when nothing looked at it.
    const decision = firewall.process(
      buildTransaction(),
      allow("upstream allowed"),
    );

    expect(decision.decision).toBe("ALLOW");
    expect(decision.findings[0]?.code).toBe("INTERNAL_ERROR");
    expect(decision.findings[0]?.message).toContain(
      "no transaction-level check could run",
    );
    expect(decision.valuePriced).toBe(false);
  });

  it("still refuses an unauthorized recipient when given context", async () => {
    const decision = firewall.process(
      buildTransaction({ to: ATTACKER }),
      allow("upstream allowed"),
      { capability: buildCapability(), intent: buildIntent(), now: NOW },
    );

    expect(decision.decision).toBe("DENY");
    expect(decision.result.code).toBe("RECIPIENT_NOT_ALLOWED");
  });

  it("escalates rather than allowing, because it cannot price anything", async () => {
    // The synchronous path has no oracle by construction, so a USD-dependent
    // decision degrades to ESCALATE. Degrading to ALLOW would be the bug.
    const decision = firewall.process(
      buildTransaction(),
      allow("upstream allowed"),
      { capability: buildCapability(), intent: buildIntent(), now: NOW },
    );

    expect(decision.decision).toBe("ESCALATE");
    expect(decision.valuePriced).toBe(false);
  });
});
