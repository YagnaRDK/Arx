import { describe, expect, it } from "bun:test";

import {
  PolicySetSchema,
  evaluatePolicySet,
} from "../src/types/policy-sets";

function set(input: unknown) {
  return PolicySetSchema.parse(input);
}

describe("policy sets", () => {
  it("defaults to a fail-closed allowlist", () => {
    // The single most important default in the system: a capability created
    // without an explicit recipient list authorizes no recipient at all.
    const parsed = set(undefined);

    expect(parsed.mode).toBe("ALLOWLIST");
    expect(evaluatePolicySet(parsed, ["0xabc"])).toEqual({
      outcome: "DENIED",
      reason: "NOT_ON_ALLOWLIST",
    });
  });

  it("permits an entry on the allowlist", () => {
    expect(
      evaluatePolicySet(set({ allow: ["0xabc"] }), ["0xabc"]).outcome,
    ).toBe("ALLOWED");
  });

  it("denies an entry that is not on the allowlist", () => {
    expect(evaluatePolicySet(set({ allow: ["0xabc"] }), ["0xdef"])).toEqual({
      outcome: "DENIED",
      reason: "NOT_ON_ALLOWLIST",
    });
  });

  it("lets a deny entry override an allow entry", () => {
    // Revoking one address must never require rebuilding the allowlist.
    expect(
      evaluatePolicySet(set({ allow: ["0xabc"], deny: ["0xabc"] }), ["0xabc"]),
    ).toEqual({ outcome: "DENIED", reason: "EXPLICIT_DENY" });
  });

  it("applies the denylist even in ANY mode", () => {
    expect(
      evaluatePolicySet(set({ mode: "ANY", deny: ["0xbad"] }), ["0xbad"]),
    ).toEqual({ outcome: "DENIED", reason: "EXPLICIT_DENY" });

    expect(
      evaluatePolicySet(set({ mode: "ANY", deny: ["0xbad"] }), ["0xok"])
        .outcome,
    ).toBe("ALLOWED");
  });

  it("compares case-insensitively", () => {
    // The same address legitimately appears as lowercase hex and as an EIP-55
    // checksummed string; an allowlist that missed one spelling would be a
    // silent bypass.
    expect(
      evaluatePolicySet(set({ allow: ["0xABCdef"] }), ["0xabcdef"]).outcome,
    ).toBe("ALLOWED");

    expect(
      evaluatePolicySet(set({ deny: ["0xABCdef"] }), ["0xabcdef"]).outcome,
    ).toBe("DENIED");
  });

  it("allows when any one candidate matches", () => {
    // A candidate list lets one check cover several spellings of the same
    // target — an address and the ENS name it resolved from.
    expect(
      evaluatePolicySet(set({ allow: ["alice.eth"] }), [
        "0xabc",
        "alice.eth",
      ]).outcome,
    ).toBe("ALLOWED");
  });

  it("denies when any one candidate is denied, even if another is allowed", () => {
    // If a name resolves to a denied address, the denial must win over the
    // name being allowlisted.
    expect(
      evaluatePolicySet(set({ allow: ["alice.eth"], deny: ["0xbad"] }), [
        "0xbad",
        "alice.eth",
      ]),
    ).toEqual({ outcome: "DENIED", reason: "EXPLICIT_DENY" });
  });

  it("denies an empty candidate list", () => {
    expect(evaluatePolicySet(set({ allow: ["0xabc"] }), []).outcome).toBe(
      "DENIED",
    );
    expect(evaluatePolicySet(set({ allow: ["0xabc"] }), [""]).outcome).toBe(
      "DENIED",
    );
  });
});
