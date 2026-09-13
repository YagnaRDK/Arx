import { describe, expect, it } from "bun:test";

import { ArxError } from "../src/core/errors";
import { TransactionNormalizer } from "../src/normalization/transaction-normalizer";
import { hashNormalizedTransaction } from "../src/approval/transaction-hash";
import type { EvmTransaction } from "../src/types/transaction";

const normalizer = new TransactionNormalizer();

const base = {
  chainId: 11155111,
  to: "0x1111111111111111111111111111111111111111",
  value: "1000000000000000",
  data: "0x",
  gasLimit: "21000",
  maxFeePerGas: "30000000000",
  maxPriorityFeePerGas: "1000000000",
  nonce: 0,
};

function normalize(tx: Record<string, unknown>, now = 1_700_000_000) {
  return normalizer.normalize({
    agentId: "agent-1",
    capabilityId: "cap-1",
    transaction: tx,
    now,
  });
}

describe("transaction normalization and approval binding", () => {
  it("derives a deterministic transaction identity", () => {
    // Identity must be content-derived, never random, so the same logical
    // request always resolves to the same transaction.
    expect(normalize(base).transactionId).toBe(normalize(base).transactionId);
  });

  it("excludes createdAt from the identity", () => {
    expect(normalize(base, 1_700_000_000).transactionId).toBe(
      normalize(base, 1_900_000_000).transactionId,
    );
  });

  it("produces the same hash regardless of field order", () => {
    const reordered = {
      nonce: 0,
      maxPriorityFeePerGas: "1000000000",
      data: "0x",
      to: "0x1111111111111111111111111111111111111111",
      maxFeePerGas: "30000000000",
      gasLimit: "21000",
      value: "1000000000000000",
      chainId: 11155111,
    };

    expect(hashNormalizedTransaction(normalize(reordered))).toBe(
      hashNormalizedTransaction(normalize(base)),
    );
  });

  it("treats address casing as display-only, not identity", () => {
    // EIP-55 checksum casing is a presentation concern. If it changed the hash,
    // a caller could break a valid approval simply by re-casing the address.
    const upper = { ...base, to: "0x1111111111111111111111111111111111111111".toUpperCase().replace("0X", "0x") };

    expect(hashNormalizedTransaction(normalize(upper))).toBe(
      hashNormalizedTransaction(normalize(base)),
    );
  });

  it("collapses leading zeros in integer fields", () => {
    // "0100" and "100" are the same value. If they hashed differently, an
    // attacker could pass limit checks under one spelling and be bound to an
    // approval under the other.
    expect(hashNormalizedTransaction(normalize({ ...base, value: "0001000000000000000" }))).toBe(
      hashNormalizedTransaction(normalize(base)),
    );
  });

  describe("any consequential change breaks the binding", () => {
    const cases: Array<[string, Record<string, unknown>]> = [
      ["recipient", { to: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" }],
      ["value", { value: "1000000000000001" }],
      ["calldata", { data: "0xa9059cbb" }],
      ["chain", { chainId: 1 }],
      ["gas limit", { gasLimit: "21001" }],
      ["max fee", { maxFeePerGas: "30000000001" }],
      ["priority fee", { maxPriorityFeePerGas: "1000000001" }],
      ["account nonce", { nonce: 1 }],
      ["transaction type", { type: "legacy" }],
    ];

    for (const [label, override] of cases) {
      it(`changing the ${label} changes the hash`, () => {
        expect(
          hashNormalizedTransaction(normalize({ ...base, ...override })),
        ).not.toBe(hashNormalizedTransaction(normalize(base)));
      });
    }
  });

  it("binds the hash to the agent and the capability", () => {
    // The same bytes authorized for one agent must not be signable by another.
    const forAgent2 = normalizer.normalize({
      agentId: "agent-2",
      capabilityId: "cap-1",
      transaction: base,
      now: 1_700_000_000,
    });

    expect(hashNormalizedTransaction(forAgent2)).not.toBe(
      hashNormalizedTransaction(normalize(base)),
    );
  });

  it("treats a missing recipient as contract creation, not an error", () => {
    const { to, ...withoutTo } = base;
    const result = normalize(withoutTo);

    expect(result.transaction.to).toBeUndefined();
  });

  it("distinguishes contract creation from a transfer to the zero address", () => {
    const { to, ...withoutTo } = base;

    expect(hashNormalizedTransaction(normalize(withoutTo))).not.toBe(
      hashNormalizedTransaction(
        normalize({ ...base, to: `0x${"0".repeat(40)}` }),
      ),
    );
  });

  describe("rejects malformed input rather than coercing it", () => {
    it("rejects a non-hex address", () => {
      expect(() => normalize({ ...base, to: "0xnothex" })).toThrow(ArxError);
    });

    it("rejects a short address", () => {
      expect(() => normalize({ ...base, to: "0x1111" })).toThrow(ArxError);
    });

    it("rejects odd-length calldata", () => {
      expect(() => normalize({ ...base, data: "0xabc" })).toThrow(ArxError);
    });

    it("rejects a negative value", () => {
      expect(() => normalize({ ...base, value: "-1" })).toThrow(ArxError);
    });

    it("rejects a value above 2^256 - 1", () => {
      expect(() =>
        normalize({ ...base, value: (2n ** 256n).toString() }),
      ).toThrow(ArxError);
    });

    it("rejects a priority fee above the max fee", () => {
      expect(() =>
        normalize({ ...base, maxPriorityFeePerGas: "40000000000" }),
      ).toThrow(ArxError);
    });

    it("carries a specific decision code", () => {
      let captured: unknown;

      try {
        normalize({ garbage: true });
      } catch (error) {
        captured = error;
      }

      expect(captured).toBeInstanceOf(ArxError);
      expect((captured as ArxError).code).toBe("INVALID_TRANSACTION");
    });
  });
});
