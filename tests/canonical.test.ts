import { describe, expect, it } from "bun:test";

import {
  CanonicalizationError,
  canonicalize,
} from "../src/crypto/canonical";
import { hashCanonical } from "../src/crypto/hash";

describe("canonical serialization", () => {
  it("is independent of object key insertion order", () => {
    // This is the property the whole approval-binding scheme rests on. If it
    // failed, two structurally identical transactions could hash differently.
    const a = { to: "0xabc", value: "1", chainId: 1 };
    const b = { chainId: 1, value: "1", to: "0xabc" };

    expect(canonicalize(a)).toBe(canonicalize(b));
    expect(hashCanonical(a)).toBe(hashCanonical(b));
  });

  it("sorts keys at every level of nesting", () => {
    expect(canonicalize({ b: { d: 1, c: 2 }, a: 3 })).toBe(
      '{"a":3,"b":{"c":2,"d":1}}',
    );
  });

  it("preserves array order, which is semantic", () => {
    expect(canonicalize([3, 1, 2])).toBe("[3,1,2]");
    expect(canonicalize([1, 2, 3])).not.toBe(canonicalize([3, 2, 1]));
  });

  it("omits undefined properties so an unset optional hashes as absent", () => {
    expect(canonicalize({ a: 1, b: undefined })).toBe('{"a":1}');
    expect(hashCanonical({ a: 1, b: undefined })).toBe(hashCanonical({ a: 1 }));
  });

  it("normalizes negative zero", () => {
    expect(canonicalize(-0)).toBe("0");
    expect(canonicalize({ v: -0 })).toBe(canonicalize({ v: 0 }));
  });

  it("rejects values JSON cannot round-trip", () => {
    expect(() => canonicalize(Number.NaN)).toThrow(CanonicalizationError);
    expect(() => canonicalize(Number.POSITIVE_INFINITY)).toThrow(
      CanonicalizationError,
    );
    expect(() => canonicalize(undefined)).toThrow(CanonicalizationError);
    expect(() => canonicalize(() => 1)).toThrow(CanonicalizationError);
    expect(() => canonicalize(Symbol("x"))).toThrow(CanonicalizationError);
  });

  it("rejects bigint rather than silently choosing a representation", () => {
    expect(() => canonicalize(1n)).toThrow(CanonicalizationError);
  });

  it("rejects Date rather than guessing a serialization", () => {
    expect(() => canonicalize(new Date(0))).toThrow(CanonicalizationError);
  });

  it("escapes strings so a crafted value cannot forge structure", () => {
    // Without escaping, a value containing a quote and a brace could make two
    // different objects serialize to the same bytes.
    const a = { name: '","evil":"1' };
    const b = { name: "x", evil: "1" };

    expect(canonicalize(a)).not.toBe(canonicalize(b));
    expect(canonicalize({ q: '"' })).toBe('{"q":"\\""}');
  });

  it("distinguishes a numeric value from its string spelling", () => {
    expect(canonicalize({ v: 1 })).not.toBe(canonicalize({ v: "1" }));
  });

  it("refuses pathologically nested input instead of overflowing the stack", () => {
    let nested: unknown = 1;
    for (let i = 0; i < 100; i += 1) {
      nested = { nested };
    }

    expect(() => canonicalize(nested)).toThrow(CanonicalizationError);
  });

  it("handles null distinctly from absent", () => {
    expect(canonicalize({ a: null })).toBe('{"a":null}');
    expect(canonicalize({ a: null })).not.toBe(canonicalize({}));
  });
});
