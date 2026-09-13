/**
 * RFC 8785 (JSON Canonicalization Scheme) style serialization.
 *
 * Every hash Arx computes — transaction identity, approval binding, audit chain
 * links — flows through here. Using plain `JSON.stringify` would make the digest
 * depend on object key insertion order, so two structurally identical
 * transactions could produce different hashes (or, worse, a reordered payload
 * could be made to collide with an approval bound to a different one).
 */

export class CanonicalizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalizationError";
  }
}

/**
 * Serializes a number the way JCS requires: integers without a decimal point,
 * and no `-0`, `NaN` or `Infinity` (which JSON cannot represent round-trippably).
 */
function canonicalizeNumber(value: number): string {
  if (!Number.isFinite(value)) {
    throw new CanonicalizationError(
      `Cannot canonicalize non-finite number: ${value}`,
    );
  }

  if (Object.is(value, -0)) {
    return "0";
  }

  return JSON.stringify(value);
}

function canonicalizeString(value: string): string {
  return JSON.stringify(value);
}

/**
 * JCS orders object members by the UTF-16 code units of their keys, which is
 * exactly what `Array.prototype.sort` does by default on JS strings.
 */
function sortKeys(keys: string[]): string[] {
  return [...keys].sort();
}

export function canonicalize(value: unknown, depth = 0): string {
  if (depth > 64) {
    throw new CanonicalizationError("Maximum nesting depth exceeded");
  }

  if (value === null) {
    return "null";
  }

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";

    case "number":
      return canonicalizeNumber(value);

    case "string":
      return canonicalizeString(value);

    case "bigint":
      // JSON has no bigint. Callers must convert to a decimal string before
      // hashing so the representation is explicit and stable, rather than
      // letting us silently pick one here.
      throw new CanonicalizationError(
        "Cannot canonicalize bigint; convert to a decimal string first",
      );

    case "undefined":
      throw new CanonicalizationError(
        "Cannot canonicalize undefined; omit the property instead",
      );

    case "function":
    case "symbol":
      throw new CanonicalizationError(`Cannot canonicalize ${typeof value}`);
  }

  if (Array.isArray(value)) {
    const items = value.map((item) => canonicalize(item, depth + 1));
    return `[${items.join(",")}]`;
  }

  if (value instanceof Date) {
    throw new CanonicalizationError(
      "Cannot canonicalize Date; convert to a number or ISO string first",
    );
  }

  const record = value as Record<string, unknown>;

  // `undefined` properties are dropped rather than rejected, so that optional
  // fields left unset hash identically to fields that were never present.
  const keys = sortKeys(
    Object.keys(record).filter((key) => record[key] !== undefined),
  );

  const members = keys.map(
    (key) => `${canonicalizeString(key)}:${canonicalize(record[key], depth + 1)}`,
  );

  return `{${members.join(",")}}`;
}
