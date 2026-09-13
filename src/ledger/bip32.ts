/**
 * BIP32 derivation-path parsing and the on-the-wire encoding Ledger apps expect.
 *
 * The encoding is defined by the Ethereum app's APDU specification: one byte of
 * derivation count, then each element as a 4-byte big-endian integer, with
 * hardened elements carrying the high bit.
 *
 * Source (input-data table, "Number of BIP 32 derivations to perform (max 10)"
 * followed by 4-byte big-endian derivation indices):
 * https://github.com/LedgerHQ/app-ethereum/blob/master/doc/ethapp.adoc
 *
 * Reference implementation (`splitPath`, `buffer.writeUInt32BE`):
 * https://github.com/LedgerHQ/ledger-live/blob/develop/libs/ledgerjs/packages/hw-app-eth/src/utils.ts
 */

import { ArxError } from "../core/errors";

/** The high bit that marks a derivation element as hardened (BIP32 `'`). */
export const HARDENED_OFFSET = 0x80000000;

/**
 * The app's stated ceiling: "Number of BIP 32 derivations to perform (max 10)".
 * Sending more would overflow the app's path buffer, so we refuse locally
 * rather than letting the device answer with an opaque status word.
 */
export const MAX_DERIVATION_ELEMENTS = 10;

/** Largest non-hardened index: indices are uint31 before the hardened bit. */
const MAX_INDEX = HARDENED_OFFSET - 1;

export type ParsedDerivationPath = {
  /** Canonical textual form, without a leading `m/` and using `'` for hardened. */
  path: string;
  /** Raw uint32 elements, hardened bit already applied. */
  elements: number[];
};

/**
 * Parses a path such as `44'/60'/0'/0/0` into its uint32 elements.
 *
 * Deliberately stricter than `hw-app-eth`'s `splitPath`, which silently skips
 * any segment that fails to parse as a number. Silently dropping a segment
 * would sign with a *different key* than the caller named — so anything we
 * cannot interpret exactly is rejected.
 */
export function parseDerivationPath(path: string): ParsedDerivationPath {
  const trimmed = path.trim();

  if (trimmed.length === 0) {
    throw new ArxError("INVALID_TRANSACTION", "Derivation path is empty");
  }

  // `m/44'/60'/...` and `44'/60'/...` name the same path.
  const withoutPrefix = /^m\//i.test(trimmed) ? trimmed.slice(2) : trimmed;

  if (withoutPrefix.length === 0 || withoutPrefix.endsWith("/")) {
    throw new ArxError(
      "INVALID_TRANSACTION",
      `Malformed derivation path: "${path}"`,
    );
  }

  const segments = withoutPrefix.split("/");

  if (segments.length > MAX_DERIVATION_ELEMENTS) {
    throw new ArxError(
      "INVALID_TRANSACTION",
      `Derivation path has ${segments.length} elements; the Ethereum app accepts at most ${MAX_DERIVATION_ELEMENTS}`,
    );
  }

  const elements: number[] = [];

  for (const segment of segments) {
    // `'` is the canonical hardened marker; `h`/`H` is the common ASCII variant.
    const hardened = /['hH]$/.test(segment);
    const digits = hardened ? segment.slice(0, -1) : segment;

    if (!/^\d+$/.test(digits)) {
      throw new ArxError(
        "INVALID_TRANSACTION",
        `Derivation path segment "${segment}" is not a non-negative integer`,
      );
    }

    const index = Number(digits);

    if (!Number.isSafeInteger(index) || index > MAX_INDEX) {
      throw new ArxError(
        "INVALID_TRANSACTION",
        `Derivation path segment "${segment}" exceeds the uint31 index range`,
      );
    }

    elements.push(hardened ? index + HARDENED_OFFSET : index);
  }

  return { path: formatDerivationPath(elements), elements };
}

/** Renders uint32 elements back to canonical text, for logs and audit records. */
export function formatDerivationPath(elements: readonly number[]): string {
  return elements
    .map((element) =>
      element >= HARDENED_OFFSET
        ? `${element - HARDENED_OFFSET}'`
        : String(element),
    )
    .join("/");
}

/**
 * Encodes a derivation path as the Ethereum app's APDU path prefix:
 * `[count, index0_be32, index1_be32, ...]`.
 */
export function encodeDerivationPath(path: string): Uint8Array {
  const { elements } = parseDerivationPath(path);

  const encoded = new Uint8Array(1 + elements.length * 4);
  encoded[0] = elements.length;

  const view = new DataView(encoded.buffer);

  elements.forEach((element, index) => {
    // `false` = big endian, matching `writeUInt32BE` in hw-app-eth.
    view.setUint32(1 + index * 4, element, false);
  });

  return encoded;
}

/** Byte length of the encoded path prefix, needed to size the first APDU chunk. */
export function encodedDerivationPathLength(path: string): number {
  return 1 + parseDerivationPath(path).elements.length * 4;
}
