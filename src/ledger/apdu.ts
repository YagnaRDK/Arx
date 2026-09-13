/**
 * APDU framing, status-word interpretation, and the transport seam.
 *
 * An APDU (ISO 7816-4, as used by every Ledger app) is
 * `CLA | INS | P1 | P2 | Lc | data`, and the device answers with
 * `response data | SW1 | SW2`. Nothing here is Ethereum-specific: this module
 * is the codec, `eth-app.ts` is the command set.
 *
 * Status-word values are taken from Ledger's own registry, not guessed:
 * https://github.com/LedgerHQ/ledger-live/blob/develop/libs/ledgerjs/packages/errors/src/index.ts
 * (published as `StatusCodes` in `@ledgerhq/errors`; the human-readable strings
 * follow that file's `getAltStatusMessage`).
 */

import type { DecisionCode } from "../core/codes";
import { ArxError } from "../core/errors";

/**
 * `Lc` is a single byte, so one APDU can carry at most 255 data bytes. The
 * Ethereum app's SIGN ETH TRANSACTION documentation states the same ceiling:
 * the RLP is "streamed to the device in 255 bytes maximum data chunks".
 * https://github.com/LedgerHQ/app-ethereum/blob/master/doc/ethapp.adoc
 */
export const APDU_MAX_DATA_LENGTH = 255;

/** Length of the trailing status word on every response. */
export const STATUS_WORD_LENGTH = 2;

export type Apdu = {
  cla: number;
  ins: number;
  p1: number;
  p2: number;
  data?: Uint8Array;
};

export type ApduResponse = {
  /** Response payload with the status word stripped off. */
  data: Uint8Array;
  /** `SW1 << 8 | SW2`. */
  statusWord: number;
};

/**
 * The one thing Arx needs from a device connection.
 *
 * Deliberately narrow: an implementation sends the framed command bytes and
 * returns the raw reply *including* the status word. Interpreting the status
 * word is this module's job, not the transport's, so every transport fails the
 * same way.
 */
export interface LedgerTransport {
  readonly name: string;
  /** Sends one complete APDU and resolves with `data || SW1 || SW2`. */
  exchange(apdu: Uint8Array): Promise<Uint8Array>;
  /** Releases any underlying socket. Optional: stateless transports have none. */
  close?(): Promise<void>;
}

function assertByte(value: number, field: string): number {
  if (!Number.isInteger(value) || value < 0 || value > 0xff) {
    throw new ArxError(
      "SIGNING_FAILED",
      `APDU field ${field} must be a single byte (got ${value})`,
    );
  }

  return value;
}

/** Serializes an APDU to `CLA | INS | P1 | P2 | Lc | data`. */
export function encodeApdu(apdu: Apdu): Uint8Array {
  const data = apdu.data ?? new Uint8Array(0);

  if (data.length > APDU_MAX_DATA_LENGTH) {
    throw new ArxError(
      "SIGNING_FAILED",
      `APDU data length ${data.length} exceeds the ${APDU_MAX_DATA_LENGTH}-byte ceiling; the caller must chunk`,
    );
  }

  const encoded = new Uint8Array(5 + data.length);

  encoded[0] = assertByte(apdu.cla, "CLA");
  encoded[1] = assertByte(apdu.ins, "INS");
  encoded[2] = assertByte(apdu.p1, "P1");
  encoded[3] = assertByte(apdu.p2, "P2");
  encoded[4] = data.length;
  encoded.set(data, 5);

  return encoded;
}

/** Splits a device reply into payload and status word. */
export function parseApduResponse(raw: Uint8Array): ApduResponse {
  if (raw.length < STATUS_WORD_LENGTH) {
    throw new ArxError(
      "SIGNING_FAILED",
      `Device reply is ${raw.length} byte(s); an APDU response always ends in a 2-byte status word`,
    );
  }

  const sw1 = raw[raw.length - 2] as number;
  const sw2 = raw[raw.length - 1] as number;

  return {
    data: raw.subarray(0, raw.length - STATUS_WORD_LENGTH),
    statusWord: (sw1 << 8) | sw2,
  };
}

export const STATUS_WORD_OK = 0x9000;

export type StatusWordInfo = {
  statusWord: number;
  /** Ledger's own constant name, for logs and the audit record. */
  name: string;
  message: string;
  /**
   * `null` for `0x9000`. Otherwise the Arx decision code this device outcome
   * maps onto.
   */
  code: DecisionCode | null;
};

/**
 * The status words Arx interprets.
 *
 * Names mirror `StatusCodes` in `@ledgerhq/errors`; the Arx code beside each
 * one is the authorization meaning. Note `CONDITIONS_OF_USE_NOT_SATISFIED`
 * (0x6985) and `USER_REFUSED_ON_DEVICE` (0x5501): a human declining on the
 * device is a *correct* outcome of the approval boundary, so it maps to
 * `SIGNER_REJECTED_BY_USER` rather than a signing failure.
 */
const STATUS_WORDS: Record<number, Omit<StatusWordInfo, "statusWord">> = {
  0x9000: { name: "OK", message: "Success", code: null },

  0x6985: {
    name: "CONDITIONS_OF_USE_NOT_SATISFIED",
    message: "Rejected on the device by the human operator",
    code: "SIGNER_REJECTED_BY_USER",
  },
  0x5501: {
    name: "USER_REFUSED_ON_DEVICE",
    message: "Refused on the device by the human operator",
    code: "SIGNER_REJECTED_BY_USER",
  },

  0x6a80: {
    name: "INCORRECT_DATA",
    message:
      "The device rejected the command payload as invalid (malformed RLP, bad derivation path, or an unsupported transaction type)",
    code: "INVALID_TRANSACTION",
  },
  0x6700: {
    name: "INCORRECT_LENGTH",
    message: "The device rejected the command length",
    code: "SIGNING_FAILED",
  },
  0x6b00: {
    name: "INCORRECT_P1_P2",
    message: "The device rejected the command parameters P1/P2",
    code: "SIGNING_FAILED",
  },

  0x6d00: {
    name: "INS_NOT_SUPPORTED",
    message:
      "The open application does not implement this instruction; the Ethereum app may be too old",
    code: "SIGNER_UNAVAILABLE",
  },
  0x6e00: {
    name: "CLA_NOT_SUPPORTED",
    message:
      "The open application does not accept CLA 0xE0 — the Ethereum app is not the application currently open on the device",
    code: "SIGNER_UNAVAILABLE",
  },
  0x6d02: {
    name: "UNKNOWN_APDU",
    message: "The open application did not recognise this APDU",
    code: "SIGNER_UNAVAILABLE",
  },

  0x5515: {
    name: "LOCKED_DEVICE",
    message: "The device is locked; unlock it and reopen the Ethereum app",
    code: "SIGNER_UNAVAILABLE",
  },
  0x6982: {
    name: "SECURITY_STATUS_NOT_SATISFIED",
    message:
      "Security status not satisfied (device locked or insufficient access rights)",
    code: "SIGNER_UNAVAILABLE",
  },
  0x6d07: {
    name: "DEVICE_NOT_ONBOARDED",
    message: "The device has no seed configured",
    code: "SIGNER_UNAVAILABLE",
  },
  0x6f00: {
    name: "TECHNICAL_PROBLEM",
    message: "Internal device error",
    code: "SIGNING_FAILED",
  },
};

/** Describes a status word, falling back to an honest "unknown" entry. */
export function describeStatusWord(statusWord: number): StatusWordInfo {
  const known = STATUS_WORDS[statusWord];

  if (known !== undefined) {
    return { statusWord, ...known };
  }

  // 0x6Fxx is the documented range for "internal error, please report".
  if (statusWord >= 0x6f00 && statusWord <= 0x6fff) {
    return {
      statusWord,
      name: "TECHNICAL_PROBLEM",
      message: "Internal device error",
      code: "SIGNING_FAILED",
    };
  }

  // An unrecognised status word is never treated as success: fail closed.
  return {
    statusWord,
    name: "UNKNOWN_STATUS_WORD",
    message: `Device returned an unrecognised status word 0x${statusWord
      .toString(16)
      .padStart(4, "0")}`,
    code: "SIGNING_FAILED",
  };
}

export function isSuccess(statusWord: number): boolean {
  return statusWord === STATUS_WORD_OK;
}

/**
 * Whether the device outcome was a human declining.
 *
 * Callers use this to report a clean `SIGNER_REJECTED_BY_USER` decision instead
 * of an error: the person exercising the approval boundary said no, which is the
 * boundary working.
 */
export function isUserRejection(statusWord: number): boolean {
  return describeStatusWord(statusWord).code === "SIGNER_REJECTED_BY_USER";
}

/** Turns a non-success status word into an `ArxError` carrying its decision code. */
export function statusWordError(
  statusWord: number,
  context: string,
): ArxError {
  const info = describeStatusWord(statusWord);

  return new ArxError(
    info.code ?? "SIGNING_FAILED",
    `${context}: ${info.message}`,
    {
      details: {
        statusWord: `0x${statusWord.toString(16).padStart(4, "0")}`,
        statusWordName: info.name,
      },
    },
  );
}

/**
 * Sends one APDU and returns its payload, throwing on any non-`0x9000` reply.
 *
 * The throw is the point: an HTTP 200 from an emulator, or a socket that
 * returned bytes, is not evidence that the device accepted the command.
 */
export async function sendApdu(
  transport: LedgerTransport,
  apdu: Apdu,
  context: string,
): Promise<Uint8Array> {
  const raw = await transport.exchange(encodeApdu(apdu));
  const response = parseApduResponse(raw);

  if (!isSuccess(response.statusWord)) {
    throw statusWordError(response.statusWord, context);
  }

  return response.data;
}

// --- hex helpers, kept here so transports and the app share one encoding ----

export function bytesToHex(bytes: Uint8Array): string {
  let hex = "";

  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }

  return hex;
}

export function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.startsWith("0x") ? hex.slice(2) : hex;

  if (normalized.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(normalized)) {
    throw new ArxError(
      "SIGNING_FAILED",
      "Expected an even-length hexadecimal string",
    );
  }

  const bytes = new Uint8Array(normalized.length / 2);

  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(
      normalized.slice(index * 2, index * 2 + 2),
      16,
    );
  }

  return bytes;
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);

  let offset = 0;

  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }

  return out;
}
