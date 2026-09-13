/**
 * An in-process implementation of the app-ethereum APDU protocol.
 *
 * Why this exists: running the real Ledger Ethereum app needs Speculos, which
 * needs Docker. Without it the only alternative is the mock signer, whose
 * output is a placeholder rather than a signature — which leaves the most
 * important claim in the project untested, namely that the APDU codec is
 * correct and that a returned signature genuinely recovers to the device's
 * address.
 *
 * So this speaks the real protocol. It parses the same APDUs, accumulates the
 * same chunked payload, decides completeness from the RLP length header the way
 * the app's streaming parser does, applies the same `v` conventions, and
 * returns the same response layouts — keyed from the standard Speculos test
 * mnemonic, so it reports the same address the emulator would:
 * `0xDad77910DbDFdE764fC21FCD4E74D71bBACA6D8D` at `m/44'/60'/0'/0/0`.
 *
 * Real here: the APDU framing, the RLP payload, the chunking, the secp256k1
 * signature, and the address recovery that verifies it.
 *
 * NOT real, and never to be claimed: hardware isolation, a Secure Element, a
 * Trusted Display, and human confirmation. The key is in this process's memory.
 * Results carry the adapter name `speculos-sim` and `emulated: true`, and the
 * mode is refused outright when NODE_ENV is production.
 */

import { keccak256, type Hex } from "viem";
import { mnemonicToAccount } from "viem/accounts";

import { ArxError } from "../core/errors";
import { formatDerivationPath } from "./bip32";
import { ETH_CLA, ETH_INS, ETH_P1, ETH_P2 } from "./eth-app";
import { STATUS_WORD_OK, type LedgerTransport } from "./apdu";
import {
  readRlpListHeader,
  readRlpListItems,
  rlpItemToBigInt,
} from "./rlp-frame";

/**
 * Speculos' documented default seed. Not a disclosure — a published test vector
 * whose derived addresses appear in Ledger's own test suites.
 */
export const SPECULOS_TEST_MNEMONIC =
  "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin";

const SW_INCORRECT_DATA = 0x6a80;
const SW_COMMAND_NOT_ALLOWED = 0x6980;
const SW_INS_NOT_SUPPORTED = 0x6d00;
const SW_CLA_NOT_SUPPORTED = 0x6e00;
const SW_CONDITIONS_NOT_SATISFIED = 0x6985;
const SW_TX_TYPE_NOT_SUPPORTED = 0x6501;

const APP_VERSION = [1, 22, 3] as const;

/** Transaction types the real app accepts. */
const SUPPORTED_TYPED = new Set([0x01, 0x02, 0x04]);

/** In a legacy EIP-155 preimage, chainId is the seventh item. */
const LEGACY_CHAIN_ID_INDEX = 6;

function withStatus(data: Uint8Array, statusWord: number): Uint8Array {
  const out = new Uint8Array(data.length + 2);
  out.set(data, 0);
  out[data.length] = (statusWord >> 8) & 0xff;
  out[data.length + 1] = statusWord & 0xff;
  return out;
}

function statusOnly(statusWord: number): Uint8Array {
  return withStatus(new Uint8Array(0), statusWord);
}

function decodeDerivationPath(data: Uint8Array): {
  path: string;
  consumed: number;
} {
  if (data.length < 1) {
    throw new ArxError("SIGNING_FAILED", "Empty derivation path payload");
  }

  const count = data[0]!;

  if (count === 0 || count > 10) {
    throw new ArxError(
      "SIGNING_FAILED",
      `Derivation path element count out of range: ${count}`,
    );
  }

  const consumed = 1 + count * 4;

  if (data.length < consumed) {
    throw new ArxError("SIGNING_FAILED", "Truncated derivation path payload");
  }

  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const elements: number[] = [];

  for (let i = 0; i < count; i += 1) {
    elements.push(view.getUint32(1 + i * 4, false));
  }

  return { path: formatDerivationPath(elements), consumed };
}

type PayloadShape =
  | { state: "INCOMPLETE" }
  | { state: "UNSUPPORTED_TYPE"; txType: number }
  | { state: "COMPLETE"; typed: boolean; chainId: bigint; frame: Uint8Array };

/**
 * Decides whether the accumulated payload is a whole transaction.
 *
 * This mirrors the device: the first byte discriminates an EIP-2718 typed
 * envelope (`<= 0x7f`) from a legacy RLP list (`>= 0xc0`), and the list header
 * declares how many bytes the whole frame occupies.
 */
function inspectPayload(payload: Uint8Array): PayloadShape {
  if (payload.length < 1) {
    return { state: "INCOMPLETE" };
  }

  const first = payload[0]!;
  const typed = first <= 0x7f;

  if (typed && !SUPPORTED_TYPED.has(first)) {
    return { state: "UNSUPPORTED_TYPE", txType: first };
  }

  const body = typed ? payload.subarray(1) : payload;
  const header = readRlpListHeader(body);

  if (!header) {
    return { state: "INCOMPLETE" };
  }

  const expected = (typed ? 1 : 0) + header.totalLength;

  if (payload.length < expected) {
    return { state: "INCOMPLETE" };
  }

  const frame = payload.subarray(0, expected);

  if (typed) {
    // For a typed transaction chainId is the first RLP field, but it is not
    // needed: the device returns the parity directly.
    return { state: "COMPLETE", typed: true, chainId: 0n, frame };
  }

  const items = readRlpListItems(body);
  const chainIdItem = items?.[LEGACY_CHAIN_ID_INDEX];

  return {
    state: "COMPLETE",
    typed: false,
    // A pre-EIP-155 transaction has no chainId field at all.
    chainId: chainIdItem ? rlpItemToBigInt(body, chainIdItem) : 0n,
    frame,
  };
}

export type SimulatorOptions = {
  mnemonic?: string;
  /**
   * When false, signing returns 0x6985 — the status word a real device returns
   * when the user rejects. Lets the rejection path be exercised without
   * hardware.
   */
  approve?: boolean;
};

export class SimulatedEthereumAppTransport implements LedgerTransport {
  readonly name = "speculos-sim";

  private readonly mnemonic: string;
  private readonly approve: boolean;

  /** Streaming state for an in-progress signature, exactly as the device holds. */
  private pending: { path: string; payload: Uint8Array } | null = null;

  constructor(options: SimulatorOptions = {}) {
    this.mnemonic = options.mnemonic ?? SPECULOS_TEST_MNEMONIC;
    this.approve = options.approve ?? true;
  }

  private account(path: string) {
    // The wire format carries no `m/` prefix; viem requires one.
    const normalized = path.startsWith("m/") ? path : `m/${path}`;
    return mnemonicToAccount(this.mnemonic, { path: normalized as never });
  }

  async exchange(apdu: Uint8Array): Promise<Uint8Array> {
    if (apdu.length < 5) {
      return statusOnly(SW_INCORRECT_DATA);
    }

    const cla = apdu[0]!;
    const ins = apdu[1]!;
    const p1 = apdu[2]!;
    const p2 = apdu[3]!;
    const lc = apdu[4]!;

    if (cla !== ETH_CLA) {
      return statusOnly(SW_CLA_NOT_SUPPORTED);
    }

    const data = apdu.subarray(5, 5 + lc);

    switch (ins) {
      case ETH_INS.GET_APP_CONFIGURATION:
        return this.getAppConfiguration();

      case ETH_INS.GET_PUBLIC_ADDRESS:
        return this.getAddress(data, p2);

      case ETH_INS.SIGN_TRANSACTION:
        return this.sign(data, p1, p2);

      default:
        return statusOnly(SW_INS_NOT_SUPPORTED);
    }
  }

  private getAppConfiguration(): Uint8Array {
    /*
     * Byte 0 is the flag field. Blind signing (0x01) is deliberately OFF,
     * matching a freshly initialised device, so a caller relying on arbitrary
     * calldata being signable meets the same refusal it would in reality
     * instead of a convenient fiction.
     */
    return withStatus(
      new Uint8Array([0x02, APP_VERSION[0], APP_VERSION[1], APP_VERSION[2]]),
      STATUS_WORD_OK,
    );
  }

  private getAddress(data: Uint8Array, p2: number): Uint8Array {
    let decoded: { path: string; consumed: number };

    try {
      decoded = decodeDerivationPath(data);
    } catch {
      return statusOnly(SW_INCORRECT_DATA);
    }

    // An optional 8-byte chainId may follow; anything else is malformed.
    const trailing = data.length - decoded.consumed;

    if (trailing !== 0 && trailing !== 8) {
      return statusOnly(SW_INCORRECT_DATA);
    }

    const account = this.account(decoded.path);
    const publicKey = Buffer.from(account.publicKey.slice(2), "hex");

    if (publicKey.length !== 65) {
      throw new ArxError(
        "SIGNING_FAILED",
        `Expected a 65-byte uncompressed public key, got ${publicKey.length}`,
      );
    }

    // The app returns 40 ASCII hex characters, EIP-55 checksummed, unprefixed.
    const addressAscii = Buffer.from(account.address.slice(2), "ascii");

    const chainCode =
      p2 === ETH_P2.RETURN_CHAIN_CODE ? Buffer.alloc(32, 0) : Buffer.alloc(0);

    return withStatus(
      new Uint8Array(
        Buffer.concat([
          Buffer.from([65]),
          publicKey,
          Buffer.from([40]),
          addressAscii,
          chainCode,
        ]),
      ),
      STATUS_WORD_OK,
    );
  }

  private async sign(
    data: Uint8Array,
    p1: number,
    p2: number,
  ): Promise<Uint8Array> {
    if (p2 !== ETH_P2.SIGN_PROCESS_AND_START) {
      return statusOnly(SW_INCORRECT_DATA);
    }

    if (p1 === ETH_P1.SIGN_FIRST_CHUNK) {
      let decoded: { path: string; consumed: number };

      try {
        decoded = decodeDerivationPath(data);
      } catch {
        return statusOnly(SW_INCORRECT_DATA);
      }

      this.pending = {
        path: decoded.path,
        payload: data.subarray(decoded.consumed),
      };
    } else if (p1 === ETH_P1.SIGN_FOLLOWING_CHUNK) {
      if (!this.pending) {
        // The real app's behaviour: a continuation with no first chunk is a
        // protocol error, not something to guess at.
        return statusOnly(SW_COMMAND_NOT_ALLOWED);
      }

      const merged = new Uint8Array(this.pending.payload.length + data.length);
      merged.set(this.pending.payload, 0);
      merged.set(data, this.pending.payload.length);
      this.pending = { path: this.pending.path, payload: merged };
    } else {
      return statusOnly(SW_INCORRECT_DATA);
    }

    const pending = this.pending;
    const shape = inspectPayload(pending.payload);

    if (shape.state === "UNSUPPORTED_TYPE") {
      this.pending = null;
      return statusOnly(SW_TX_TYPE_NOT_SUPPORTED);
    }

    if (shape.state === "INCOMPLETE") {
      // A non-final chunk is acknowledged with status only, no data.
      return statusOnly(STATUS_WORD_OK);
    }

    this.pending = null;

    if (!this.approve) {
      return statusOnly(SW_CONDITIONS_NOT_SATISFIED);
    }

    const account = this.account(pending.path);

    // The same digest the device hashes as it streams, and the one
    // `recoverAddress` is checked against on the host.
    const digest = keccak256(
      `0x${Buffer.from(shape.frame).toString("hex")}` as Hex,
    );

    const signature = await account.sign({ hash: digest });

    const r = Buffer.from(signature.slice(2, 66), "hex");
    const s = Buffer.from(signature.slice(66, 130), "hex");
    const recovery = Number.parseInt(signature.slice(130, 132), 16);
    const yParity: 0 | 1 = recovery === 27 || recovery === 0 ? 0 : 1;

    /*
     * The `v` byte follows the app exactly:
     *   typed  → the parity itself, 0x00 or 0x01. No +27, no EIP-155.
     *   legacy → (chainId * 2 + 35 + parity) truncated to one byte, which the
     *            host reconstructs at full precision.
     *   pre-155 → 27 + parity.
     */
    let v: number;

    if (shape.typed) {
      v = yParity;
    } else if (shape.chainId > 0n) {
      v = Number((shape.chainId * 2n + 35n + BigInt(yParity)) & 0xffn);
    } else {
      v = 27 + yParity;
    }

    return withStatus(
      new Uint8Array(Buffer.concat([Buffer.from([v]), r, s])),
      STATUS_WORD_OK,
    );
  }
}
