/**
 * The `app-ethereum` command set Arx uses at the signing boundary.
 *
 * Every command byte below is traceable to Ledger's published specification —
 * nothing here is inferred:
 *
 *   GET ETH PUBLIC ADDRESS   CLA 0xE0  INS 0x02
 *   SIGN ETH TRANSACTION     CLA 0xE0  INS 0x04
 *   GET APP CONFIGURATION    CLA 0xE0  INS 0x06
 *
 * https://github.com/LedgerHQ/app-ethereum/blob/master/doc/ethapp.adoc
 * (the "APDUs list" table and each command's *Coding* section)
 *
 * The chunking and `v`-recovery behaviour follows Ledger's own client:
 * https://github.com/LedgerHQ/ledger-live/blob/develop/libs/ledgerjs/packages/hw-app-eth/src/Eth.ts
 * https://github.com/LedgerHQ/ledger-live/blob/develop/libs/ledgerjs/packages/hw-app-eth/src/utils.ts
 */

import { fromRlp, getAddress as checksumAddress, toRlp, type Hex } from "viem";

import { ArxError } from "../core/errors";
import {
  APDU_MAX_DATA_LENGTH,
  bytesToHex,
  concatBytes,
  hexToBytes,
  sendApdu,
  type LedgerTransport,
} from "./apdu";
import { encodeDerivationPath } from "./bip32";

/** Ethereum application class byte. Source: ethapp.adoc, every *Coding* table. */
export const ETH_CLA = 0xe0;

/** Instruction bytes. Source: ethapp.adoc "APDUs list". */
export const ETH_INS = {
  GET_PUBLIC_ADDRESS: 0x02,
  SIGN_TRANSACTION: 0x04,
  GET_APP_CONFIGURATION: 0x06,
} as const;

/** P1/P2 values for the commands implemented here. Source: ethapp.adoc. */
export const ETH_P1 = {
  /** GET ETH PUBLIC ADDRESS: return the address without on-device confirmation. */
  ADDRESS_RETURN: 0x00,
  /** GET ETH PUBLIC ADDRESS: display the address and require confirmation. */
  ADDRESS_DISPLAY_AND_CONFIRM: 0x01,
  /** SIGN ETH TRANSACTION: first transaction data block. */
  SIGN_FIRST_CHUNK: 0x00,
  /** SIGN ETH TRANSACTION: subsequent transaction data block. */
  SIGN_FOLLOWING_CHUNK: 0x80,
} as const;

export const ETH_P2 = {
  /** GET ETH PUBLIC ADDRESS: do not return the chain code. */
  NO_CHAIN_CODE: 0x00,
  /** GET ETH PUBLIC ADDRESS: return the 32-byte chain code. */
  RETURN_CHAIN_CODE: 0x01,
  /** SIGN ETH TRANSACTION: process the payload and start the review flow. */
  SIGN_PROCESS_AND_START: 0x00,
} as const;

/**
 * GET APP CONFIGURATION flag bits.
 * Source: ethapp.adoc, GET APP CONFIGURATION *Output data*.
 *
 * (Older `hw-app-eth` releases interpreted 0x04/0x08 as Stark support; the
 * current app specification documents 0x10/0x20 as the Transaction Check bits,
 * and the app specification is authoritative for the app we talk to.)
 */
export const ETH_CONFIG_FLAGS = {
  ARBITRARY_DATA_ENABLED: 0x01,
  ERC20_PROVISIONING_NECESSARY: 0x02,
  TRANSACTION_CHECK_ENABLED: 0x10,
  TRANSACTION_CHECK_OPT_IN_DONE: 0x20,
} as const;

export type EthAppConfiguration = {
  version: string;
  major: number;
  minor: number;
  patch: number;
  flags: number;
  arbitraryDataEnabled: boolean;
  erc20ProvisioningNecessary: boolean;
  transactionCheckEnabled: boolean;
  transactionCheckOptInDone: boolean;
};

export type EthAddressResult = {
  /** Uncompressed SEC1 public key, hex without `0x`. */
  publicKey: string;
  /** EIP-55 checksummed address. */
  address: `0x${string}`;
  /** Present only when requested. */
  chainCode?: string;
};

export type DeviceSignature = {
  /** The raw first response byte, before any EIP-155 interpretation. */
  vFromDevice: number;
  r: Hex;
  s: Hex;
  /** The full 65-byte device reply, for the audit record. */
  raw: Hex;
};

/**
 * True when `payload` is an EIP-2718 typed-transaction envelope.
 *
 * EIP-2718 reserves a leading byte of `0x00..0x7f` for the transaction type;
 * a legacy transaction is a bare RLP list, whose first byte is `>= 0xc0`.
 */
export function isTypedTransactionPayload(payload: Uint8Array): boolean {
  const first = payload[0];

  return first !== undefined && first <= 0x7f;
}

/**
 * Splits the signing payload into APDU data blocks.
 *
 * The first block carries the derivation-path prefix ahead of the payload; the
 * rest are payload only. Faithful port of `safeChunkTransaction`:
 * https://github.com/LedgerHQ/ledger-live/blob/develop/libs/ledgerjs/packages/hw-app-eth/src/utils.ts
 *
 * For legacy transactions the chunk boundary matters for correctness, not just
 * throughput. A legacy EIP-155 payload ends with the `v`/`r`/`s` slots, so a
 * boundary landing just before them can make the app treat a partial RLP as a
 * complete transaction. The loop below shrinks the chunk size until the final
 * chunk is guaranteed to be longer than that trailing triple.
 */
export function chunkSignPayload(
  payload: Uint8Array,
  derivationPathBytes: Uint8Array,
  typed: boolean,
): Uint8Array[] {
  const full = concatBytes(derivationPathBytes, payload);

  if (full.length <= APDU_MAX_DATA_LENGTH) {
    return [full];
  }

  if (typed) {
    return sliceEvenly(full, APDU_MAX_DATA_LENGTH);
  }

  const tailLength = legacyTrailingVrsLength(payload);

  let chunkSize = 0;
  const lastChunkSize = full.length % APDU_MAX_DATA_LENGTH;

  if (lastChunkSize === 0 || lastChunkSize > tailLength) {
    chunkSize = APDU_MAX_DATA_LENGTH;
  } else {
    for (let shrink = 1; shrink < APDU_MAX_DATA_LENGTH; shrink += 1) {
      const candidate = APDU_MAX_DATA_LENGTH - shrink;
      const remainder = full.length % candidate;

      if (remainder === 0 || remainder > tailLength) {
        chunkSize = candidate;
        break;
      }
    }
  }

  if (chunkSize <= 0) {
    // Fail closed: never send a chunking we know the app may misread.
    throw new ArxError(
      "SIGNING_FAILED",
      "Could not find a safe APDU chunk size for this legacy transaction",
    );
  }

  return sliceEvenly(full, chunkSize);
}

function sliceEvenly(bytes: Uint8Array, size: number): Uint8Array[] {
  const chunks: Uint8Array[] = [];

  for (let offset = 0; offset < bytes.length; offset += size) {
    chunks.push(bytes.subarray(offset, offset + size));
  }

  return chunks;
}

/**
 * Byte length of the RLP-encoded trailing `(v, r, s)` triple of a legacy
 * payload, excluding the list header byte — the quantity `safeChunkTransaction`
 * compares the final chunk against.
 */
function legacyTrailingVrsLength(payload: Uint8Array): number {
  const decoded = fromRlp(`0x${bytesToHex(payload)}` as Hex, "hex");

  if (!Array.isArray(decoded) || decoded.length < 3) {
    throw new ArxError(
      "INVALID_TRANSACTION",
      "Legacy signing payload is not an RLP list of at least three items",
    );
  }

  const tail = decoded.slice(-3);
  const encoded = hexToBytes(toRlp(tail, "hex"));

  // Drop the list-prefix byte, matching `hexBuffer(encodedVrs).subarray(1)`.
  return encoded.length - 1;
}

/**
 * Reduces a chain ID to the 4-byte integer the device uses when it folds the
 * chain ID into a single `v` byte.
 *
 * Port of `getChainIdAsUint32`: the device keeps the *high* bytes of the chain
 * ID, so this takes the first four bytes of its big-endian encoding.
 */
export function chainIdAsUint32(chainId: bigint): number {
  if (chainId < 0n) {
    throw new ArxError("INVALID_TRANSACTION", "chainId cannot be negative");
  }

  const hex = chainId.toString(16);
  const padded = hex.length % 2 === 1 ? `0${hex}` : hex;
  const head = hexToBytes(padded).subarray(0, 4);

  return Number.parseInt(bytesToHex(head), 16);
}

/**
 * Recovers the signature's y-parity from the device's single `v` byte.
 *
 * For a typed (EIP-2718) transaction the device already returns the parity, so
 * the legacy EIP-155 `v` encoding must **not** be assumed. For a legacy
 * transaction the device has folded `chainId * 2 + 35 + parity` into one byte,
 * which overflows for all but tiny chain IDs — so the overflow is replayed here
 * for both candidate parities and matched against what the device returned.
 *
 * Port of `getParity`:
 * https://github.com/LedgerHQ/ledger-live/blob/develop/libs/ledgerjs/packages/hw-app-eth/src/utils.ts
 */
export function deriveYParity(
  vFromDevice: number,
  chainId: bigint,
  typed: boolean,
): 0 | 1 {
  if (typed) {
    if (vFromDevice !== 0 && vFromDevice !== 1) {
      throw new ArxError(
        "SIGNING_FAILED",
        `Typed transaction expects a y-parity of 0 or 1, device returned ${vFromDevice}`,
      );
    }

    return vFromDevice;
  }

  if (chainId === 0n) {
    // Pre-EIP-155: v is 27/28 and carries the parity directly.
    if (vFromDevice !== 27 && vFromDevice !== 28) {
      throw new ArxError(
        "SIGNING_FAILED",
        `Pre-EIP-155 transaction expects v of 27 or 28, device returned ${vFromDevice}`,
      );
    }

    return vFromDevice === 27 ? 0 : 1;
  }

  const eip155Base = chainIdAsUint32(chainId) * 2 + 35;

  if (eip155Base % 256 === vFromDevice) {
    return 0;
  }

  if ((eip155Base + 1) % 256 === vFromDevice) {
    return 1;
  }

  throw new ArxError(
    "SIGNING_FAILED",
    `Device v byte ${vFromDevice} does not match either EIP-155 parity for chain ${chainId}`,
  );
}

/** The on-chain `v` for a legacy EIP-155 transaction. */
export function legacyEip155V(chainId: bigint, yParity: 0 | 1): bigint {
  return chainId * 2n + 35n + BigInt(yParity);
}

export type GetAddressOptions = {
  /** Show the address on the device and require confirmation before returning it. */
  display?: boolean;
  /** Also return the 32-byte chain code. */
  chainCode?: boolean;
  /**
   * Optional chain ID, appended as 8 bytes big-endian. Recent apps use it to
   * name the network on the review screen.
   */
  chainId?: bigint;
};

export class EthereumApp {
  constructor(private readonly transport: LedgerTransport) {}

  /** GET APP CONFIGURATION (INS 0x06). */
  async getAppConfiguration(): Promise<EthAppConfiguration> {
    const data = await sendApdu(
      this.transport,
      {
        cla: ETH_CLA,
        ins: ETH_INS.GET_APP_CONFIGURATION,
        p1: 0x00,
        p2: 0x00,
      },
      "GET APP CONFIGURATION",
    );

    if (data.length < 4) {
      throw new ArxError(
        "SIGNER_UNAVAILABLE",
        `GET APP CONFIGURATION returned ${data.length} bytes; expected 4 (flags, major, minor, patch)`,
      );
    }

    const flags = data[0] as number;
    const major = data[1] as number;
    const minor = data[2] as number;
    const patch = data[3] as number;

    return {
      version: `${major}.${minor}.${patch}`,
      major,
      minor,
      patch,
      flags,
      arbitraryDataEnabled:
        (flags & ETH_CONFIG_FLAGS.ARBITRARY_DATA_ENABLED) !== 0,
      erc20ProvisioningNecessary:
        (flags & ETH_CONFIG_FLAGS.ERC20_PROVISIONING_NECESSARY) !== 0,
      transactionCheckEnabled:
        (flags & ETH_CONFIG_FLAGS.TRANSACTION_CHECK_ENABLED) !== 0,
      transactionCheckOptInDone:
        (flags & ETH_CONFIG_FLAGS.TRANSACTION_CHECK_OPT_IN_DONE) !== 0,
    };
  }

  /** GET ETH PUBLIC ADDRESS (INS 0x02). */
  async getAddress(
    path: string,
    options: GetAddressOptions = {},
  ): Promise<EthAddressResult> {
    const pathBytes = encodeDerivationPath(path);

    const data =
      options.chainId === undefined
        ? pathBytes
        : concatBytes(pathBytes, encodeUint64BE(options.chainId));

    const response = await sendApdu(
      this.transport,
      {
        cla: ETH_CLA,
        ins: ETH_INS.GET_PUBLIC_ADDRESS,
        p1: options.display
          ? ETH_P1.ADDRESS_DISPLAY_AND_CONFIRM
          : ETH_P1.ADDRESS_RETURN,
        p2: options.chainCode
          ? ETH_P2.RETURN_CHAIN_CODE
          : ETH_P2.NO_CHAIN_CODE,
        data,
      },
      "GET ETH PUBLIC ADDRESS",
    );

    // Output layout: pubKeyLen | pubKey | addrLen | ASCII address | [chainCode].
    const publicKeyLength = response[0];

    if (publicKeyLength === undefined) {
      throw new ArxError(
        "SIGNER_UNAVAILABLE",
        "GET ETH PUBLIC ADDRESS returned an empty response",
      );
    }

    const addressLengthOffset = 1 + publicKeyLength;
    const addressLength = response[addressLengthOffset];

    if (addressLength === undefined) {
      throw new ArxError(
        "SIGNER_UNAVAILABLE",
        "GET ETH PUBLIC ADDRESS response is truncated before the address length",
      );
    }

    const addressStart = addressLengthOffset + 1;
    const addressEnd = addressStart + addressLength;

    if (response.length < addressEnd) {
      throw new ArxError(
        "SIGNER_UNAVAILABLE",
        "GET ETH PUBLIC ADDRESS response is truncated inside the address",
      );
    }

    const asciiAddress = new TextDecoder().decode(
      response.subarray(addressStart, addressEnd),
    );

    // The device returns ASCII without the `0x` prefix; checksum it through
    // viem so a malformed device reply cannot reach the rest of the pipeline.
    const address = checksumAddress(`0x${asciiAddress.replace(/^0x/i, "")}`);

    const chainCode = options.chainCode
      ? bytesToHex(response.subarray(addressEnd, addressEnd + 32))
      : undefined;

    return {
      publicKey: bytesToHex(response.subarray(1, 1 + publicKeyLength)),
      address,
      ...(chainCode === undefined ? {} : { chainCode }),
    };
  }

  /**
   * SIGN ETH TRANSACTION (INS 0x04).
   *
   * `payloadHex` is the unsigned serialization: for a typed transaction, the
   * EIP-2718 type byte followed by the RLP list — byte-for-byte what viem's
   * `serializeTransaction` produces for an unsigned transaction. Arx never
   * hand-rolls RLP.
   */
  async signTransaction(
    path: string,
    payloadHex: string,
  ): Promise<DeviceSignature> {
    const payload = hexToBytes(payloadHex);

    if (payload.length === 0) {
      throw new ArxError(
        "INVALID_TRANSACTION",
        "Signing payload is empty",
      );
    }

    const pathBytes = encodeDerivationPath(path);
    const typed = isTypedTransactionPayload(payload);
    const chunks = chunkSignPayload(payload, pathBytes, typed);

    let response: Uint8Array | undefined;

    for (const [index, chunk] of chunks.entries()) {
      response = await sendApdu(
        this.transport,
        {
          cla: ETH_CLA,
          ins: ETH_INS.SIGN_TRANSACTION,
          p1:
            index === 0
              ? ETH_P1.SIGN_FIRST_CHUNK
              : ETH_P1.SIGN_FOLLOWING_CHUNK,
          p2: ETH_P2.SIGN_PROCESS_AND_START,
          data: chunk,
        },
        `SIGN ETH TRANSACTION (chunk ${index + 1}/${chunks.length})`,
      );
    }

    // Output layout: v (1) | r (32) | s (32).
    if (response === undefined || response.length < 65) {
      throw new ArxError(
        "SIGNING_FAILED",
        `SIGN ETH TRANSACTION returned ${response?.length ?? 0} bytes; expected 65 (v, r, s)`,
      );
    }

    return {
      vFromDevice: response[0] as number,
      r: `0x${bytesToHex(response.subarray(1, 33))}`,
      s: `0x${bytesToHex(response.subarray(33, 65))}`,
      raw: `0x${bytesToHex(response.subarray(0, 65))}`,
    };
  }
}

/** 8-byte big-endian chain ID, as the optional GET ADDRESS suffix expects. */
function encodeUint64BE(value: bigint): Uint8Array {
  if (value < 0n || value > 0xffffffffffffffffn) {
    throw new ArxError(
      "INVALID_TRANSACTION",
      "chainId does not fit in the 8-byte field the Ethereum app expects",
    );
  }

  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, value, false);

  return bytes;
}
