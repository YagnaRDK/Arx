import type { DeviceScreenCapture } from "../ledger/speculos-control";
import type { RenderedDeviceScreens } from "../ledger/clear-signing";
import type { NormalizedTransaction } from "../types/transaction";

export type { DeviceScreenCapture };

/**
 * Whether a signature is a real secp256k1 signature or a placeholder.
 *
 * Invariant 8: a mock signature is never presented as a real blockchain
 * signature. This field is carried on every result and echoed on every API
 * response so the distinction cannot be lost in transit.
 */
export type SignatureType = "MOCK" | "REAL";

export type SignerResult = {
  /** Broadcastable RLP for a real signature; a `0xmock_`-prefixed digest for a mock. */
  signedTransaction: string;
  /** The address the signer reported. Verified against the recovered signer. */
  signerAddress: string;
  transactionId: string;
  signatureType: SignatureType;

  /** 32-byte `0x`-prefixed hex. */
  r: string;
  /** 32-byte `0x`-prefixed hex. */
  s: string;
  /**
   * `0x`-prefixed hex quantity of the transaction's `v`: the EIP-155 value for
   * a legacy transaction, and the y-parity for a typed (EIP-2718) one.
   */
  v: string;
  /** Present for typed transactions and whenever it could be derived. */
  yParity?: 0 | 1;
  /** 65-byte `0x` signature, `r || s || 27 + yParity` (viem `serializeSignature`). */
  rawSignature?: string;

  /**
   * What the device actually displayed, captured from the emulator's event log.
   * This is the evidence that a human saw the real recipient and amount.
   * Absent when no capture surface exists (a physical device over HID has none).
   */
  deviceScreens?: DeviceScreenCapture;

  /**
   * Arx's local prediction of the review screens, from the clear-signing
   * descriptors. A prediction, never a capture — the two are separate fields
   * because they are separate claims.
   */
  clearSigningPreview?: RenderedDeviceScreens;

  /**
   * True only when the signature was recovered from the digest Arx itself
   * computed and the recovered address matched the address the device reported.
   * A mock signature is never `verified`.
   */
  verified: boolean;

  adapter: string;
  derivationPath?: string;
  /** The exact unsigned bytes streamed to the device, for the audit record. */
  signedDigest?: string;
};

export type SignerStatus = {
  adapter: string;
  signatureType: SignatureType;
  /** Whether this adapter could sign right now. */
  available: boolean;
  /** True when the signature comes from an emulator rather than secure hardware. */
  emulated: boolean;
  address?: string;
  derivationPath?: string;
  /** App version, transport in use, or the reason it is unavailable. */
  detail?: string;
  appVersion?: string;
};

export interface SignerAdapter {
  readonly name: string;
  readonly signatureType: SignatureType;

  getAddress(): Promise<string>;

  signTransaction(transaction: NormalizedTransaction): Promise<SignerResult>;

  /**
   * Liveness and identity of the signing boundary, without signing anything.
   * Optional so an adapter that cannot be probed does not have to lie.
   */
  getStatus?(): Promise<SignerStatus>;

  /**
   * Independently re-checks a result this adapter produced. `SignerService`
   * verifies every real signature regardless; this exists for adapters that
   * can add something the service cannot (a device attestation, say).
   */
  verifySignature?(
    transaction: NormalizedTransaction,
    result: SignerResult,
  ): Promise<boolean>;
}
