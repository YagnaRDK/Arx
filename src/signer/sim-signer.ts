/**
 * Signer backed by Arx's in-process app-ethereum protocol simulator.
 *
 * This drives the *same* `EthereumApp` codec the Speculos adapter uses — the
 * same APDU framing, the same chunking, the same `v` conventions — against a
 * transport that implements the app's protocol locally. The signature it
 * returns is a genuine secp256k1 signature over the real RLP payload, and
 * `SignerService` recovers the signer address from the digest and compares it to
 * the device address exactly as it would for hardware.
 *
 * It exists so the full authorization-to-signature path, including verification,
 * can be exercised and demonstrated on a machine with no Docker and no device.
 *
 * The honesty boundary, restated because it is the whole point: the key is in
 * this process's memory. There is no Secure Element, no Trusted Display, and no
 * human confirmation. `emulated` is `true`, the adapter is named
 * `speculos-sim`, and the mode refuses to start under NODE_ENV=production —
 * because in production this would be precisely the software key Arx exists to
 * make unnecessary.
 */

import { serializeSignature } from "viem";

import { env } from "../config/env";
import { ArxError } from "../core/errors";
import { renderDeviceScreens } from "../ledger/clear-signing";
import {
  EthereumApp,
  deriveYParity,
  isTypedTransactionPayload,
  legacyEip155V,
} from "../ledger/eth-app";
import {
  SimulatedEthereumAppTransport,
  SPECULOS_TEST_MNEMONIC,
} from "../ledger/transport-simulator";
import {
  serializeSigned,
  serializeUnsigned,
  unsignedTransactionDigest,
} from "../ledger/tx-serialize";
import type { NormalizedTransaction } from "../types/transaction";
import type {
  SignerAdapter,
  SignerResult,
  SignerStatus,
} from "./signer-types";

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex.slice(2), "hex"));
}

export type SimSignerConfig = {
  derivationPath?: string;
  mnemonic?: string;
  /** False makes the simulated device reject, as a user would. */
  approve?: boolean;
};

export class SimSignerAdapter implements SignerAdapter {
  readonly name = "speculos-sim";
  /**
   * REAL because the bytes are a real secp256k1 signature that verifies against
   * the derived address. The emulation is of the *device*, not of the
   * cryptography — and `getStatus()` reports `emulated: true` so no caller can
   * mistake this for hardware-backed signing.
   */
  readonly signatureType = "REAL" as const;

  private readonly transport: SimulatedEthereumAppTransport;
  private readonly app: EthereumApp;
  private readonly derivationPath: string;

  constructor(config: SimSignerConfig = {}) {
    if (env.nodeEnv === "production") {
      throw new ArxError(
        "SIGNER_UNAVAILABLE",
        "The simulated signer holds its key in process memory and is refused in production. Use SIGNER_MODE=speculos or dmk.",
      );
    }

    this.derivationPath = config.derivationPath ?? env.signerDerivationPath;
    this.transport = new SimulatedEthereumAppTransport({
      mnemonic: config.mnemonic ?? SPECULOS_TEST_MNEMONIC,
      approve: config.approve,
    });
    this.app = new EthereumApp(this.transport);
  }

  async getAddress(): Promise<string> {
    const result = await this.app.getAddress(this.derivationPath);
    return result.address;
  }

  async getStatus(): Promise<SignerStatus> {
    const configuration = await this.app.getAppConfiguration();

    return {
      adapter: this.name,
      signatureType: "REAL",
      available: true,
      // The load-bearing flag: this is not a hardware signer.
      emulated: true,
      address: await this.getAddress(),
      appVersion: configuration.version,
      detail:
        "In-process app-ethereum protocol simulator. The signature is real secp256k1 over the real RLP payload; the device, its Secure Element and its Trusted Display are not.",
    };
  }

  async signTransaction(
    transaction: NormalizedTransaction,
  ): Promise<SignerResult> {
    const evm = transaction.transaction;

    const payload = serializeUnsigned(evm);
    const typed = isTypedTransactionPayload(hexToBytes(payload));
    const deviceAddress = await this.getAddress();

    const signature = await this.app.signTransaction(
      this.derivationPath,
      payload,
    );

    const yParity = deriveYParity(
      signature.vFromDevice,
      BigInt(evm.chainId),
      typed,
    );

    const v = typed
      ? BigInt(yParity)
      : legacyEip155V(BigInt(evm.chainId), yParity);

    return {
      signedTransaction: serializeSigned(evm, {
        r: signature.r,
        s: signature.s,
        yParity,
      }),
      signerAddress: deviceAddress,
      transactionId: transaction.transactionId,
      signatureType: "REAL",
      r: signature.r,
      s: signature.s,
      v: `0x${v.toString(16)}`,
      yParity,
      rawSignature: serializeSignature({
        r: signature.r,
        s: signature.s,
        yParity,
      }),
      /*
       * What a Trusted Display *would* show. Labelled a preview, not a capture:
       * with no device there is no trusted display to read back, and presenting
       * a locally rendered screen as device evidence would be exactly the lie
       * the readback assertion exists to catch.
       */
      clearSigningPreview: renderDeviceScreens(evm),
      // SignerService recovers and compares before this becomes true.
      verified: false,
      adapter: this.name,
      derivationPath: this.derivationPath,
    };
  }

  async verifySignature(): Promise<boolean> {
    // Verification lives in SignerService, which recovers the signer from the
    // digest. Nothing adapter-specific to add.
    return true;
  }

  async close(): Promise<void> {
    // Nothing to release: the simulator holds no socket.
  }
}

export const SIM_SIGNER_EXPECTED_ADDRESS: `0x${string}` =
  "0xDad77910DbDFdE764fC21FCD4E74D71bBACA6D8D";
