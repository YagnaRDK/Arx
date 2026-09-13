import { serializeSignature, type Hex } from "viem";

import { ArxError } from "../core/errors";
import type { LedgerTransport } from "../ledger/apdu";
import {
  decodeErc20Call,
  renderDeviceScreens,
  type RenderedDeviceScreens,
} from "../ledger/clear-signing";
import {
  deriveYParity,
  EthereumApp,
  isTypedTransactionPayload,
  legacyEip155V,
  type EthAppConfiguration,
} from "../ledger/eth-app";
import {
  SpeculosControl,
  type DeviceScreenCapture,
} from "../ledger/speculos-control";
import { hexToBytes } from "../ledger/apdu";
import { SpeculosHttpTransport } from "../ledger/transport-speculos-http";
import { SpeculosTcpTransport } from "../ledger/transport-speculos-tcp";
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
import { verifyTransactionSignature } from "./verify-signature";

export type SpeculosSignerConfig = {
  /** Speculos REST API base URL, used for control and (optionally) for APDUs. */
  apiUrl: string;
  /** Raw APDU socket host. Only used when `transport` is `tcp`. */
  apduHost?: string;
  apduPort?: number;
  /** Which surface carries the APDUs. Control always goes over the REST API. */
  transport?: "http" | "tcp";
  derivationPath?: string;
  /** Press the device's buttons automatically. Demo convenience, default off. */
  autoApprove?: boolean;
  /** Capture the device's event log as approval evidence. */
  captureScreens?: boolean;
  timeoutMs?: number;
  /**
   * Optional expected signer address.
   *
   * When set, the address the device reports must match it or the signature is
   * refused with `SIGNER_ADDRESS_MISMATCH`. Use it to pin a demo seed's account
   * so a misconfigured emulator (a different `--seed`) fails loudly instead of
   * signing with an unexpected key.
   */
  signerAddress?: string;
};

const DEFAULT_DERIVATION_PATH = "44'/60'/0'/0/0";

/**
 * The real Speculos signer: genuine `app-ethereum` APDUs against the emulator.
 *
 * `signatureType` is `REAL` because the bytes are a real secp256k1 signature
 * over the real transaction digest, produced by the real Ledger application
 * binary and recoverable to the seed's account. What is *not* real is the
 * hardware: Speculos is an emulator with a known demo seed and no secure
 * element. Every status and capture this adapter returns therefore carries
 * `emulated: true`, and the adapter name is `speculos`.
 */
export class SpeculosSignerAdapter implements SignerAdapter {
  readonly name = "speculos";
  readonly signatureType = "REAL" as const;

  private readonly transport: LedgerTransport;
  private readonly control: SpeculosControl;
  private readonly app: EthereumApp;
  private readonly derivationPath: string;
  private readonly config: SpeculosSignerConfig;

  private cachedAddress: string | null = null;

  constructor(config: SpeculosSignerConfig) {
    this.config = config;
    this.derivationPath = config.derivationPath ?? DEFAULT_DERIVATION_PATH;

    this.transport =
      config.transport === "tcp"
        ? new SpeculosTcpTransport({
            host: config.apduHost ?? "127.0.0.1",
            port: config.apduPort ?? 9999,
            ...(config.timeoutMs === undefined
              ? {}
              : { timeoutMs: config.timeoutMs }),
          })
        : new SpeculosHttpTransport({
            apiUrl: config.apiUrl,
            ...(config.timeoutMs === undefined
              ? {}
              : { timeoutMs: config.timeoutMs }),
          });

    this.control = new SpeculosControl({ apiUrl: config.apiUrl });
    this.app = new EthereumApp(this.transport);
  }

  async getAddress(): Promise<string> {
    if (this.cachedAddress !== null) {
      return this.cachedAddress;
    }

    // `display: false` — this is Arx reading the account, not a human
    // confirming one. On-device confirmation belongs to the signing flow.
    const result = await this.app.getAddress(this.derivationPath, {
      display: false,
    });

    const expected = this.config.signerAddress;

    if (
      expected !== undefined &&
      expected.toLowerCase() !== result.address.toLowerCase()
    ) {
      throw new ArxError(
        "SIGNER_ADDRESS_MISMATCH",
        "The emulated device derived a different address than the configured signer address",
        {
          details: {
            configured: expected,
            derived: result.address,
            derivationPath: this.derivationPath,
          },
        },
      );
    }

    this.cachedAddress = result.address;

    return result.address;
  }

  async getStatus(): Promise<SignerStatus> {
    const base: SignerStatus = {
      adapter: this.name,
      signatureType: "REAL",
      available: false,
      emulated: true,
      derivationPath: this.derivationPath,
    };

    let configuration: EthAppConfiguration;

    try {
      configuration = await this.app.getAppConfiguration();
    } catch (error) {
      return {
        ...base,
        detail:
          error instanceof Error
            ? `Speculos unreachable or the Ethereum app is not open: ${error.message}`
            : "Speculos unreachable",
      };
    }

    try {
      const address = await this.getAddress();

      return {
        ...base,
        available: true,
        address,
        appVersion: configuration.version,
        detail: `Emulated Ledger via ${this.transport.name}; app-ethereum ${configuration.version}`,
      };
    } catch (error) {
      return {
        ...base,
        appVersion: configuration.version,
        detail:
          error instanceof Error
            ? error.message
            : "Could not derive the signer address",
      };
    }
  }

  async signTransaction(
    transaction: NormalizedTransaction,
  ): Promise<SignerResult> {
    const evm = transaction.transaction;

    // The exact bytes the device will review, and the digest a correct
    // signature must recover against.
    const payload = serializeUnsigned(evm);
    const digest = unsignedTransactionDigest(evm);
    const typed = isTypedTransactionPayload(hexToBytes(payload));

    const deviceAddress = await this.getAddress();

    // Scope the screen capture to this transaction. Best effort: losing the
    // reset must not lose the signature, but a stale capture must never be
    // presented as this transaction's evidence, so a failure disables capture.
    let captureScoped = this.config.captureScreens !== false;

    if (captureScoped) {
      try {
        await this.control.resetEvents();
      } catch {
        captureScoped = false;
      }
    }

    if (this.config.autoApprove === true) {
      // Not best-effort: if automation cannot be installed, the flow would
      // block on a device nobody is watching.
      await this.control.autoApprove({ enabled: true });
    }

    const signature = await this.app.signTransaction(
      this.derivationPath,
      payload,
    );

    const yParity = deriveYParity(
      signature.vFromDevice,
      BigInt(evm.chainId),
      typed,
    );

    const signedTransaction = serializeSigned(evm, {
      r: signature.r,
      s: signature.s,
      yParity,
    });

    const v = typed
      ? BigInt(yParity)
      : legacyEip155V(BigInt(evm.chainId), yParity);

    const deviceScreens = captureScoped
      ? await this.captureScreens()
      : undefined;

    return {
      signedTransaction,
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
      ...(deviceScreens === undefined ? {} : { deviceScreens }),
      clearSigningPreview: this.previewScreens(transaction),
      // The service recovers and compares before this becomes `true`.
      verified: false,
      adapter: this.name,
      derivationPath: this.derivationPath,
      signedDigest: digest,
    };
  }

  async verifySignature(
    transaction: NormalizedTransaction,
    result: SignerResult,
  ): Promise<boolean> {
    if (result.yParity === undefined) {
      return false;
    }

    const verification = await verifyTransactionSignature({
      transaction,
      r: result.r,
      s: result.s,
      yParity: result.yParity,
      reportedAddress: result.signerAddress,
    });

    return verification.verified;
  }

  /** Exposed so an operator can grab the PNG of the review screen for a demo. */
  async getScreenshot(): Promise<Uint8Array> {
    return this.control.getScreenshot();
  }

  async close(): Promise<void> {
    await this.transport.close?.();
  }

  private async captureScreens(): Promise<DeviceScreenCapture | undefined> {
    try {
      const capture = await this.control.readDeviceScreens();

      return {
        ...capture,
        // Restated on the capture itself: whoever reads this downstream may
        // never see the adapter name.
        source: `${capture.source} (emulated device, auto-approve ${
          this.config.autoApprove === true ? "ON" : "off"
        })`,
      };
    } catch {
      // No evidence is better than fabricated evidence.
      return undefined;
    }
  }

  private previewScreens(
    transaction: NormalizedTransaction,
  ): RenderedDeviceScreens {
    const evm = transaction.transaction;

    return renderDeviceScreens(evm, decodeErc20Call(evm.data) ?? null);
  }
}

/** Convenience for callers that already hold a hex payload (tests, tooling). */
export function payloadIsTyped(payloadHex: Hex): boolean {
  return isTypedTransactionPayload(hexToBytes(payloadHex));
}
