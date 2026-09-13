import { serializeSignature } from "viem";

import { ArxError } from "../core/errors";
import {
  decodeErc20Call,
  renderDeviceScreens,
} from "../ledger/clear-signing";
import { hexToBytes } from "../ledger/apdu";
import {
  deriveYParity,
  isTypedTransactionPayload,
  legacyEip155V,
} from "../ledger/eth-app";
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

/**
 * Physical-device adapter built on Ledger's Device Management Kit.
 *
 * Package names and call shapes are taken from Ledger's published docs:
 *   `@ledgerhq/device-management-kit`          — `DeviceManagementKitBuilder`,
 *                                                `startDiscovering`, `connect`
 *   `@ledgerhq/device-signer-kit-ethereum`     — `SignerEthBuilder`,
 *                                                `getAddress`, `signTransaction`
 *   `@ledgerhq/device-transport-kit-node-hid`  — `nodeHidTransportFactory`
 *
 * https://github.com/LedgerHQ/device-sdk-ts/blob/develop/packages/device-management-kit/README.md
 * https://github.com/LedgerHQ/device-sdk-ts/blob/develop/packages/signer/signer-eth/README.md
 * https://github.com/LedgerHQ/device-sdk-ts/blob/develop/packages/transport/node-hid/README.md
 *
 * **The packages are deliberately not declared dependencies.** They pull a
 * native HID binding, which cannot be installed in an environment with no USB
 * device attached, and a dependency that fails to install would stop the whole
 * service booting. Everything is therefore reached through a lazy dynamic
 * `import()` of a non-literal specifier: this module always loads, and when the
 * packages are absent it reports itself unavailable instead of crashing.
 *
 * **Not verified against real packages or a real device.** Nothing in this
 * adapter has been executed: the packages are not installed in this repository
 * and no physical Ledger was attached. The call shapes follow the published
 * documentation, and the DMK observable's `v` byte is the raw device byte (DMK's
 * `SignTransactionCommand` reads it with `extract8BitUInt`), so the same
 * `deriveYParity` logic the Speculos path uses applies here — but treat this
 * adapter as untested code until someone runs it with hardware.
 */

const REQUIRED_PACKAGES = [
  "@ledgerhq/device-management-kit",
  "@ledgerhq/device-signer-kit-ethereum",
  "@ledgerhq/device-transport-kit-node-hid",
] as const;

/**
 * What an operator must actually install. `@ledgerhq/context-module` and `rxjs`
 * are declared peer dependencies of the packages above (verified from their
 * published `package.json` on the npm registry), so they have to be installed
 * alongside them.
 */
const INSTALL_HINT =
  "bun add @ledgerhq/device-management-kit @ledgerhq/device-signer-kit-ethereum @ledgerhq/device-transport-kit-node-hid @ledgerhq/context-module rxjs";

const DEFAULT_DERIVATION_PATH = "44'/60'/0'/0/0";

export type DmkSignerConfig = {
  derivationPath?: string;
  /** Seconds to wait for a device to appear during discovery. */
  discoveryTimeoutMs?: number;
  /** Optional expected address; a mismatch is refused rather than signed. */
  signerAddress?: string;
};

type DmkSession = {
  dmk: any;
  sessionId: string;
  signerEth: any;
};

export class DmkSignerAdapter implements SignerAdapter {
  readonly name = "ledger-dmk";
  readonly signatureType = "REAL" as const;

  private readonly derivationPath: string;
  private readonly discoveryTimeoutMs: number;
  private session: DmkSession | null = null;

  constructor(private readonly config: DmkSignerConfig = {}) {
    this.derivationPath = config.derivationPath ?? DEFAULT_DERIVATION_PATH;
    this.discoveryTimeoutMs = config.discoveryTimeoutMs ?? 15_000;
  }

  async getStatus(): Promise<SignerStatus> {
    const base: SignerStatus = {
      adapter: this.name,
      signatureType: "REAL",
      available: false,
      // A physical Ledger is the opposite of emulated. This flag is only true
      // for an emulator.
      emulated: false,
      derivationPath: this.derivationPath,
    };

    const missing = await findMissingPackages();

    if (missing.length > 0) {
      return {
        ...base,
        detail: `Device Management Kit packages are not installed: ${missing.join(", ")}. On a machine with a Ledger attached, run \`${INSTALL_HINT}\`.`,
      };
    }

    try {
      const session = await this.connect();
      const address = await this.deviceAddress(session);

      return {
        ...base,
        available: true,
        address,
        detail: "Physical Ledger over Node HID via the Device Management Kit",
      };
    } catch (error) {
      return {
        ...base,
        detail:
          error instanceof Error
            ? error.message
            : "Could not reach a physical Ledger device",
      };
    }
  }

  async getAddress(): Promise<string> {
    const session = await this.connect();

    return this.deviceAddress(session);
  }

  async signTransaction(
    transaction: NormalizedTransaction,
  ): Promise<SignerResult> {
    const evm = transaction.transaction;
    const session = await this.connect();

    const payload = serializeUnsigned(evm);
    const payloadBytes = hexToBytes(payload);
    const typed = isTypedTransactionPayload(payloadBytes);
    const digest = unsignedTransactionDigest(evm);

    const deviceAddress = await this.deviceAddress(session);

    const signature = (await consumeDeviceAction(
      session.signerEth.signTransaction(this.derivationPath, payloadBytes),
      "signTransaction",
    )) as { r: string; s: string; v: number };

    const yParity = deriveYParity(
      signature.v,
      BigInt(evm.chainId),
      typed,
    );

    const r = signature.r as `0x${string}`;
    const s = signature.s as `0x${string}`;

    const v = typed
      ? BigInt(yParity)
      : legacyEip155V(BigInt(evm.chainId), yParity);

    return {
      signedTransaction: serializeSigned(evm, { r, s, yParity }),
      signerAddress: deviceAddress,
      transactionId: transaction.transactionId,
      signatureType: "REAL",
      r,
      s,
      v: `0x${v.toString(16)}`,
      yParity,
      rawSignature: serializeSignature({ r, s, yParity }),
      // A physical device exposes no screen-scraping surface. The absence of
      // `deviceScreens` is honest: the screens existed, Arx just cannot prove
      // what they said.
      clearSigningPreview: renderDeviceScreens(
        evm,
        decodeErc20Call(evm.data) ?? null,
      ),
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

  async close(): Promise<void> {
    if (this.session === null) {
      return;
    }

    try {
      await this.session.dmk.disconnect({ sessionId: this.session.sessionId });
    } catch {
      // A device already unplugged is not an error worth propagating.
    }

    this.session = null;
  }

  private async deviceAddress(session: DmkSession): Promise<string> {
    const result = (await consumeDeviceAction(
      session.signerEth.getAddress(this.derivationPath, {
        checkOnDevice: false,
      }),
      "getAddress",
    )) as { address: string };

    const expected = this.config.signerAddress;

    if (
      expected !== undefined &&
      expected.toLowerCase() !== result.address.toLowerCase()
    ) {
      throw new ArxError(
        "SIGNER_ADDRESS_MISMATCH",
        "The device derived a different address than the configured signer address",
        { details: { configured: expected, derived: result.address } },
      );
    }

    return result.address;
  }

  private async connect(): Promise<DmkSession> {
    if (this.session !== null) {
      return this.session;
    }

    const [core, ethSigner, transport] = await loadPackages();

    const dmk = new core.DeviceManagementKitBuilder()
      .addTransport(transport.nodeHidTransportFactory)
      .build();

    const deviceId = await firstDiscoveredDevice(dmk, this.discoveryTimeoutMs);

    const sessionId: string = await dmk.connect({ deviceId });

    // `{ dmk, sessionId }` per the current `SignerEthBuilder` source. The
    // package README still shows the older `{ sdk, sessionId }` spelling; the
    // source is authoritative.
    // https://github.com/LedgerHQ/device-sdk-ts/blob/develop/packages/signer/signer-eth/src/api/SignerEthBuilder.ts
    const signerEth = new ethSigner.SignerEthBuilder({
      dmk,
      sessionId,
    }).build();

    this.session = { dmk, sessionId, signerEth };

    return this.session;
  }
}

/**
 * Loads the DMK packages at call time.
 *
 * The specifier is held in a variable on purpose: a literal `import()` would
 * make TypeScript demand the package be resolvable at build time, and would
 * make bundlers hard-fail when it is not installed.
 */
async function loadPackages(): Promise<[any, any, any]> {
  const loaded: any[] = [];

  for (const name of REQUIRED_PACKAGES) {
    const specifier: string = name;

    try {
      loaded.push(await import(specifier));
    } catch (error) {
      throw new ArxError(
        "SIGNER_UNAVAILABLE",
        `Ledger Device Management Kit package "${name}" is not installed; run \`${INSTALL_HINT}\``,
        { cause: error },
      );
    }
  }

  return [loaded[0], loaded[1], loaded[2]];
}

async function findMissingPackages(): Promise<string[]> {
  const missing: string[] = [];

  for (const name of REQUIRED_PACKAGES) {
    const specifier: string = name;

    try {
      await import(specifier);
    } catch {
      missing.push(name);
    }
  }

  return missing;
}

/** Takes the first device discovery emits, then stops discovering. */
function firstDiscoveredDevice(dmk: any, timeoutMs: number): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) {
        return;
      }

      settled = true;
      subscription?.unsubscribe?.();
      dmk.stopDiscovering?.();
      reject(
        new ArxError(
          "SIGNER_UNAVAILABLE",
          `No Ledger device appeared within ${timeoutMs}ms`,
        ),
      );
    }, timeoutMs);

    const subscription = dmk.startDiscovering().subscribe({
      next: (device: { id: string }) => {
        if (settled) {
          return;
        }

        settled = true;
        clearTimeout(timer);
        subscription?.unsubscribe?.();
        dmk.stopDiscovering?.();
        resolve(device.id);
      },
      error: (error: unknown) => {
        if (settled) {
          return;
        }

        settled = true;
        clearTimeout(timer);
        reject(
          new ArxError("SIGNER_UNAVAILABLE", "Ledger discovery failed", {
            cause: error,
          }),
        );
      },
    });
  });
}

/**
 * Drains a DMK device action to its terminal state.
 *
 * `DeviceActionStatus` values are `not-started`, `pending`, `stopped`,
 * `completed` and `error`:
 * https://github.com/LedgerHQ/device-sdk-ts/blob/develop/packages/device-management-kit/src/api/device-action/model/DeviceActionState.ts
 *
 * `stopped` means the person cancelled on the device — the approval boundary
 * working, so it maps to `SIGNER_REJECTED_BY_USER`, not a failure.
 */
function consumeDeviceAction(
  action: { observable: any; cancel: () => void },
  label: string,
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    action.observable.subscribe({
      next: (state: { status: string; output?: unknown; error?: unknown }) => {
        if (state.status === "completed") {
          resolve(state.output);
          return;
        }

        if (state.status === "stopped") {
          reject(
            new ArxError(
              "SIGNER_REJECTED_BY_USER",
              `${label} was cancelled on the device`,
            ),
          );
          return;
        }

        if (state.status === "error") {
          reject(
            new ArxError("SIGNING_FAILED", `${label} failed on the device`, {
              details: { error: String(state.error) },
            }),
          );
        }
      },
      error: (error: unknown) => {
        reject(
          new ArxError("SIGNING_FAILED", `${label} raised a transport error`, {
            cause: error,
          }),
        );
      },
      complete: () => {
        // A stream that completes without a terminal state is not a success.
        reject(
          new ArxError(
            "SIGNING_FAILED",
            `${label} completed without producing a result`,
          ),
        );
      },
    });
  });
}
