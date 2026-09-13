import { env, type SignerMode } from "../config/env";
import { DmkSignerAdapter } from "./dmk-signer";
import { MockSignerAdapter } from "./mock-signer";
import { SimSignerAdapter } from "./sim-signer";
import { PrivySignerAdapter } from "./privy-signer";
import { SignerService } from "./signer-service";
import type { SignerAdapter } from "./signer-types";
import { SpeculosSignerAdapter } from "./speculos-signer";

/**
 * Selects the signer adapter for a mode.
 *
 * Every branch is explicit and there is no default fallback: a mode Arx does
 * not implement must not quietly become the mock signer, because a mock
 * signature presented where a real one was expected is invariant 8's exact
 * failure. `privy` therefore resolves to a stub that reports itself
 * unavailable.
 */
export function createSignerAdapter(
  mode: SignerMode = env.signerMode,
): SignerAdapter {
  switch (mode) {
    case "mock":
      return new MockSignerAdapter();

    case "sim":
      return new SimSignerAdapter({
        derivationPath: env.signerDerivationPath,
      });

    case "speculos":
      return new SpeculosSignerAdapter({
        apiUrl: env.speculosApiUrl,
        apduHost: env.speculosApduHost,
        apduPort: env.speculosApduPort,
        transport: env.speculosTransport,
        derivationPath: env.signerDerivationPath,
        autoApprove: env.speculosAutoApprove,
        captureScreens: true,
      });

    case "dmk":
      return new DmkSignerAdapter({
        derivationPath: env.signerDerivationPath,
      });

    case "privy":
      return new PrivySignerAdapter();
  }
}

export function createSignerService(
  mode: SignerMode = env.signerMode,
): SignerService {
  return new SignerService(createSignerAdapter(mode));
}
