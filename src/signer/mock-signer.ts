import { hashCanonical } from "../crypto/hash";
import type { NormalizedTransaction } from "../types/transaction";
import type {
  SignerAdapter,
  SignerResult,
  SignerStatus,
} from "./signer-types";

/**
 * The no-hardware signer. Deterministic, and deliberately impossible to mistake
 * for a real signature.
 *
 * Four independent markers say "mock": the `mock-signer` adapter name, the
 * `signatureType: "MOCK"` field carried on the result and every API response,
 * the `0xmock_` prefix on `signedTransaction` (which is not valid RLP, so it
 * cannot be broadcast even by accident), and an `r` component that is the
 * literal ASCII bytes of "mock" repeated. `verified` is always false: there is
 * nothing to recover.
 */
export class MockSignerAdapter implements SignerAdapter {
  readonly name = "mock-signer";
  readonly signatureType = "MOCK" as const;

  /**
   * Not a real derived address, and not a burn address either — a recognisable
   * sentinel, so a mock result cannot be confused with a device's address.
   */
  private readonly signerAddress = "0x0000000000000000000000000000000000000001";

  /** 32 bytes of ASCII "mock". Recognisable in raw hex at a glance. */
  private static readonly MOCK_R = `0x${"6d6f636b".repeat(8)}`;

  async getAddress(): Promise<string> {
    return this.signerAddress;
  }

  async getStatus(): Promise<SignerStatus> {
    return {
      adapter: this.name,
      signatureType: "MOCK",
      available: true,
      emulated: true,
      address: this.signerAddress,
      detail:
        "Mock signer: produces a deterministic placeholder, never a valid signature",
    };
  }

  async signTransaction(
    transaction: NormalizedTransaction,
  ): Promise<SignerResult> {
    // Through `hashCanonical`, not `JSON.stringify`: a digest that depends on
    // key order is not deterministic, even for a mock.
    const digest = hashCanonical(transaction.transaction);

    return {
      signedTransaction: `0xmock_${digest.slice(2)}`,
      signerAddress: this.signerAddress,
      transactionId: transaction.transactionId,
      signatureType: "MOCK",
      r: MockSignerAdapter.MOCK_R,
      s: digest,
      v: "0x00",
      verified: false,
      adapter: this.name,
    };
  }
}
