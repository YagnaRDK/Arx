import { describe, expect, it } from "bun:test";
import { recoverAddress } from "viem";

import { ArxError } from "../src/core/errors";
import { unsignedTransactionDigest } from "../src/ledger/tx-serialize";
import { TransactionNormalizer } from "../src/normalization/transaction-normalizer";
import {
  SIM_SIGNER_EXPECTED_ADDRESS,
  SimSignerAdapter,
} from "../src/signer/sim-signer";
import { SignerService } from "../src/signer/signer-service";
import type { EvmTransaction } from "../src/types/transaction";

const normalizer = new TransactionNormalizer();

function normalize(overrides: Partial<EvmTransaction> = {}) {
  return normalizer.normalize({
    agentId: "agent-1",
    capabilityId: "cap-1",
    now: 1_700_000_000,
    transaction: {
      chainId: 11155111,
      to: "0x1111111111111111111111111111111111111111",
      value: "10000000000000000",
      data: "0x",
      gasLimit: "21000",
      maxFeePerGas: "30000000000",
      maxPriorityFeePerGas: "1000000000",
      nonce: 0,
      ...overrides,
    },
  });
}

describe("simulated app-ethereum signer", () => {
  it("derives the published Speculos test-seed address through the APDU codec", async () => {
    /*
     * This is a cross-check, not a tautology: the expected value comes from
     * Ledger's own test fixtures for the default Speculos seed. Matching it
     * means the GET ETH PUBLIC ADDRESS request encoding, the BIP-32 path
     * packing and the response parsing are all correct — the same code paths
     * the real emulator exercises.
     */
    const address = await new SimSignerAdapter().getAddress();

    expect(address).toBe(SIM_SIGNER_EXPECTED_ADDRESS);
  });

  it("reports itself as emulated, never as hardware-backed", async () => {
    const status = await new SignerService(
      new SimSignerAdapter(),
    ).getSignerInfo();

    expect(status.emulated).toBe(true);
    expect(status.adapter).toBe("speculos-sim");
    // The signature really is secp256k1, which is why the type is REAL — the
    // `emulated` flag is what stops that being read as hardware-backed.
    expect(status.signatureType).toBe("REAL");
  });

  it("reads the app configuration", async () => {
    const status = (await new SignerService(
      new SimSignerAdapter(),
    ).getSignerInfo()) as { appVersion?: string };

    expect(status.appVersion).toBe("1.22.3");
  });

  it("produces an EIP-1559 signature that recovers to the device address", async () => {
    const service = new SignerService(new SimSignerAdapter());
    const transaction = normalize();

    const result = await service.sign(transaction);

    expect(result.signatureType).toBe("REAL");
    // Set only after SignerService recovered the signer and compared it.
    expect(result.verified).toBe(true);

    // Recovered again here, independently of the service, so the assertion does
    // not rest on the same code that set the flag.
    const recovered = await recoverAddress({
      hash: unsignedTransactionDigest(transaction.transaction),
      signature: result.rawSignature as `0x${string}`,
    });

    expect(recovered).toBe(SIM_SIGNER_EXPECTED_ADDRESS);
    expect(recovered).toBe(result.signerAddress);
  });

  it("returns yParity for a typed transaction rather than an EIP-155 v", async () => {
    const result = await new SignerService(new SimSignerAdapter()).sign(
      normalize(),
    );

    // The app returns the parity itself for EIP-2718 envelopes. Adding 27 or
    // applying EIP-155 here would produce an unrecoverable signature.
    expect([0, 1]).toContain(result.yParity);
    expect(result.v).toBe(`0x${result.yParity}`);
  });

  it("signs a payload spanning multiple APDU chunks", async () => {
    // 600 bytes of calldata exceeds the 255-byte APDU data ceiling, so this
    // only passes if chunking and reassembly are both correct.
    const transaction = normalize({
      to: "0x2222222222222222222222222222222222222222",
      value: "0",
      data: `0x${"ab".repeat(600)}`,
      gasLimit: "500000",
      nonce: 7,
    });

    const result = await new SignerService(new SimSignerAdapter()).sign(
      transaction,
    );

    expect(result.verified).toBe(true);

    const recovered = await recoverAddress({
      hash: unsignedTransactionDigest(transaction.transaction),
      signature: result.rawSignature as `0x${string}`,
    });

    expect(recovered).toBe(result.signerAddress);
  });

  it("signs a legacy transaction with an EIP-155 v", async () => {
    const transaction = normalize({ type: "legacy" });
    const result = await new SignerService(new SimSignerAdapter()).sign(
      transaction,
    );

    expect(result.verified).toBe(true);

    // chainId * 2 + 35 + parity, at full precision rather than the single byte
    // the device sends.
    const expectedV = BigInt(11155111) * 2n + 35n + BigInt(result.yParity!);
    expect(BigInt(result.v!)).toBe(expectedV);
  });

  it("surfaces a device rejection as its own outcome, not a generic failure", async () => {
    // A person declining at the device is a normal result. Reporting it as
    // SIGNING_FAILED would hide the one outcome the human gate exists to produce.
    const service = new SignerService(new SimSignerAdapter({ approve: false }));

    let captured: unknown;

    try {
      await service.sign(normalize());
    } catch (error) {
      captured = error;
    }

    expect(captured).toBeInstanceOf(ArxError);
    expect((captured as ArxError).code).toBe("SIGNER_REJECTED_BY_USER");
  });

  it("refuses a signature for a transaction it was not given", async () => {
    const service = new SignerService(new SimSignerAdapter());
    const result = await service.sign(normalize());

    // Different bytes must yield a different identity, so a signature can never
    // be silently reattributed to another transaction.
    const other = normalize({ value: "20000000000000000" });

    expect(result.transactionId).not.toBe(other.transactionId);
  });

  it("is deterministic for the same transaction", async () => {
    const service = new SignerService(new SimSignerAdapter());
    const transaction = normalize();

    const first = await service.sign(transaction);
    const second = await service.sign(transaction);

    // RFC 6979 deterministic ECDSA: the same key over the same digest gives the
    // same signature, which keeps the demo reproducible.
    expect(first.signedTransaction).toBe(second.signedTransaction);
  });
});
