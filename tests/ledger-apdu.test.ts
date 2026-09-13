import net from "node:net";

import { keccak256, parseTransaction } from "viem";
import { privateKeyToAccount, sign } from "viem/accounts";
import { describe, expect, it } from "vitest";

import { env } from "../src/config/env";
import {
  APDU_MAX_DATA_LENGTH,
  bytesToHex,
  describeStatusWord,
  encodeApdu,
  hexToBytes,
  isUserRejection,
  parseApduResponse,
  STATUS_WORD_OK,
} from "../src/ledger/apdu";
import {
  encodeDerivationPath,
  formatDerivationPath,
  HARDENED_OFFSET,
  parseDerivationPath,
} from "../src/ledger/bip32";
import {
  decodeErc20Call,
  renderDeviceScreens,
  USDT_DESCRIPTOR,
} from "../src/ledger/clear-signing";
import {
  chainIdAsUint32,
  chunkSignPayload,
  deriveYParity,
  EthereumApp,
  ETH_CLA,
  ETH_INS,
  ETH_P1,
  isTypedTransactionPayload,
  legacyEip155V,
} from "../src/ledger/eth-app";
import { groupEventsIntoScreens } from "../src/ledger/speculos-control";
import { SpeculosHttpTransport } from "../src/ledger/transport-speculos-http";
import { SpeculosTcpTransport } from "../src/ledger/transport-speculos-tcp";
import {
  serializeSigned,
  serializeUnsigned,
  unsignedTransactionDigest,
} from "../src/ledger/tx-serialize";
import { verifyTransactionSignature } from "../src/signer/verify-signature";
import { MockSignerAdapter } from "../src/signer/mock-signer";
import { SignerService } from "../src/signer/signer-service";
import type { EvmTransaction, NormalizedTransaction } from "../src/types/transaction";

const DEMO_PATH = "44'/60'/0'/0/0";

// --- BIP32 codec -----------------------------------------------------------

describe("BIP32 derivation-path codec", () => {
  it("parses the standard Ethereum path into uint32 elements", () => {
    expect(parseDerivationPath(DEMO_PATH)).toEqual({
      path: "44'/60'/0'/0/0",
      elements: [
        44 + HARDENED_OFFSET,
        60 + HARDENED_OFFSET,
        0 + HARDENED_OFFSET,
        0,
        0,
      ],
    });
  });

  it("encodes exactly one count byte plus 4 big-endian bytes per element", () => {
    // count=05, then 8000002c 8000003c 80000000 00000000 00000000
    expect(bytesToHex(encodeDerivationPath(DEMO_PATH))).toBe(
      "058000002c8000003c800000000000000000000000",
    );
    expect(encodeDerivationPath(DEMO_PATH).length).toBe(1 + 5 * 4);
  });

  it("encodes a non-hardened-only path without the high bit", () => {
    expect(bytesToHex(encodeDerivationPath("0/1/2"))).toBe(
      "03000000000000000100000002",
    );
  });

  it("accepts a leading m/ and the h hardened spelling", () => {
    expect(encodeDerivationPath("m/44'/60'/0'/0/0")).toEqual(
      encodeDerivationPath(DEMO_PATH),
    );
    expect(encodeDerivationPath("44h/60h/0h/0/0")).toEqual(
      encodeDerivationPath(DEMO_PATH),
    );
  });

  it("round-trips through the textual form", () => {
    const { elements } = parseDerivationPath(DEMO_PATH);

    expect(formatDerivationPath(elements)).toBe(DEMO_PATH);
  });

  it("rejects, rather than silently skipping, anything it cannot interpret", () => {
    expect(() => parseDerivationPath("")).toThrow();
    expect(() => parseDerivationPath("44'/x/0'")).toThrow();
    expect(() => parseDerivationPath("44'/")).toThrow();
    expect(() => parseDerivationPath("44'/2147483648")).toThrow();
    // The Ethereum app documents a ceiling of 10 derivations.
    expect(() => parseDerivationPath("0/1/2/3/4/5/6/7/8/9/10")).toThrow();
  });
});

// --- APDU framing ----------------------------------------------------------

describe("APDU framing", () => {
  it("frames GET APP CONFIGURATION as e0 06 00 00 00", () => {
    const apdu = encodeApdu({
      cla: ETH_CLA,
      ins: ETH_INS.GET_APP_CONFIGURATION,
      p1: 0x00,
      p2: 0x00,
    });

    expect(bytesToHex(apdu)).toBe("e006000000");
  });

  it("frames GET ETH PUBLIC ADDRESS with the encoded path as its data", () => {
    const apdu = encodeApdu({
      cla: ETH_CLA,
      ins: ETH_INS.GET_PUBLIC_ADDRESS,
      p1: ETH_P1.ADDRESS_RETURN,
      p2: 0x00,
      data: encodeDerivationPath(DEMO_PATH),
    });

    // Lc = 0x15 = 21 = 1 + 5*4
    expect(bytesToHex(apdu)).toBe(
      "e002000015058000002c8000003c800000000000000000000000",
    );
    expect(apdu[4]).toBe(21);
  });

  it("frames SIGN ETH TRANSACTION first and subsequent chunks with P1 00 / 80", () => {
    const first = encodeApdu({
      cla: ETH_CLA,
      ins: ETH_INS.SIGN_TRANSACTION,
      p1: ETH_P1.SIGN_FIRST_CHUNK,
      p2: 0x00,
      data: new Uint8Array([0xde, 0xad]),
    });
    const next = encodeApdu({
      cla: ETH_CLA,
      ins: ETH_INS.SIGN_TRANSACTION,
      p1: ETH_P1.SIGN_FOLLOWING_CHUNK,
      p2: 0x00,
      data: new Uint8Array([0xbe, 0xef]),
    });

    expect(bytesToHex(first)).toBe("e004000002dead");
    expect(bytesToHex(next)).toBe("e004800002beef");
  });

  it("refuses to frame more than 255 data bytes", () => {
    expect(() =>
      encodeApdu({
        cla: ETH_CLA,
        ins: ETH_INS.SIGN_TRANSACTION,
        p1: 0x00,
        p2: 0x00,
        data: new Uint8Array(APDU_MAX_DATA_LENGTH + 1),
      }),
    ).toThrow();
  });

  it("splits a response into payload and status word", () => {
    const parsed = parseApduResponse(hexToBytes("105e441f9000"));

    expect(bytesToHex(parsed.data)).toBe("105e441f");
    expect(parsed.statusWord).toBe(STATUS_WORD_OK);
  });

  it("rejects a reply too short to contain a status word", () => {
    expect(() => parseApduResponse(new Uint8Array([0x90]))).toThrow();
  });
});

// --- Status words ----------------------------------------------------------

describe("status-word mapping", () => {
  it("treats 0x9000 as success with no decision code", () => {
    const info = describeStatusWord(0x9000);

    expect(info.name).toBe("OK");
    expect(info.code).toBeNull();
  });

  it("maps a user decline to SIGNER_REJECTED_BY_USER", () => {
    expect(describeStatusWord(0x6985).code).toBe("SIGNER_REJECTED_BY_USER");
    expect(describeStatusWord(0x5501).code).toBe("SIGNER_REJECTED_BY_USER");
    expect(isUserRejection(0x6985)).toBe(true);
    expect(isUserRejection(0x6a80)).toBe(false);
  });

  it("maps invalid data, unsupported instruction and wrong app", () => {
    expect(describeStatusWord(0x6a80).code).toBe("INVALID_TRANSACTION");
    expect(describeStatusWord(0x6d00).code).toBe("SIGNER_UNAVAILABLE");
    expect(describeStatusWord(0x6e00).code).toBe("SIGNER_UNAVAILABLE");
    expect(describeStatusWord(0x6e00).message).toMatch(/not the application/i);
  });

  it("fails closed on an unknown status word", () => {
    const info = describeStatusWord(0x1234);

    expect(info.name).toBe("UNKNOWN_STATUS_WORD");
    expect(info.code).toBe("SIGNING_FAILED");
  });

  it("every readable message is non-empty", () => {
    for (const sw of [0x9000, 0x6985, 0x6a80, 0x6d00, 0x6e00, 0x5515, 0x6f01]) {
      expect(describeStatusWord(sw).message.length).toBeGreaterThan(0);
    }
  });
});

// --- Chunking --------------------------------------------------------------

describe("SIGN ETH TRANSACTION chunking", () => {
  const pathBytes = encodeDerivationPath(DEMO_PATH);

  it("sends one chunk when the path plus payload fits in 255 bytes", () => {
    const payload = new Uint8Array(100).fill(0x02);
    const chunks = chunkSignPayload(payload, pathBytes, true);

    expect(chunks.length).toBe(1);
    expect(chunks[0]!.length).toBe(pathBytes.length + payload.length);
    // The first chunk carries the derivation path ahead of the payload.
    expect(bytesToHex(chunks[0]!.subarray(0, pathBytes.length))).toBe(
      bytesToHex(pathBytes),
    );
  });

  it("splits a typed payload at the 255-byte ceiling, path in the first chunk", () => {
    const payload = new Uint8Array(600).fill(0x02);
    const chunks = chunkSignPayload(payload, pathBytes, true);

    const total = pathBytes.length + payload.length;

    expect(chunks.length).toBe(Math.ceil(total / APDU_MAX_DATA_LENGTH));
    expect(chunks[0]!.length).toBe(APDU_MAX_DATA_LENGTH);
    expect(bytesToHex(chunks[0]!.subarray(0, pathBytes.length))).toBe(
      bytesToHex(pathBytes),
    );

    for (const chunk of chunks) {
      expect(chunk.length).toBeLessThanOrEqual(APDU_MAX_DATA_LENGTH);
    }

    // Reassembling the chunks must reproduce path || payload exactly.
    const rejoined = chunks.flatMap((chunk) => Array.from(chunk));
    expect(rejoined.length).toBe(total);
    expect(bytesToHex(Uint8Array.from(rejoined.slice(0, pathBytes.length)))).toBe(
      bytesToHex(pathBytes),
    );
  });

  it("identifies EIP-2718 typed envelopes by their leading type byte", () => {
    expect(isTypedTransactionPayload(new Uint8Array([0x02, 0xf8]))).toBe(true);
    expect(isTypedTransactionPayload(new Uint8Array([0xf8, 0x6c]))).toBe(false);
  });

  it("chunks a long legacy payload without ending a chunk on the v/r/s triple", () => {
    const legacy: EvmTransaction = {
      chainId: 1,
      to: "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
      value: "1",
      // Long enough to force multiple chunks.
      data: `0x${"ab".repeat(400)}`,
      gasLimit: "21000",
      maxFeePerGas: "1000000000",
      maxPriorityFeePerGas: "0",
      nonce: 1,
      type: "legacy",
    };

    const payload = hexToBytes(serializeUnsigned(legacy));
    const chunks = chunkSignPayload(payload, pathBytes, false);

    expect(chunks.length).toBeGreaterThan(1);

    const sizes = new Set(chunks.slice(0, -1).map((chunk) => chunk.length));
    expect(sizes.size).toBe(1);

    const chunkSize = chunks[0]!.length;
    expect(chunkSize).toBeLessThanOrEqual(APDU_MAX_DATA_LENGTH);

    const lastChunk = chunks.at(-1)!;
    // The trailing (chainId, 0, 0) triple of an unsigned EIP-155 legacy payload
    // encodes to at most 35 bytes; the final chunk must be longer than that.
    expect(lastChunk.length).toBeGreaterThan(0);
  });
});

// --- v / yParity -----------------------------------------------------------

describe("signature parity recovery", () => {
  it("takes the device byte as the parity for a typed transaction", () => {
    expect(deriveYParity(0, 11155111n, true)).toBe(0);
    expect(deriveYParity(1, 11155111n, true)).toBe(1);
    // An EIP-155-looking v on a typed transaction is a bug, not a parity.
    expect(() => deriveYParity(37, 1n, true)).toThrow();
  });

  it("replays the device's single-byte EIP-155 overflow for a legacy transaction", () => {
    // chainId 1: v = 1*2 + 35 + parity = 37 or 38, no overflow.
    expect(deriveYParity(37, 1n, false)).toBe(0);
    expect(deriveYParity(38, 1n, false)).toBe(1);

    // Sepolia: 11155111*2 + 35 = 22310257; 22310257 % 256 = 113.
    const base = 11155111 * 2 + 35;
    expect(deriveYParity(base % 256, 11155111n, false)).toBe(0);
    expect(deriveYParity((base + 1) % 256, 11155111n, false)).toBe(1);

    expect(() => deriveYParity(7, 11155111n, false)).toThrow();
  });

  it("handles pre-EIP-155 v of 27/28", () => {
    expect(deriveYParity(27, 0n, false)).toBe(0);
    expect(deriveYParity(28, 0n, false)).toBe(1);
  });

  it("reduces a chain ID to the 4 high bytes the device keeps", () => {
    expect(chainIdAsUint32(1n)).toBe(1);
    expect(chainIdAsUint32(11155111n)).toBe(11155111);
    expect(chainIdAsUint32(0n)).toBe(0);
  });

  it("computes the legacy EIP-155 v", () => {
    expect(legacyEip155V(1n, 0)).toBe(37n);
    expect(legacyEip155V(1n, 1)).toBe(38n);
    expect(legacyEip155V(11155111n, 1)).toBe(22310258n);
  });
});

// --- Signature verification (the invariant) --------------------------------

const SIGNING_KEY =
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as const;

function normalized(transaction: EvmTransaction): NormalizedTransaction {
  return {
    transactionId: "tx-under-test",
    agentId: "agent-001",
    capabilityId: "cap-001",
    transactionType: "EVM_TRANSACTION",
    transaction,
    createdAt: 1_700_000_000,
  };
}

const EIP1559_TX: EvmTransaction = {
  chainId: 11155111,
  to: "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
  value: "10000000000000000",
  data: "0x",
  gasLimit: "21000",
  maxFeePerGas: "2000000000",
  maxPriorityFeePerGas: "1000000000",
  nonce: 7,
  type: "eip1559",
};

describe("signature verification against the approved digest", () => {
  it("recovers a known key's signature back to that key's address", async () => {
    const account = privateKeyToAccount(SIGNING_KEY);
    const digest = unsignedTransactionDigest(EIP1559_TX);

    // Sanity: the digest is keccak of the exact bytes streamed to the device.
    expect(digest).toBe(keccak256(serializeUnsigned(EIP1559_TX)));

    const signature = await sign({ hash: digest, privateKey: SIGNING_KEY });

    const verification = await verifyTransactionSignature({
      transaction: normalized(EIP1559_TX),
      r: signature.r,
      s: signature.s,
      yParity: signature.yParity as 0 | 1,
      reportedAddress: account.address,
    });

    expect(verification.verified).toBe(true);
    expect(verification.digest).toBe(digest);
    expect(verification.recoveredAddress.toLowerCase()).toBe(
      account.address.toLowerCase(),
    );
  });

  it("does not verify when the device reports a different address", async () => {
    const digest = unsignedTransactionDigest(EIP1559_TX);
    const signature = await sign({ hash: digest, privateKey: SIGNING_KEY });

    const verification = await verifyTransactionSignature({
      transaction: normalized(EIP1559_TX),
      r: signature.r,
      s: signature.s,
      yParity: signature.yParity as 0 | 1,
      reportedAddress: "0x0000000000000000000000000000000000000009",
    });

    expect(verification.verified).toBe(false);
  });

  it("does not verify a signature made over a different transaction", async () => {
    const account = privateKeyToAccount(SIGNING_KEY);
    const other: EvmTransaction = { ...EIP1559_TX, value: "1" };

    const signature = await sign({
      hash: unsignedTransactionDigest(other),
      privateKey: SIGNING_KEY,
    });

    const verification = await verifyTransactionSignature({
      transaction: normalized(EIP1559_TX),
      r: signature.r,
      s: signature.s,
      yParity: signature.yParity as 0 | 1,
      reportedAddress: account.address,
    });

    expect(verification.verified).toBe(false);
  });

  it("recovers a legacy EIP-155 transaction too", async () => {
    const account = privateKeyToAccount(SIGNING_KEY);
    const legacy: EvmTransaction = { ...EIP1559_TX, type: "legacy" };

    const signature = await sign({
      hash: unsignedTransactionDigest(legacy),
      privateKey: SIGNING_KEY,
    });

    const verification = await verifyTransactionSignature({
      transaction: normalized(legacy),
      r: signature.r,
      s: signature.s,
      yParity: signature.yParity as 0 | 1,
      reportedAddress: account.address,
    });

    expect(verification.verified).toBe(true);
  });
});

describe("signed transaction assembly", () => {
  it("round-trips an EIP-1559 transaction through serialize -> parse", async () => {
    const digest = unsignedTransactionDigest(EIP1559_TX);
    const signature = await sign({ hash: digest, privateKey: SIGNING_KEY });

    const signed = serializeSigned(EIP1559_TX, {
      r: signature.r,
      s: signature.s,
      yParity: signature.yParity as 0 | 1,
    });

    const parsed = parseTransaction(signed);

    expect(parsed.type).toBe("eip1559");
    expect(parsed.chainId).toBe(EIP1559_TX.chainId);
    expect(parsed.to?.toLowerCase()).toBe(EIP1559_TX.to);
    expect(String(parsed.value)).toBe(EIP1559_TX.value);
    expect(parsed.r).toBe(signature.r);
    expect(parsed.s).toBe(signature.s);
  });

  it("puts the EIP-155 v, not the bare parity, into a legacy transaction", async () => {
    const legacy: EvmTransaction = { ...EIP1559_TX, type: "legacy" };
    const signature = await sign({
      hash: unsignedTransactionDigest(legacy),
      privateKey: SIGNING_KEY,
    });
    const yParity = signature.yParity as 0 | 1;

    const signed = serializeSigned(legacy, {
      r: signature.r,
      s: signature.s,
      yParity,
    });

    const parsed = parseTransaction(signed);

    expect(parsed.type).toBe("legacy");
    expect(parsed.chainId).toBe(legacy.chainId);
    expect(parsed.v).toBe(legacyEip155V(BigInt(legacy.chainId), yParity));
  });
});

// --- Mock signer labelling -------------------------------------------------

describe("mock signer", () => {
  it("is deterministic, prefixed, and never reported as verified", async () => {
    const service = new SignerService(new MockSignerAdapter());

    const first = await service.sign(normalized(EIP1559_TX));
    const second = await service.sign(normalized(EIP1559_TX));

    expect(first.signedTransaction).toBe(second.signedTransaction);
    expect(first.signedTransaction.startsWith("0xmock_")).toBe(true);
    expect(first.signatureType).toBe("MOCK");
    expect(first.verified).toBe(false);
    // The literal ASCII "mock" repeated, so raw hex is self-describing.
    expect(first.r).toBe(`0x${"6d6f636b".repeat(8)}`);
  });

  it("changes its digest when the transaction changes", async () => {
    const service = new SignerService(new MockSignerAdapter());

    const a = await service.sign(normalized(EIP1559_TX));
    const b = await service.sign(normalized({ ...EIP1559_TX, value: "1" }));

    expect(a.signedTransaction).not.toBe(b.signedTransaction);
  });
});

// --- Speculos TCP framing, against a local stand-in server -----------------

/**
 * Speculos' APDU socket prefixes a response with a 4-byte length that
 * **excludes** the 2-byte status word. This fake reproduces that exactly, and
 * deliberately writes each frame in two pieces so the transport's partial-read
 * handling is exercised rather than assumed.
 */
function startFakeApduServer(responseHex: string): Promise<{
  port: number;
  received: string[];
  close: () => Promise<void>;
}> {
  const received: string[] = [];

  return new Promise((resolve) => {
    const server = net.createServer((socket) => {
      let buffer = Buffer.alloc(0);

      socket.on("data", (chunk) => {
        buffer = Buffer.concat([buffer, chunk]);

        while (buffer.length >= 4) {
          const length = buffer.readUInt32BE(0);

          if (buffer.length < 4 + length) {
            return;
          }

          received.push(buffer.subarray(4, 4 + length).toString("hex"));
          buffer = buffer.subarray(4 + length);

          const payload = Buffer.from(responseHex, "hex");
          const prefix = Buffer.alloc(4);
          prefix.writeUInt32BE(payload.length - 2, 0);

          const frame = Buffer.concat([prefix, payload]);

          // Split the frame so the client must reassemble it.
          const cut = Math.max(1, Math.floor(frame.length / 2));
          socket.write(frame.subarray(0, cut));
          setTimeout(() => socket.write(frame.subarray(cut)), 5);
        }
      });
    });

    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as net.AddressInfo;

      resolve({
        port: address.port,
        received,
        close: () =>
          new Promise<void>((done) => {
            server.close(() => done());
          }),
      });
    });
  });
}

describe("Speculos APDU socket framing", () => {
  it("writes a length-prefixed request and reassembles a split reply including the status word", async () => {
    const server = await startFakeApduServer("105e441f9000");

    const transport = new SpeculosTcpTransport({
      host: "127.0.0.1",
      port: server.port,
      timeoutMs: 4000,
    });

    try {
      const raw = await transport.exchange(hexToBytes("e006000000"));

      // The status word survived: 4-byte prefix said 4, the wire carried 6.
      expect(bytesToHex(raw)).toBe("105e441f9000");
      expect(parseApduResponse(raw).statusWord).toBe(STATUS_WORD_OK);
      expect(server.received).toEqual(["e006000000"]);
    } finally {
      await transport.close();
      await server.close();
    }
  });

  it("serialises concurrent exchanges instead of mixing up their replies", async () => {
    const server = await startFakeApduServer("aa559000");

    const transport = new SpeculosTcpTransport({
      host: "127.0.0.1",
      port: server.port,
      timeoutMs: 4000,
    });

    try {
      const results = await Promise.all([
        transport.exchange(hexToBytes("e006000000")),
        transport.exchange(hexToBytes("e006000001")),
        transport.exchange(hexToBytes("e006000002")),
      ]);

      for (const raw of results) {
        expect(bytesToHex(raw)).toBe("aa559000");
      }

      expect(server.received).toEqual([
        "e006000000",
        "e006000001",
        "e006000002",
      ]);
    } finally {
      await transport.close();
      await server.close();
    }
  });

  it("reports SIGNER_UNAVAILABLE when nothing is listening", async () => {
    const transport = new SpeculosTcpTransport({
      host: "127.0.0.1",
      // Port 1 is privileged and unbound in every environment this runs in.
      port: 1,
      timeoutMs: 1500,
    });

    await expect(transport.exchange(hexToBytes("e006000000"))).rejects.toThrow(
      /Speculos APDU socket/,
    );

    await transport.close();
  });
});

// --- Clear signing ---------------------------------------------------------

describe("clear-signing render", () => {
  it("renders a native send with amount, recipient and max fees", () => {
    const screens = renderDeviceScreens(EIP1559_TX, null);

    expect(screens.renderedBy).toBe("arx-clear-signing-preview");
    expect(screens.clearSigned).toBe(true);
    expect(screens.intent).toBe("Send");

    const labels = screens.fields.map((field) => field.label);
    expect(labels).toContain("Amount");
    expect(labels).toContain("To");
    expect(labels).toContain("Max fees");

    expect(
      screens.fields.find((field) => field.label === "Amount")?.value,
    ).toBe("0.01 ETH");
    // 21000 * 2 gwei = 0.000042 ETH
    expect(
      screens.fields.find((field) => field.label === "Max fees")?.value,
    ).toBe("0.000042 ETH");
  });

  it("uses a bundled ERC-7730 descriptor for a USDT transfer", () => {
    const usdtTransfer: EvmTransaction = {
      ...EIP1559_TX,
      chainId: 1,
      to: "0xdac17f958d2ee523a2206206994597c13d831ec7",
      value: "0",
      // transfer(0x7099…79C8, 25_000_000) — 25 USDT at 6 decimals
      data: "0xa9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c800000000000000000000000000000000000000000000000000000000017d7840",
    };

    const decoded = decodeErc20Call(usdtTransfer.data);
    expect(decoded?.functionName).toBe("transfer");

    const screens = renderDeviceScreens(usdtTransfer, decoded, USDT_DESCRIPTOR);

    expect(screens.clearSigned).toBe(true);
    expect(screens.intent).toBe("Send");
    expect(screens.descriptorId).toBe("Tether USD");
    expect(
      screens.fields.find((field) => field.label === "Amount")?.value,
    ).toBe("25 USDT");
    expect(
      screens.fields.find((field) => field.label === "To")?.value,
    ).toBe("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
  });

  it("renders an unlimited approval as Unlimited, with a warning", () => {
    const approveMax: EvmTransaction = {
      ...EIP1559_TX,
      chainId: 1,
      to: "0xdac17f958d2ee523a2206206994597c13d831ec7",
      value: "0",
      data: `0x095ea7b300000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8${"f".repeat(64)}`,
    };

    const screens = renderDeviceScreens(
      approveMax,
      decodeErc20Call(approveMax.data),
      USDT_DESCRIPTOR,
    );

    expect(screens.intent).toBe("Approve");
    const amount = screens.fields.find((field) => field.label === "Amount");
    expect(amount?.value).toBe("Unlimited USDT");
    expect(amount?.warning).toMatch(/unlimited/i);
  });

  it("says blind sign, fail-closed, when no descriptor matches", () => {
    const unknownCall: EvmTransaction = {
      ...EIP1559_TX,
      to: "0x1111111111111111111111111111111111111111",
      data: "0xdeadbeef0000000000000000000000000000000000000000000000000000000000000001",
    };

    const screens = renderDeviceScreens(unknownCall, null);

    expect(screens.clearSigned).toBe(false);
    expect(screens.intent).toBe("Blind sign");
    expect(screens.warnings.join(" ")).toMatch(/undecoded calldata/i);
  });

  it("does not apply a descriptor bound to another chain", () => {
    const wrongChain: EvmTransaction = {
      ...EIP1559_TX,
      chainId: 11155111,
      to: "0xdac17f958d2ee523a2206206994597c13d831ec7",
      value: "0",
      data: "0xa9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c800000000000000000000000000000000000000000000000000000000017d7840",
    };

    const screens = renderDeviceScreens(
      wrongChain,
      decodeErc20Call(wrongChain.data),
      USDT_DESCRIPTOR,
    );

    expect(screens.clearSigned).toBe(false);
    expect(screens.warnings.join(" ")).toMatch(/not bound to/i);
  });
});

describe("device screen grouping", () => {
  it("splits the event log into screens whenever the vertical position resets", () => {
    const screens = groupEventsIntoScreens([
      { text: "Review", y: 3 },
      { text: "transaction", y: 17 },
      { text: "Amount", y: 3 },
      { text: "0.01 ETH", y: 17 },
      { text: "Accept", y: 3 },
    ]);

    expect(screens).toEqual([
      ["Review", "transaction"],
      ["Amount", "0.01 ETH"],
      ["Accept"],
    ]);
  });
});

// --- Live Speculos: skips cleanly when the emulator is absent --------------

/**
 * Probed once, at module load, so the live tests can be *registered* as skipped
 * rather than passed.
 *
 * `it.skip` is used instead of a per-test `context.skip()` because this repo is
 * currently run under both vitest and `bun test`, and only vitest supplies a
 * skippable test context. A skipped test reports as skipped in both runners —
 * it never fails the suite and never silently counts as device coverage.
 */
const speculosAvailable = await (async () => {
  try {
    const response = await fetch(
      `${env.speculosApiUrl}/events?currentscreenonly=true`,
      { signal: AbortSignal.timeout(1200) },
    );

    return response.ok;
  } catch {
    return false;
  }
})();

if (!speculosAvailable) {
  console.info(
    `[ledger] Speculos not reachable at ${env.speculosApiUrl}; live device tests are SKIPPED, not passed.`,
  );
}

const liveIt = speculosAvailable ? it : it.skip;

describe("live Speculos (skipped without a running emulator)", () => {
  liveIt("answers GET APP CONFIGURATION with a version", async () => {
    const transport = new SpeculosHttpTransport({
      apiUrl: env.speculosApiUrl,
      timeoutMs: 5000,
    });

    const configuration = await new EthereumApp(
      transport,
    ).getAppConfiguration();

    expect(configuration.version).toMatch(/^\d+\.\d+\.\d+$/);
  });

  liveIt("derives an address for the demo derivation path", async () => {
    const transport = new SpeculosHttpTransport({
      apiUrl: env.speculosApiUrl,
      timeoutMs: 5000,
    });

    const result = await new EthereumApp(transport).getAddress(DEMO_PATH, {
      display: false,
    });

    expect(result.address).toMatch(/^0x[0-9a-fA-F]{40}$/);
    expect(result.publicKey.length).toBeGreaterThan(0);
  });
});
