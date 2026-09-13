/**
 * Speculos raw APDU socket transport (default `127.0.0.1:9999`).
 *
 * Framing, verified against Speculos' own socket server rather than assumed:
 *
 *   request : 4-byte big-endian length, then exactly that many APDU bytes
 *             (`recv_packet` reads 4 bytes, decodes big-endian `size`, then
 *             reads `size` bytes)
 *   response: 4-byte big-endian length that **excludes the 2-byte status
 *             word**, then the payload *and* the status word
 *             (`forward_to_client` computes `size = (len(packet) - 2)` and
 *             sends `size.to_bytes(4, "big") + packet`)
 *
 * https://github.com/LedgerHQ/speculos/blob/master/speculos/mcu/apdu.py
 *
 * That asymmetry is the trap in this protocol: reading `length` bytes after the
 * prefix silently truncates the status word, which would make every device
 * reply look like a different reply with no status at all. We read
 * `length + 2`.
 *
 * TCP delivers a byte stream, not messages, so a single `data` event may carry
 * half a frame or several frames. Everything is accumulated in a buffer and
 * frames are only completed once all their bytes have arrived.
 */

import net from "node:net";

import { ArxError } from "../core/errors";
import { STATUS_WORD_LENGTH, type LedgerTransport } from "./apdu";

export type SpeculosTcpTransportConfig = {
  host: string;
  port: number;
  /** Ceiling on connecting and on each exchange. */
  timeoutMs?: number;
};

const DEFAULT_TIMEOUT_MS = 30_000;
const LENGTH_PREFIX_BYTES = 4;

type PendingExchange = {
  resolve: (response: Uint8Array) => void;
  reject: (error: unknown) => void;
  timer: ReturnType<typeof setTimeout>;
};

export class SpeculosTcpTransport implements LedgerTransport {
  readonly name = "speculos-tcp";

  private readonly host: string;
  private readonly port: number;
  private readonly timeoutMs: number;

  private socket: net.Socket | null = null;
  private buffer = Buffer.alloc(0);
  private pending: PendingExchange | null = null;

  /**
   * Serializes exchanges. The APDU socket has no request identifiers, so a
   * second command sent before the first reply arrives would make the two
   * replies indistinguishable.
   */
  private queue: Promise<unknown> = Promise.resolve();

  constructor(config: SpeculosTcpTransportConfig) {
    this.host = config.host;
    this.port = config.port;
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  async exchange(apdu: Uint8Array): Promise<Uint8Array> {
    const run = this.queue.then(
      () => this.exchangeExclusive(apdu),
      () => this.exchangeExclusive(apdu),
    );

    // Keep the chain alive regardless of this exchange's outcome.
    this.queue = run.catch(() => undefined);

    return run;
  }

  private async exchangeExclusive(apdu: Uint8Array): Promise<Uint8Array> {
    const socket = await this.connect();

    return new Promise<Uint8Array>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending = null;
        this.destroy();
        reject(
          new ArxError(
            "SIGNER_UNAVAILABLE",
            `Speculos APDU socket ${this.host}:${this.port} did not reply within ${this.timeoutMs}ms`,
          ),
        );
      }, this.timeoutMs);

      this.pending = { resolve, reject, timer };

      const frame = Buffer.alloc(LENGTH_PREFIX_BYTES + apdu.length);
      frame.writeUInt32BE(apdu.length, 0);
      frame.set(apdu, LENGTH_PREFIX_BYTES);

      socket.write(frame, (error) => {
        if (error) {
          this.settle(reject, error);
        }
      });
    });
  }

  private async connect(): Promise<net.Socket> {
    if (this.socket !== null && !this.socket.destroyed) {
      return this.socket;
    }

    return new Promise<net.Socket>((resolve, reject) => {
      const socket = net.createConnection({
        host: this.host,
        port: this.port,
      });

      const connectTimer = setTimeout(() => {
        socket.destroy();
        reject(
          new ArxError(
            "SIGNER_UNAVAILABLE",
            `Speculos APDU socket ${this.host}:${this.port} did not accept a connection within ${this.timeoutMs}ms`,
          ),
        );
      }, this.timeoutMs);

      socket.once("connect", () => {
        clearTimeout(connectTimer);

        // Nagle would delay small APDU frames waiting for more bytes.
        socket.setNoDelay(true);

        this.socket = socket;
        this.buffer = Buffer.alloc(0);
        resolve(socket);
      });

      socket.on("data", (chunk: Buffer) => {
        this.buffer = Buffer.concat([this.buffer, chunk]);
        this.drainFrames();
      });

      socket.once("error", (error) => {
        clearTimeout(connectTimer);
        this.socket = null;

        const wrapped = new ArxError(
          "SIGNER_UNAVAILABLE",
          `Speculos APDU socket ${this.host}:${this.port} failed`,
          { cause: error },
        );

        if (this.pending === null) {
          reject(wrapped);
          return;
        }

        this.rejectPending(wrapped);
      });

      socket.once("close", () => {
        clearTimeout(connectTimer);
        this.socket = null;

        // A close mid-exchange is never a successful signature.
        this.rejectPending(
          new ArxError(
            "SIGNER_UNAVAILABLE",
            "Speculos closed the APDU socket before replying",
          ),
        );
      });
    });
  }

  /** Completes every whole frame currently buffered. */
  private drainFrames(): void {
    for (;;) {
      if (this.buffer.length < LENGTH_PREFIX_BYTES) {
        return;
      }

      const payloadLength = this.buffer.readUInt32BE(0);
      // The prefix excludes the status word; the wire carries it anyway.
      const frameLength =
        LENGTH_PREFIX_BYTES + payloadLength + STATUS_WORD_LENGTH;

      if (this.buffer.length < frameLength) {
        return;
      }

      const frame = this.buffer.subarray(LENGTH_PREFIX_BYTES, frameLength);
      this.buffer = this.buffer.subarray(frameLength);

      const pending = this.pending;

      if (pending === null) {
        // An unsolicited frame: nothing to correlate it with, so drop it rather
        // than hand it to the next command as if it were that command's reply.
        continue;
      }

      this.pending = null;
      clearTimeout(pending.timer);
      pending.resolve(Uint8Array.from(frame));
    }
  }

  private rejectPending(error: unknown): void {
    const pending = this.pending;

    if (pending === null) {
      return;
    }

    this.pending = null;
    clearTimeout(pending.timer);
    pending.reject(error);
  }

  private settle(reject: (error: unknown) => void, error: unknown): void {
    const pending = this.pending;

    if (pending !== null) {
      clearTimeout(pending.timer);
      this.pending = null;
    }

    reject(error);
  }

  private destroy(): void {
    this.socket?.destroy();
    this.socket = null;
    this.buffer = Buffer.alloc(0);
  }

  async close(): Promise<void> {
    this.destroy();
  }
}
