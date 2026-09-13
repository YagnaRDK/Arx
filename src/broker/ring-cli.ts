/**
 * Wrapper around the Ledger Key Ring CLI (`wallet-cli ring`).
 *
 * The Key Ring (LKRP) gives Arx a hardware-rooted seal for the secrets it
 * brokers. The point is not encryption for its own sake — it is that unsealing
 * is rooted in a trustchain the agent process cannot reconstruct on its own, so
 * a compromised agent that reads Arx's disk still has nothing usable.
 *
 * Two operational notes drawn from the real CLI rather than its docs, both
 * verified against `wallet-cli@2.1.0`:
 *
 *  - The error channel moves with `--output`. Under `--output json` a failure
 *    is reported as JSON on **stdout**; in human mode the same failure goes to
 *    **stderr** with a differently-shaped error object. Both exit 1. Every call
 *    here passes `--output json` and parses stdout, and the JSON is read
 *    defensively rather than handed straight to `JSON.parse`, because the shape
 *    of that envelope is not something this code should depend on.
 *  - `ring init` requires a physically attached device. Provisioning is
 *    deliberately an operator action, never something Arx attempts implicitly.
 */

import { spawn } from "node:child_process";

import { canonicalize } from "../crypto/canonical";
import { sha256Hex } from "../crypto/hash";

export type RingResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: string; notInitialized: boolean };

export type RingStatus = {
  available: boolean;
  initialized: boolean;
  version?: string;
  keys?: string[];
  reason?: string;
};

const DEFAULT_TIMEOUT_MS = 20_000;

/**
 * The CLI is invoked through `bunx` so a clone needs no global install. A
 * pinned version keeps behaviour reproducible — an unpinned `bunx` would let a
 * future release silently change the seal format.
 */
const RING_PACKAGE = process.env.ARX_WALLET_CLI_PACKAGE ??
  "@ledgerhq/wallet-cli@2.1.0";

/**
 * `stdout` is deliberately a Buffer.
 *
 * `ring encrypt` emits binary ciphertext. Decoding it as UTF-8 here would
 * replace every invalid byte sequence with U+FFFD, and re-encoding that
 * produces different bytes — so the seal would be silently unrecoverable. The
 * corruption is invisible without a provisioned Key Ring, which is why only the
 * callers that genuinely expect text decode it.
 */
type ExecResult = { stdout: Buffer; stderr: string; code: number | null };

function exec(
  args: readonly string[],
  options: { input?: Buffer; timeoutMs?: number } = {},
): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    const child = spawn("bunx", [RING_PACKAGE, ...args], {
      stdio: ["pipe", "pipe", "pipe"],
    });

    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(
        new Error(
          `wallet-cli ${args.join(" ")} timed out after ${options.timeoutMs ?? DEFAULT_TIMEOUT_MS}ms`,
        ),
      );
    }, options.timeoutMs ?? DEFAULT_TIMEOUT_MS);

    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));

    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });

    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr).toString("utf8"),
        code,
      });
    });

    if (options.input) {
      child.stdin.write(options.input);
    }

    child.stdin.end();
  });
}

/**
 * The CLI prints a human-readable tip line before its JSON payload, so the
 * output cannot simply be handed to `JSON.parse`. The last balanced top-level
 * object is the result.
 */
function extractJson(output: string): unknown {
  const start = output.indexOf("{");

  if (start === -1) {
    return undefined;
  }

  let depth = 0;
  let inString = false;
  let escaped = false;

  for (let i = start; i < output.length; i += 1) {
    const char = output[i]!;

    if (escaped) {
      escaped = false;
      continue;
    }

    if (char === "\\") {
      escaped = true;
      continue;
    }

    if (char === '"') {
      inString = !inString;
      continue;
    }

    if (inString) {
      continue;
    }

    if (char === "{") {
      depth += 1;
    } else if (char === "}") {
      depth -= 1;

      if (depth === 0) {
        try {
          return JSON.parse(output.slice(start, i + 1));
        } catch {
          return undefined;
        }
      }
    }
  }

  return undefined;
}

function readError(parsed: unknown, fallback: string): string {
  if (parsed && typeof parsed === "object" && "error" in parsed) {
    const error = (parsed as { error?: unknown }).error;

    if (error && typeof error === "object" && "message" in error) {
      return String((error as { message?: unknown }).message);
    }

    if (typeof error === "string") {
      return error;
    }
  }

  return fallback;
}

export class RingCli {
  private cachedStatus: RingStatus | null = null;

  /**
   * Reports whether the CLI is reachable and whether a Key Ring is provisioned.
   * Cached, because this runs on the authorization path and each invocation
   * spawns a process.
   */
  async status(refresh = false): Promise<RingStatus> {
    if (this.cachedStatus && !refresh) {
      return this.cachedStatus;
    }

    try {
      const result = await exec(["ring", "keys", "--output", "json"]);
      const parsed = extractJson(result.stdout.toString("utf8"));

      if (parsed && typeof parsed === "object" && "ok" in parsed) {
        const body = parsed as {
          ok: boolean;
          data?: unknown;
          keys?: unknown;
        };

        if (body.ok) {
          const keys = Array.isArray(body.keys)
            ? body.keys.map(String)
            : undefined;

          this.cachedStatus = { available: true, initialized: true, keys };
          return this.cachedStatus;
        }

        const message = readError(parsed, "wallet-cli ring reported a failure");

        this.cachedStatus = {
          available: true,
          initialized: false,
          reason: message,
        };

        return this.cachedStatus;
      }

      this.cachedStatus = {
        available: false,
        initialized: false,
        reason:
          result.stderr.trim() ||
          "wallet-cli produced no parseable JSON output",
      };
    } catch (error) {
      this.cachedStatus = {
        available: false,
        initialized: false,
        reason: error instanceof Error ? error.message : String(error),
      };
    }

    return this.cachedStatus;
  }

  /**
   * Seals bytes under a named Key Ring key. `keyName` scopes the derived key, so
   * a capability sealed for one purpose cannot be unsealed by a broker
   * configured for another.
   */
  async encrypt(
    keyName: string,
    plaintext: Buffer,
  ): Promise<RingResult<Buffer>> {
    return this.transform("encrypt", keyName, plaintext);
  }

  async decrypt(
    keyName: string,
    ciphertext: Buffer,
  ): Promise<RingResult<Buffer>> {
    return this.transform("decrypt", keyName, ciphertext);
  }

  private async transform(
    operation: "encrypt" | "decrypt",
    keyName: string,
    input: Buffer,
  ): Promise<RingResult<Buffer>> {
    const status = await this.status();

    if (!status.initialized) {
      return {
        ok: false,
        error:
          status.reason ??
          "Ledger Key Ring is not initialized; run `wallet-cli ring init` with a device attached",
        notInitialized: true,
      };
    }

    try {
      const result = await exec(["ring", operation, "--key", keyName], {
        input,
      });

      if (result.code !== 0) {
        return {
          ok: false,
          error: readError(
            extractJson(result.stdout.toString("utf8")),
            result.stderr.trim() || `ring ${operation} exited ${result.code}`,
          ),
          notInitialized: false,
        };
      }

      /*
       * A failure can still arrive on stdout with exit 0, so the output is
       * inspected for an error envelope. Only the leading bytes are decoded:
       * a successful `encrypt` returns binary, and decoding all of it to look
       * for JSON would be wasteful on a large payload. An error envelope is
       * small and always appears at the start.
       */
      const parsed = extractJson(
        result.stdout.subarray(0, 4096).toString("utf8"),
      );

      if (parsed && typeof parsed === "object" && "ok" in parsed) {
        const body = parsed as { ok: boolean };

        if (!body.ok) {
          return {
            ok: false,
            error: readError(parsed, `ring ${operation} failed`),
            notInitialized: false,
          };
        }
      }

      // The raw bytes, never a round-trip through a string.
      return { ok: true, value: result.stdout };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error.message : String(error),
        notInitialized: false,
      };
    }
  }

  /**
   * Device authenticity preflight.
   *
   * Worth running before trusting a device as a signing boundary: a signature
   * from a counterfeit device is not hardware-rooted, whatever it looks like on
   * the wire.
   */
  async genuineCheck(): Promise<RingResult<unknown>> {
    try {
      const result = await exec(["genuine-check", "--output", "json"], {
        timeoutMs: 60_000,
      });

      const parsed = extractJson(result.stdout.toString("utf8"));

      if (parsed && typeof parsed === "object" && "ok" in parsed) {
        const body = parsed as { ok: boolean; data?: unknown };

        if (body.ok) {
          return { ok: true, value: body.data };
        }
      }

      return {
        ok: false,
        error: readError(parsed, "genuine-check did not confirm the device"),
        notInitialized: false,
      };
    } catch (error) {
      return {
        ok: false,
        error: error instanceof Error ? error.message : String(error),
        notInitialized: false,
      };
    }
  }

  /**
   * Stable fingerprint of a sealing request, for the audit record.
   *
   * Previously returned the canonical JSON itself, which is the opposite of a
   * fingerprint: it would have written the payload into the audit log verbatim.
   */
  static sealFingerprint(keyName: string, payload: unknown): string {
    return `0x${sha256Hex(canonicalize({ keyName, payload }))}`;
  }
}

export const ringCli = new RingCli();
