/**
 * Server lifecycle for the demo suite.
 *
 * The demo attaches to a server that is already listening, and starts one only
 * if nothing answers. That ordering matters for a live demo: a presenter with
 * `bun run dev` in one pane and the dashboard open in a browser must not have the
 * demo silently start a second instance against a different database, which
 * would leave the dashboard showing none of the decisions being narrated.
 */

import { rmSync } from "node:fs";

import { ArxClient } from "./api";
import type { ServerHandle } from "./context";

const REPO_ROOT = new URL("../../", import.meta.url).pathname;

export async function probe(baseUrl: string): Promise<boolean> {
  const client = new ArxClient({ baseUrl, timeoutMs: 1_500 });

  for (const path of ["/health", "/signer", "/"]) {
    const result = await client.get(path);

    if (!result.transportError && result.status > 0) {
      return true;
    }
  }

  return false;
}

/** Reads the database path the running server reports, if it reports one. */
export async function reportedDatabasePath(
  baseUrl: string,
): Promise<string | null> {
  const client = new ArxClient({ baseUrl, timeoutMs: 2_000 });
  const result = await client.get("/health");

  if (!result.ok || typeof result.body !== "object" || result.body === null) {
    return null;
  }

  const record = result.body as Record<string, any>;

  for (const candidate of [
    record.databasePath,
    record.database,
    record.db?.path,
    record.storage?.databasePath,
  ]) {
    if (typeof candidate === "string" && candidate.length > 0) {
      return candidate;
    }
  }

  return null;
}

export async function attachOrStart(options: {
  baseUrl: string;
  port: number;
  databasePath: string;
  adminToken: string;
  allowSpawn: boolean;
  resetDatabase: boolean;
  waitMs?: number;
}): Promise<ServerHandle> {
  if (await probe(options.baseUrl)) {
    return {
      baseUrl: options.baseUrl,
      spawned: false,
      databasePath:
        (await reportedDatabasePath(options.baseUrl)) ??
        process.env.DATABASE_PATH ??
        null,
      async stop() {},
      logs: () => "",
    };
  }

  if (!options.allowSpawn) {
    throw new Error(
      `No Arx server is listening on ${options.baseUrl} and --no-spawn was given. Start one with: bun run dev`,
    );
  }

  if (options.resetDatabase) {
    // A fresh database is what makes the suite repeatable: spend windows, nonce
    // high-water marks and the audit chain all carry state between runs.
    for (const suffix of ["", "-wal", "-shm"]) {
      rmSync(`${options.databasePath}${suffix}`, { force: true });
    }
  }

  const chunks: string[] = [];

  const child = Bun.spawn(["bun", "run", "src/index.ts"], {
    cwd: REPO_ROOT,
    env: {
      ...process.env,
      PORT: String(options.port),
      DATABASE_PATH: options.databasePath,
      SIGNER_MODE: process.env.SIGNER_MODE ?? "mock",
      ARX_ADMIN_TOKEN: options.adminToken,
      ARX_DASHBOARD: "1",
    },
    stdout: "pipe",
    stderr: "pipe",
  });

  const drain = async (stream: ReadableStream<Uint8Array> | null) => {
    if (!stream) {
      return;
    }

    const decoder = new TextDecoder();

    for await (const chunk of stream) {
      chunks.push(decoder.decode(chunk));
    }
  };

  void drain(child.stdout as ReadableStream<Uint8Array> | null);
  void drain(child.stderr as ReadableStream<Uint8Array> | null);

  const deadline = Date.now() + (options.waitMs ?? 20_000);
  let ready = false;

  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      break;
    }

    if (await probe(options.baseUrl)) {
      ready = true;
      break;
    }

    await new Promise((resolve) => setTimeout(resolve, 250));
  }

  const handle: ServerHandle = {
    baseUrl: options.baseUrl,
    spawned: true,
    databasePath: options.databasePath,
    async stop() {
      if (child.exitCode === null) {
        child.kill();
        await child.exited;
      }
    },
    logs: () => chunks.join(""),
  };

  if (!ready) {
    await handle.stop();

    throw new Error(
      `Arx server did not become ready on ${options.baseUrl}.\n\n--- server output ---\n${chunks.join("") || "(no output)"}`,
    );
  }

  return handle;
}
