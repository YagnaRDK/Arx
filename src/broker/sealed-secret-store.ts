/**
 * Storage for the secrets Arx brokers on an agent's behalf.
 *
 * The threat this addresses is the ordinary one: an agent given an API key
 * holds that key for as long as the key lives, and anything that reads the
 * agent's memory, environment, logs or prompt context gets it too. Prompt
 * injection makes that materially worse, because the agent can be talked into
 * disclosing it.
 *
 * So Arx never hands the secret over. It stores it sealed, unseals it
 * just-in-time to perform an authorized action, and returns only the result.
 *
 * Two seal backends exist and they are not interchangeable:
 *
 *   `ledger-keyring`  LKRP via `wallet-cli ring`. Unsealing is rooted in a
 *                     trustchain the agent process cannot reconstruct, so disk
 *                     access alone yields nothing.
 *   `local-dev`       scrypt + AES-256-GCM from a local passphrase. Present so
 *                     the project runs with no hardware. It is NOT
 *                     hardware-rooted, and every response and audit entry says
 *                     so — a seal whose provenance is unclear is worse than no
 *                     seal, because it invites misplaced trust.
 */

import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";

import { ArxError } from "../core/errors";
import { canonicalize } from "../crypto/canonical";
import { sha256Hex } from "../crypto/hash";
import { ringCli } from "./ring-cli";

export type SealBackend = "ledger-keyring" | "local-dev";

export type SealedSecret = {
  name: string;
  backend: SealBackend;
  /** Base64 ciphertext. Never the plaintext. */
  ciphertext: string;
  /** Digest of the plaintext, so an unseal can be checked without storing it. */
  plaintextDigest: string;
  createdAt: number;
  keyName: string;
};

export type UnsealResult = {
  secret: string;
  backend: SealBackend;
  /** True only for a hardware-rooted seal. Surfaced to callers verbatim. */
  hardwareRooted: boolean;
};

const SCRYPT_PARAMS = { N: 16_384, r: 8, p: 1, dkLen: 32 } as const;

function localKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, SCRYPT_PARAMS.dkLen, {
    N: SCRYPT_PARAMS.N,
    r: SCRYPT_PARAMS.r,
    p: SCRYPT_PARAMS.p,
  });
}

function localSeal(plaintext: string, passphrase: string): string {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", localKey(passphrase, salt), iv);

  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);

  return Buffer.concat([
    salt,
    iv,
    cipher.getAuthTag(),
    ciphertext,
  ]).toString("base64");
}

function localUnseal(sealed: string, passphrase: string): string {
  const raw = Buffer.from(sealed, "base64");

  const salt = raw.subarray(0, 16);
  const iv = raw.subarray(16, 28);
  const tag = raw.subarray(28, 44);
  const ciphertext = raw.subarray(44);

  const decipher = createDecipheriv(
    "aes-256-gcm",
    localKey(passphrase, salt),
    iv,
  );
  decipher.setAuthTag(tag);

  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]).toString("utf8");
}

export class SealedSecretStore {
  private readonly path: string;
  private readonly localPassphrase: string;
  private cache: Record<string, SealedSecret> = {};

  constructor(options?: { path?: string; localPassphrase?: string }) {
    this.path =
      options?.path ??
      process.env.ARX_SEALED_SECRETS_PATH ??
      join("./data", "sealed-secrets.json");

    this.localPassphrase =
      options?.localPassphrase ?? process.env.ARX_LOCAL_SEAL_PASSPHRASE ?? "";

    this.load();
  }

  private load(): void {
    if (!existsSync(this.path)) {
      this.cache = {};
      return;
    }

    try {
      this.cache = JSON.parse(readFileSync(this.path, "utf8")) as Record<
        string,
        SealedSecret
      >;
    } catch {
      // A corrupt store must not silently become an empty one, or a missing
      // secret would look like a secret that was never configured.
      throw new ArxError(
        "INTERNAL_ERROR",
        `Sealed secret store at ${this.path} is unreadable`,
      );
    }
  }

  private persist(): void {
    mkdirSync(dirname(this.path), { recursive: true });
    writeFileSync(this.path, JSON.stringify(this.cache, null, 2), {
      mode: 0o600,
    });
  }

  /** Which backend is usable right now, preferring the hardware-rooted one. */
  async activeBackend(): Promise<{ backend: SealBackend; reason?: string }> {
    const status = await ringCli.status();

    if (status.initialized) {
      return { backend: "ledger-keyring" };
    }

    return {
      backend: "local-dev",
      reason:
        status.reason ??
        "Ledger Key Ring is not provisioned on this host; falling back to a local development seal",
    };
  }

  /**
   * Seals a secret. The plaintext is not retained anywhere, and the caller is
   * expected to discard its own copy.
   */
  async seal(input: {
    name: string;
    secret: string;
    keyName?: string;
  }): Promise<SealedSecret> {
    const keyName = input.keyName ?? `arx-broker-${input.name}`;
    const { backend } = await this.activeBackend();

    let ciphertext: string;

    if (backend === "ledger-keyring") {
      const result = await ringCli.encrypt(
        keyName,
        Buffer.from(input.secret, "utf8"),
      );

      if (!result.ok) {
        throw new ArxError(
          "INTERNAL_ERROR",
          `Ledger Key Ring seal failed: ${result.error}`,
        );
      }

      ciphertext = result.value.toString("base64");
    } else {
      if (!this.localPassphrase) {
        throw new ArxError(
          "INTERNAL_ERROR",
          "No seal backend available: the Ledger Key Ring is not provisioned and ARX_LOCAL_SEAL_PASSPHRASE is unset",
        );
      }

      ciphertext = localSeal(input.secret, this.localPassphrase);
    }

    const record: SealedSecret = {
      name: input.name,
      backend,
      ciphertext,
      plaintextDigest: `0x${sha256Hex(input.secret)}`,
      createdAt: Math.floor(Date.now() / 1000),
      keyName,
    };

    this.cache[input.name] = record;
    this.persist();

    return record;
  }

  /**
   * Unseals just-in-time. The returned value must be used and dropped, never
   * stored, logged, or returned to an agent.
   */
  async unseal(name: string): Promise<UnsealResult> {
    const record = this.cache[name];

    if (!record) {
      throw new ArxError("FORBIDDEN", `No sealed secret named "${name}"`);
    }

    if (record.backend === "ledger-keyring") {
      const result = await ringCli.decrypt(
        record.keyName,
        Buffer.from(record.ciphertext, "base64"),
      );

      if (!result.ok) {
        throw new ArxError(
          "SIGNER_UNAVAILABLE",
          `Ledger Key Ring unseal failed: ${result.error}`,
        );
      }

      const secret = result.value.toString("utf8");

      if (`0x${sha256Hex(secret)}` !== record.plaintextDigest) {
        throw new ArxError(
          "INTERNAL_ERROR",
          "Unsealed secret does not match its recorded digest",
        );
      }

      return { secret, backend: "ledger-keyring", hardwareRooted: true };
    }

    if (!this.localPassphrase) {
      throw new ArxError(
        "INTERNAL_ERROR",
        "ARX_LOCAL_SEAL_PASSPHRASE is unset; cannot unseal a local-dev secret",
      );
    }

    const secret = localUnseal(record.ciphertext, this.localPassphrase);

    if (`0x${sha256Hex(secret)}` !== record.plaintextDigest) {
      throw new ArxError(
        "INTERNAL_ERROR",
        "Unsealed secret does not match its recorded digest",
      );
    }

    return { secret, backend: "local-dev", hardwareRooted: false };
  }

  /** Metadata only. Deliberately never includes ciphertext or plaintext. */
  list(): Array<Omit<SealedSecret, "ciphertext">> {
    return Object.values(this.cache).map(({ ciphertext, ...rest }) => rest);
  }

  has(name: string): boolean {
    return this.cache[name] !== undefined;
  }

  /** Stable digest of the store's shape, for the audit record. */
  fingerprint(): string {
    return `0x${sha256Hex(
      canonicalize(
        this.list().map((entry) => ({
          name: entry.name,
          backend: entry.backend,
          digest: entry.plaintextDigest,
        })),
      ),
    )}`;
  }
}
