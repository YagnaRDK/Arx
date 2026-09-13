import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
  type KeyObject,
} from "node:crypto";

import { canonicalize } from "./canonical";
import { sha256Hex } from "./hash";
import { env } from "../config/env";

/**
 * Arx's authorization key.
 *
 * This is *not* a signing key for blockchain transactions — Arx never holds one
 * of those. It is an Ed25519 key Arx uses to sign its own approval artifacts, so
 * the signer boundary can verify that Arx authorized a transaction rather than
 * trusting whatever arrived in the request.
 *
 * Why this matters: without it, the only evidence an approval is genuine is a
 * row in Arx's database. Anyone who can write to that database could mint an
 * approval. With it, the signer verifies a signature over the approval's binding
 * fields, so database write access is no longer sufficient to obtain a
 * signature — an attacker would also need the authorization key.
 */
export class AuthorizationKey {
  private readonly privateKey: KeyObject;
  private readonly publicKey: KeyObject;

  /** Fingerprint of the public key, recorded on every approval it signs. */
  readonly keyId: string;
  /** True when the key was generated at boot and will not survive a restart. */
  readonly ephemeral: boolean;

  constructor(pem?: string) {
    if (pem && pem.trim().length > 0) {
      this.privateKey = createPrivateKey(pem);
      this.publicKey = createPublicKey(this.privateKey);
      this.ephemeral = false;
    } else {
      const pair = generateKeyPairSync("ed25519");
      this.privateKey = pair.privateKey;
      this.publicKey = pair.publicKey;
      this.ephemeral = true;
    }

    this.keyId = sha256Hex(this.publicKeyDer().toString("base64")).slice(0, 16);
  }

  private publicKeyDer(): Buffer {
    return this.publicKey.export({ type: "spki", format: "der" });
  }

  publicKeyPem(): string {
    return this.publicKey.export({ type: "spki", format: "pem" }).toString();
  }

  /** Signs the canonical form of `payload`. Ed25519 needs no separate digest. */
  sign(payload: unknown): string {
    const message = Buffer.from(canonicalize(payload), "utf8");
    return nodeSign(null, message, this.privateKey).toString("base64");
  }

  verify(payload: unknown, signature: string): boolean {
    try {
      const message = Buffer.from(canonicalize(payload), "utf8");
      return nodeVerify(
        null,
        message,
        this.publicKey,
        Buffer.from(signature, "base64"),
      );
    } catch {
      // A malformed signature is a failed verification, not an exception to
      // propagate — the caller must not be able to distinguish the two.
      return false;
    }
  }
}

export const authorizationKey = new AuthorizationKey(env.authorizationKeyPem);
