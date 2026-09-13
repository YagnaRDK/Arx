import { createHash, createHmac, timingSafeEqual } from "node:crypto";

import { canonicalize } from "./canonical";

/** SHA-256 of a UTF-8 string, as lowercase hex without a `0x` prefix. */
export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/** SHA-256 of the canonical JSON form of `value`, `0x`-prefixed. */
export function hashCanonical(value: unknown): string {
  return `0x${sha256Hex(canonicalize(value))}`;
}

export function hmacSha256Hex(secret: string, message: string): string {
  return createHmac("sha256", secret).update(message, "utf8").digest("hex");
}

/**
 * Constant-time string comparison. Used for every secret comparison (admin
 * tokens, agent HMAC signatures) so response latency does not leak how many
 * leading bytes of a guess were correct.
 */
export function safeEqual(a: string, b: string): boolean {
  const bufferA = Buffer.from(a, "utf8");
  const bufferB = Buffer.from(b, "utf8");

  if (bufferA.length !== bufferB.length) {
    return false;
  }

  return timingSafeEqual(bufferA, bufferB);
}
