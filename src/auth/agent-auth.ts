import { canonicalize } from "../crypto/canonical";
import { hmacSha256Hex, safeEqual, sha256Hex } from "../crypto/hash";
import { db } from "../db/database";
import { env } from "../config/env";
import { ArxError } from "../core/errors";
import { AgentStore, deriveAgentKey } from "../storage/agent-store";

/**
 * Data-plane request authentication: HMAC-SHA256 per agent.
 *
 * Before this existed, any process that could reach the port could mint itself
 * a capability with unlimited authority and then exercise it. Least privilege
 * is meaningless without an identity to attach privilege to.
 *
 * ## The signing string — write a client against exactly this
 *
 * Six fields, joined by a single `\n`, in this order:
 *
 * ```
 * ARX-HMAC-SHA256-V1\n
 * <METHOD>\n          uppercase HTTP method, e.g. POST
 * <PATH>\n            request path including query string, e.g. /authorize
 * <TIMESTAMP>\n       unix seconds, as sent in X-Arx-Timestamp
 * <NONCE>\n           unique per request, as sent in X-Arx-Nonce
 * <BODY_SHA256>       see below
 * ```
 *
 * `BODY_SHA256` is `sha256(canonical_json(body))` as lowercase hex with no
 * `0x`, where `canonical_json` is RFC 8785 (JCS). For an empty body it is
 * `sha256("")`. Canonical JSON rather than raw bytes is deliberate: the
 * signature then commits to the *semantic* body Arx parsed, so a proxy
 * reformatting whitespace does not break authentication, and no raw-body
 * plumbing is needed in the HTTP layer.
 *
 * ```
 * signature = hex(HMAC_SHA256(key, signing_string))
 * key       = hex(SHA256("arx-agent-secret:v1:" + agentId + ":" + secret))
 * ```
 *
 * The key is derived from the enrollment secret rather than being it, so the
 * database stores no plaintext secret (see `AgentStore.signingKey`).
 *
 * Headers: `X-Arx-Agent`, `X-Arx-Timestamp`, `X-Arx-Nonce`, `X-Arx-Signature`.
 */

export const AGENT_HEADERS = {
  agent: "x-arx-agent",
  timestamp: "x-arx-timestamp",
  nonce: "x-arx-nonce",
  signature: "x-arx-signature",
} as const;

export const SIGNING_SCHEME = "ARX-HMAC-SHA256-V1";

export type AuthenticatedAgent = {
  agentId: string;
  label?: string;
  /** How the identity was established. `NONE` never reaches a caller. */
  method: "HMAC";
  timestamp: number;
  nonce: string;
};

export type SignatureMaterial = {
  method: string;
  path: string;
  timestamp: number;
  nonce: string;
  body?: unknown;
};

/** `sha256(canonical_json(body))`, lowercase hex. Empty body hashes `""`. */
export function hashRequestBody(body: unknown): string {
  if (body === undefined || body === null || body === "") {
    return sha256Hex("");
  }

  if (typeof body === "string") {
    // A pre-serialized body is hashed as sent; callers passing a string must
    // have canonicalized it themselves.
    return sha256Hex(body);
  }

  return sha256Hex(canonicalize(body));
}

/** Builds the exact string both sides HMAC. The single source of truth. */
export function buildSigningString(material: SignatureMaterial): string {
  return [
    SIGNING_SCHEME,
    material.method.toUpperCase(),
    material.path,
    String(material.timestamp),
    material.nonce,
    hashRequestBody(material.body),
  ].join("\n");
}

/** Client-side helper: sign a request with an agent's plaintext secret. */
export function signRequestWithSecret(
  agentId: string,
  secret: string,
  material: SignatureMaterial,
): string {
  return hmacSha256Hex(
    deriveAgentKey(agentId, secret),
    buildSigningString(material),
  );
}

/** Signs with an already-derived key (what the server stores). */
export function signRequestWithKey(
  key: string,
  material: SignatureMaterial,
): string {
  return hmacSha256Hex(key, buildSigningString(material));
}

/**
 * Per-agent request nonce ledger.
 *
 * Separate from intent nonces: this stops a captured *HTTP request* being
 * resent, which matters even for requests that carry no intent nonce at all.
 * It lives here rather than in `src/storage` because it is transport state, not
 * part of the authorization model.
 */
class RequestNonceLedger {
  /**
   * `INSERT OR IGNORE` on the primary key is the atomic claim: two concurrent
   * copies of one captured request produce one insert and the loser sees
   * `changes === 0`. A SELECT-then-INSERT would let both through.
   */
  private readonly claimStatement = db.prepare(`
    INSERT OR IGNORE INTO request_nonces (nonce_key, agent_id, seen_at)
    VALUES (?, ?, ?)
  `);

  private readonly pruneStatement = db.prepare(`
    DELETE FROM request_nonces WHERE seen_at < ?
  `);

  claim(agentId: string, nonce: string, now: number): boolean {
    return (
      this.claimStatement.run(`${agentId}:${nonce}`, agentId, now).changes > 0
    );
  }

  /**
   * Drops nonces older than the skew window. Safe because a request with a
   * timestamp that old is already rejected as skewed, so its nonce can never be
   * useful again.
   */
  prune(olderThan: number): number {
    return this.pruneStatement.run(olderThan).changes;
  }
}

export class AgentAuthenticator {
  private readonly nonces = new RequestNonceLedger();

  constructor(
    private readonly agents: AgentStore,
    private readonly maxClockSkewSeconds: number = env.maxClockSkewSeconds,
  ) {}

  /** True when the request carries agent credentials at all. */
  static hasCredentials(headers: Record<string, unknown>): boolean {
    return typeof readHeader(headers, AGENT_HEADERS.agent) === "string";
  }

  /**
   * Authenticates one request. Throws `ArxError` with a specific code on every
   * failure; never returns a partial or "probably fine" identity.
   */
  authenticate(input: {
    method: string;
    path: string;
    headers: Record<string, unknown>;
    body?: unknown;
    now?: number;
  }): AuthenticatedAgent {
    const now = input.now ?? Math.floor(Date.now() / 1000);

    const agentId = readHeader(input.headers, AGENT_HEADERS.agent);
    const timestampRaw = readHeader(input.headers, AGENT_HEADERS.timestamp);
    const nonce = readHeader(input.headers, AGENT_HEADERS.nonce);
    const signature = readHeader(input.headers, AGENT_HEADERS.signature);

    if (!agentId || !timestampRaw || !nonce || !signature) {
      throw new ArxError(
        "UNAUTHENTICATED",
        `Requests must carry ${Object.values(AGENT_HEADERS).join(", ")}`,
      );
    }

    const timestamp = Number(timestampRaw);

    if (!Number.isInteger(timestamp) || timestamp <= 0) {
      throw new ArxError(
        "TIMESTAMP_SKEWED",
        "X-Arx-Timestamp must be unix seconds",
      );
    }

    // Checked before the nonce is claimed, so a stale captured request cannot
    // consume ledger space, and before the agent lookup, so the cheapest
    // rejection happens first.
    if (Math.abs(now - timestamp) > this.maxClockSkewSeconds) {
      throw new ArxError(
        "TIMESTAMP_SKEWED",
        `Request timestamp is outside the ${this.maxClockSkewSeconds}s skew window`,
        { details: { timestamp, now } },
      );
    }

    const agent = this.agents.get(agentId);

    if (!agent) {
      throw new ArxError("AGENT_NOT_FOUND", "Unknown agent", {
        details: { agentId },
      });
    }

    if (!agent.enabled) {
      throw new ArxError("AGENT_DISABLED", "Agent is disabled", {
        details: { agentId },
      });
    }

    const key = this.agents.signingKey(agentId);

    if (!key) {
      throw new ArxError("AGENT_NOT_FOUND", "Agent has no credential on file", {
        details: { agentId },
      });
    }

    const expected = signRequestWithKey(key, {
      method: input.method,
      path: input.path,
      timestamp,
      nonce,
      body: input.body,
    });

    // Constant-time: `===` on a hex digest leaks, through response latency, how
    // many leading bytes of a guess were right.
    if (!safeEqual(signature.trim().toLowerCase(), expected)) {
      throw new ArxError("SIGNATURE_INVALID", "Request signature is invalid");
    }

    // Claimed only after the signature verifies. Claiming first would let an
    // unauthenticated attacker burn the nonces of requests it merely observed,
    // turning replay protection into a denial-of-service primitive.
    if (!this.nonces.claim(agentId, nonce, now)) {
      throw new ArxError(
        "REPLAY_DETECTED",
        "Request nonce has already been used",
        { details: { agentId } },
      );
    }

    this.agents.touchLastSeen(agentId, now);

    return {
      agentId,
      label: agent.label,
      method: "HMAC",
      timestamp,
      nonce,
    };
  }

  /** Housekeeping. Anything older than the skew window is already unusable. */
  pruneNonces(now = Math.floor(Date.now() / 1000)): number {
    return this.nonces.prune(now - this.maxClockSkewSeconds - 1);
  }
}

function readHeader(
  headers: Record<string, unknown>,
  name: string,
): string | undefined {
  // Fastify lowercases incoming header names; the fallback scan keeps this
  // usable from tests and non-Fastify callers.
  const direct = headers[name] ?? headers[name.toUpperCase()];
  const raw =
    direct ??
    Object.entries(headers).find(
      ([key]) => key.toLowerCase() === name.toLowerCase(),
    )?.[1];

  if (typeof raw === "string") {
    return raw.length > 0 ? raw : undefined;
  }

  if (Array.isArray(raw) && typeof raw[0] === "string") {
    return raw[0].length > 0 ? raw[0] : undefined;
  }

  return undefined;
}
