import { randomBytes } from "node:crypto";

import { db } from "../db/database";
import { safeEqual, sha256Hex } from "../crypto/hash";

/**
 * Agent identities.
 *
 * An agent is a data-plane principal: it may exercise capabilities an operator
 * granted it and nothing else. Registering an agent and granting a capability
 * are both control-plane actions, which is what stops a compromised agent from
 * widening its own authority (invariant 11).
 */

export type Agent = {
  agentId: string;
  label?: string;
  enabled: boolean;
  createdAt: number;
  updatedAt: number;
  lastSeenAt?: number;
};

export type RegisteredAgent = {
  agent: Agent;
  /**
   * The plaintext enrollment secret. Returned exactly once, at registration:
   * only its derived key is stored, so this value cannot be recovered later.
   */
  secret: string;
};

type AgentRow = {
  agent_id: string;
  label: string | null;
  secret_hash: string;
  enabled: number;
  created_at: number;
  updated_at: number;
  last_seen_at: number | null;
};

function rowToAgent(row: AgentRow): Agent {
  return {
    agentId: row.agent_id,
    label: row.label ?? undefined,
    enabled: row.enabled === 1,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    lastSeenAt: row.last_seen_at ?? undefined,
  };
}

/**
 * Domain-separated derivation of the stored key from the enrollment secret.
 *
 * The agent id is mixed in so the same secret enrolled under two ids produces
 * two unrelated keys, and the version tag is there so the derivation can be
 * changed later without silently validating old material.
 *
 * A single SHA-256 pass (rather than a password KDF) is sufficient *because the
 * secret is 256 bits of CSPRNG output*, not a human-chosen password: there is
 * no dictionary to walk. If secrets ever become operator-chosen, this must
 * become a memory-hard KDF.
 */
export function deriveAgentKey(agentId: string, secret: string): string {
  return sha256Hex(`arx-agent-secret:v1:${agentId}:${secret}`);
}

/**
 * Generates an enrollment secret. 32 bytes, url-safe, so it can be pasted into
 * an environment variable or a header without escaping.
 */
export function generateAgentSecret(): string {
  return randomBytes(32).toString("base64url");
}

export class AgentStore {
  private readonly insertStatement = db.prepare(`
    INSERT INTO agents (
      agent_id, label, secret_hash, enabled, created_at, updated_at, last_seen_at
    )
    VALUES (?, ?, ?, 1, ?, ?, NULL)
  `);

  private readonly getStatement = db.prepare(`
    SELECT * FROM agents WHERE agent_id = ?
  `);

  private readonly listStatement = db.prepare(`
    SELECT * FROM agents ORDER BY created_at DESC LIMIT ?
  `);

  private readonly setEnabledStatement = db.prepare(`
    UPDATE agents SET enabled = ?, updated_at = ? WHERE agent_id = ?
  `);

  private readonly rotateStatement = db.prepare(`
    UPDATE agents SET secret_hash = ?, updated_at = ? WHERE agent_id = ?
  `);

  private readonly touchStatement = db.prepare(`
    UPDATE agents SET last_seen_at = ? WHERE agent_id = ?
  `);

  private readonly keyStatement = db.prepare(`
    SELECT secret_hash, enabled FROM agents WHERE agent_id = ?
  `);

  /**
   * Registers a new agent and returns its plaintext secret once.
   *
   * Throws if the id already exists rather than rotating the secret: silently
   * replacing an existing agent's key would be a way to take over its identity
   * through a route that only looks like a create.
   */
  register(input: {
    agentId: string;
    label?: string;
    secret?: string;
    now?: number;
  }): RegisteredAgent {
    const now = input.now ?? Math.floor(Date.now() / 1000);

    if (this.get(input.agentId)) {
      throw new Error(`Agent already registered: ${input.agentId}`);
    }

    const secret = input.secret ?? generateAgentSecret();

    this.insertStatement.run(
      input.agentId,
      input.label ?? null,
      deriveAgentKey(input.agentId, secret),
      now,
      now,
    );

    const agent = this.get(input.agentId);

    if (!agent) {
      throw new Error(`Agent registration did not persist: ${input.agentId}`);
    }

    return { agent, secret };
  }

  /** Issues a fresh secret for an existing agent, invalidating the old one. */
  rotateSecret(agentId: string, now = Math.floor(Date.now() / 1000)): RegisteredAgent {
    const existing = this.get(agentId);

    if (!existing) {
      throw new Error(`Unknown agent: ${agentId}`);
    }

    const secret = generateAgentSecret();

    this.rotateStatement.run(deriveAgentKey(agentId, secret), now, agentId);

    const agent = this.get(agentId);

    if (!agent) {
      throw new Error(`Agent disappeared during rotation: ${agentId}`);
    }

    return { agent, secret };
  }

  get(agentId: string): Agent | null {
    const row = this.getStatement.get(agentId) as AgentRow | null | undefined;
    return row ? rowToAgent(row) : null;
  }

  list(limit = 100): Agent[] {
    return (this.listStatement.all(limit) as AgentRow[]).map(rowToAgent);
  }

  /**
   * Constant-time check of a presented plaintext secret.
   *
   * A disabled agent fails here as well as at the transport layer, so disabling
   * an agent revokes it everywhere at once rather than only on the paths that
   * remembered to check `enabled`.
   */
  verifySecret(agentId: string, secret: string): boolean {
    const row = this.keyStatement.get(agentId) as
      | { secret_hash: string; enabled: number }
      | null
      | undefined;

    if (!row || row.enabled !== 1) {
      return false;
    }

    return safeEqual(deriveAgentKey(agentId, secret), row.secret_hash);
  }

  /**
   * The HMAC key used to authenticate this agent's requests.
   *
   * This is the derived key, not the enrollment secret: the plaintext secret
   * never enters the database. Note the inherent property of symmetric request
   * authentication — whoever holds this key can mint requests, so database read
   * access is equivalent to agent impersonation. It is not equivalent to
   * obtaining a signature: a signature additionally requires a verified
   * approval, and forging one of those needs the authorization key. Moving
   * agents to Ed25519 request signing would remove even the impersonation
   * property; it is the obvious next hardening step.
   */
  signingKey(agentId: string): string | null {
    const row = this.keyStatement.get(agentId) as
      | { secret_hash: string; enabled: number }
      | null
      | undefined;

    return row ? row.secret_hash : null;
  }

  setEnabled(
    agentId: string,
    enabled: boolean,
    now = Math.floor(Date.now() / 1000),
  ): boolean {
    return (
      this.setEnabledStatement.run(enabled ? 1 : 0, now, agentId).changes > 0
    );
  }

  touchLastSeen(agentId: string, now = Math.floor(Date.now() / 1000)): void {
    this.touchStatement.run(now, agentId);
  }
}
