import { Database } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

import { env } from "../config/env";

mkdirSync(dirname(env.databasePath), { recursive: true });

export const db = new Database(env.databasePath, { create: true });

db.run("PRAGMA journal_mode = WAL;");
db.run("PRAGMA foreign_keys = ON;");
// Without this, two requests racing on the same approval can surface
// SQLITE_BUSY instead of serializing.
db.run("PRAGMA busy_timeout = 5000;");
db.run("PRAGMA synchronous = NORMAL;");

db.run(`
  CREATE TABLE IF NOT EXISTS capabilities (
    capability_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    allowed_actions TEXT NOT NULL,
    allowed_protocols TEXT NOT NULL,
    allowed_chains TEXT NOT NULL,
    allowed_input_tokens TEXT NOT NULL,
    allowed_output_tokens TEXT NOT NULL,
    max_amount_usd REAL NOT NULL,
    max_slippage_bps INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    nonce INTEGER NOT NULL,
    status TEXT NOT NULL,
    usage TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
`);

db.run(`
  CREATE TABLE IF NOT EXISTS processed_intents (
    replay_key TEXT PRIMARY KEY,
    capability_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    nonce INTEGER NOT NULL,
    processed_at INTEGER NOT NULL
  );
`);

db.run(`
  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL,
    capability_id TEXT,
    agent_id TEXT,
    action TEXT,
    decision TEXT NOT NULL,
    policy_code TEXT NOT NULL,
    reason TEXT NOT NULL,
    amount_usd REAL,
    slippage_bps INTEGER,
    timestamp INTEGER NOT NULL
  );
`);

db.run(`
  CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    transaction_hash TEXT NOT NULL,
    policy_code TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    status TEXT NOT NULL
  );
`);

/**
 * Additive migrations.
 *
 * The v0.4 tables above are created verbatim so an existing `arx.sqlite` keeps
 * working, then widened here. `ALTER TABLE ... ADD COLUMN` throws if the column
 * already exists and SQLite offers no `IF NOT EXISTS` for it, so each one is
 * attempted and the duplicate-column error swallowed. Anything else rethrows.
 */
function addColumn(table: string, definition: string): void {
  try {
    db.run(`ALTER TABLE ${table} ADD COLUMN ${definition};`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);

    if (!message.includes("duplicate column name")) {
      throw error;
    }
  }
}

// Capability v2: policy sets, limits, escalation rules.
addColumn("capabilities", "recipients TEXT NOT NULL DEFAULT '{}'");
addColumn("capabilities", "contracts TEXT NOT NULL DEFAULT '{}'");
addColumn("capabilities", "methods TEXT NOT NULL DEFAULT '{}'");
addColumn("capabilities", "limits TEXT NOT NULL DEFAULT '{}'");
addColumn("capabilities", "human_approval TEXT NOT NULL DEFAULT '{}'");
addColumn("capabilities", "max_risk_score REAL NOT NULL DEFAULT 80");
addColumn("capabilities", "allow_contract_creation INTEGER NOT NULL DEFAULT 0");
addColumn("capabilities", "value_tolerance_bps INTEGER NOT NULL DEFAULT 500");
addColumn("capabilities", "not_before INTEGER");
addColumn("capabilities", "label TEXT");

// Approval v2: risk, oracle value, escalation outcome, Arx's own signature.
addColumn("approvals", "chain_id INTEGER NOT NULL DEFAULT 0");
addColumn("approvals", "approval_type TEXT NOT NULL DEFAULT 'AUTO'");
addColumn("approvals", "risk_score REAL NOT NULL DEFAULT 0");
addColumn("approvals", "value_usd REAL NOT NULL DEFAULT 0");
addColumn("approvals", "reason TEXT NOT NULL DEFAULT ''");
addColumn("approvals", "authorization_signature TEXT");
addColumn("approvals", "authorization_key_id TEXT");
addColumn("approvals", "decided_by TEXT");
addColumn("approvals", "decided_at INTEGER");

/**
 * Tamper-evident audit chain.
 *
 * Each entry commits to the previous entry's hash, so removing or editing a
 * historical decision invalidates every hash after it. `GET /audit/verify`
 * recomputes the chain and reports the first break.
 */
db.run(`
  CREATE TABLE IF NOT EXISTS audit_chain (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    request_id TEXT,
    capability_id TEXT,
    agent_id TEXT,
    approval_id TEXT,
    transaction_id TEXT,
    decision TEXT,
    code TEXT,
    reason TEXT,
    payload TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    timestamp INTEGER NOT NULL
  );
`);

db.run(
  `CREATE INDEX IF NOT EXISTS idx_audit_chain_request ON audit_chain (request_id);`,
);
db.run(
  `CREATE INDEX IF NOT EXISTS idx_audit_chain_agent ON audit_chain (agent_id, timestamp);`,
);

/**
 * Spend accounting.
 *
 * A window limit cannot be enforced by summing past signatures alone: an
 * approval that has been issued but not yet signed is already committed
 * authority. Rows are written as RESERVED at approval time, moved to SETTLED on
 * a successful signature, and RELEASED if the approval expires or fails — so a
 * failed signing does not permanently consume the agent's budget.
 */
db.run(`
  CREATE TABLE IF NOT EXISTS spend_ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capability_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    approval_id TEXT NOT NULL UNIQUE,
    amount_usd REAL NOT NULL,
    value_wei TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
`);

db.run(
  `CREATE INDEX IF NOT EXISTS idx_spend_window ON spend_ledger (capability_id, state, created_at);`,
);

/**
 * Nonce ledger, separate from `processed_intents`.
 *
 * `processed_intents` answers "has this exact nonce been used?". This table
 * answers "what is the highest nonce this capability has accepted?", which is
 * what lets a reusable capability keep authorizing new actions while still
 * refusing an old replayed one.
 */
db.run(`
  CREATE TABLE IF NOT EXISTS capability_nonces (
    capability_id TEXT PRIMARY KEY,
    highest_nonce INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
`);

/**
 * Idempotency records.
 *
 * Keyed by (capability, intentId) with a hash of the intent body. A retry with
 * the same body replays the stored response; the same id with a different body
 * is a conflict, not a new authorization.
 */
db.run(`
  CREATE TABLE IF NOT EXISTS idempotency_records (
    capability_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    intent_hash TEXT NOT NULL,
    response_status INTEGER NOT NULL,
    response_body TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (capability_id, intent_id)
  );
`);

/**
 * Agent identities.
 *
 * An agent authenticates with an HMAC secret and can only ever exercise
 * capabilities an operator granted it. Critically, an agent cannot mint its own
 * capability — that is a control-plane action — which is what stops a
 * compromised agent from simply widening its own authority.
 */
db.run(`
  CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    label TEXT,
    secret_hash TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    last_seen_at INTEGER
  );
`);

/** Replay protection for authenticated requests, independent of intent nonces. */
db.run(`
  CREATE TABLE IF NOT EXISTS request_nonces (
    nonce_key TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    seen_at INTEGER NOT NULL
  );
`);

/** Cache for oracle prices and external risk lookups, with explicit staleness. */
db.run(`
  CREATE TABLE IF NOT EXISTS oracle_cache (
    cache_key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    source TEXT NOT NULL,
    fetched_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );
`);

export function resetDatabaseForTests(): void {
  if (env.nodeEnv !== "test") {
    throw new Error("resetDatabaseForTests is only available in NODE_ENV=test");
  }

  for (const table of [
    "capabilities",
    "processed_intents",
    "audit_logs",
    "audit_chain",
    "approvals",
    "spend_ledger",
    "capability_nonces",
    "idempotency_records",
    "agents",
    "request_nonces",
    "oracle_cache",
  ]) {
    db.run(`DELETE FROM ${table};`);
  }
}
