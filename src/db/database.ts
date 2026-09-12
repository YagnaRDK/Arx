import { Database } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { env } from "../config/env";

mkdirSync(dirname(env.databasePath), { recursive: true });

export const db = new Database(env.databasePath);

db.run("PRAGMA journal_mode = WAL;");
db.run("PRAGMA foreign_keys = ON;");

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
