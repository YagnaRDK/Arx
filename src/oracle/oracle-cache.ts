import { db } from "../db/database";

/**
 * A cache with an explicit expiry, not a TTL-by-convention.
 *
 * An oracle cache that returns a value without saying how old it is turns a
 * staleness bound into a suggestion. Entries carry both `fetchedAt` (when the
 * upstream observation was taken) and `expiresAt` (when this process agreed to
 * stop trusting it), and a read past `expiresAt` is a miss.
 */
export type OracleCacheEntry = {
  value: string;
  source: string;
  fetchedAt: number;
  expiresAt: number;
};

export interface OracleCache {
  get(key: string, now: number): OracleCacheEntry | undefined;
  set(key: string, entry: OracleCacheEntry): void;
}

/** Backed by the `oracle_cache` table, so a restart does not re-hammer an RPC. */
export class SqliteOracleCache implements OracleCache {
  private readonly getStatement = db.prepare(`
    SELECT value, source, fetched_at, expires_at
    FROM oracle_cache
    WHERE cache_key = ?
  `);

  private readonly setStatement = db.prepare(`
    INSERT INTO oracle_cache (cache_key, value, source, fetched_at, expires_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT (cache_key) DO UPDATE SET
      value = excluded.value,
      source = excluded.source,
      fetched_at = excluded.fetched_at,
      expires_at = excluded.expires_at
  `);

  get(key: string, now: number): OracleCacheEntry | undefined {
    const row = this.getStatement.get(key) as
      | {
          value: string;
          source: string;
          fetched_at: number;
          expires_at: number;
        }
      | undefined;

    if (!row || row.expires_at <= now) {
      return undefined;
    }

    return {
      value: row.value,
      source: row.source,
      fetchedAt: row.fetched_at,
      expiresAt: row.expires_at,
    };
  }

  set(key: string, entry: OracleCacheEntry): void {
    this.setStatement.run(
      key,
      entry.value,
      entry.source,
      entry.fetchedAt,
      entry.expiresAt,
    );
  }
}

/** In-process cache, for tests and for running without a database. */
export class MemoryOracleCache implements OracleCache {
  private readonly entries = new Map<string, OracleCacheEntry>();

  get(key: string, now: number): OracleCacheEntry | undefined {
    const entry = this.entries.get(key);

    if (!entry || entry.expiresAt <= now) {
      return undefined;
    }

    return entry;
  }

  set(key: string, entry: OracleCacheEntry): void {
    this.entries.set(key, entry);
  }
}
