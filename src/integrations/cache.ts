/**
 * TTL cache for integration lookups, backed by the `oracle_cache` table.
 *
 * Caching an authorization input is a security decision, not just a latency
 * one: a stale answer that is treated as fresh is indistinguishable from a
 * compromised one. So every entry carries an absolute `expires_at` that is
 * checked on read, entries are never served past it, and the fetch timestamp
 * travels with the value so a caller can record how old the evidence was when
 * it authorized something.
 *
 * TTLs here are deliberately short. ENS in particular is re-resolved often
 * because a name can be re-pointed at any moment; see `ens/ens-resolver.ts`.
 */

import { db } from "../db/database";

export type CachedEntry<T> = {
  value: T;
  source: string;
  fetchedAt: number;
  expiresAt: number;
};

const selectStatement = db.prepare<
  {
    value: string;
    source: string;
    fetched_at: number;
    expires_at: number;
  },
  [string]
>(
  `SELECT value, source, fetched_at, expires_at
     FROM oracle_cache
    WHERE cache_key = ?`,
);

const upsertStatement = db.prepare<
  unknown,
  [string, string, string, number, number]
>(
  `INSERT INTO oracle_cache (cache_key, value, source, fetched_at, expires_at)
        VALUES (?, ?, ?, ?, ?)
   ON CONFLICT(cache_key) DO UPDATE SET
        value = excluded.value,
        source = excluded.source,
        fetched_at = excluded.fetched_at,
        expires_at = excluded.expires_at`,
);

const deleteStatement = db.prepare<unknown, [string]>(
  `DELETE FROM oracle_cache WHERE cache_key = ?`,
);

/**
 * Namespaced so adapters cannot collide with the price oracle, which shares
 * this table.
 */
export function cacheKey(namespace: string, ...parts: string[]): string {
  return [namespace, ...parts.map((part) => part.toLowerCase())].join(":");
}

/**
 * Reads a live entry. `now` is injected so cache freshness is part of the
 * caller's deterministic time frame rather than a hidden clock read.
 */
export function readCache<T>(key: string, now: number): CachedEntry<T> | null {
  const row = selectStatement.get(key);

  if (row === null) {
    return null;
  }

  if (row.expires_at <= now) {
    // Expired rows are dropped on read rather than swept on a timer, so a
    // stale value can never be returned by a later code path that forgets to
    // check the expiry.
    deleteStatement.run(key);

    return null;
  }

  try {
    return {
      value: JSON.parse(row.value) as T,
      source: row.source,
      fetchedAt: row.fetched_at,
      expiresAt: row.expires_at,
    };
  } catch {
    deleteStatement.run(key);

    return null;
  }
}

export function writeCache<T>(input: {
  key: string;
  value: T;
  source: string;
  now: number;
  ttlSeconds: number;
}): CachedEntry<T> {
  const expiresAt = input.now + Math.max(1, Math.floor(input.ttlSeconds));

  upsertStatement.run(
    input.key,
    JSON.stringify(input.value),
    input.source,
    input.now,
    expiresAt,
  );

  return {
    value: input.value,
    source: input.source,
    fetchedAt: input.now,
    expiresAt,
  };
}

export function invalidateCache(key: string): void {
  deleteStatement.run(key);
}

const claimStatement = db.prepare<
  unknown,
  [string, string, string, number, number]
>(
  `INSERT OR IGNORE INTO oracle_cache
        (cache_key, value, source, fetched_at, expires_at)
   VALUES (?, ?, ?, ?, ?)`,
);

const existsStatement = db.prepare<{ expires_at: number }, [string]>(
  `SELECT expires_at FROM oracle_cache WHERE cache_key = ?`,
);

/**
 * Claims a key exactly once within its TTL, atomically.
 *
 * `INSERT OR IGNORE` makes the claim a single statement, so two concurrent
 * requests presenting the same x402 payment nonce cannot both win: SQLite
 * serializes the insert and the loser sees `claimed: false`. A read-then-write
 * check would be a textbook double-spend window.
 *
 * An expired row is deleted and re-claimed, which is correct here because the
 * TTL is set from the payment's own `validBefore`: once the authorization can no
 * longer be settled, its nonce is no longer a replay risk.
 */
export function claimOnce(input: {
  key: string;
  source: string;
  now: number;
  ttlSeconds: number;
}): { claimed: boolean } {
  const existing = existsStatement.get(input.key);

  if (existing !== null && existing.expires_at <= input.now) {
    deleteStatement.run(input.key);
  }

  const expiresAt = input.now + Math.max(1, Math.floor(input.ttlSeconds));

  const result = claimStatement.run(
    input.key,
    JSON.stringify({ claimedAt: input.now }),
    input.source,
    input.now,
    expiresAt,
  );

  // `changes === 0` means the row already existed and the insert was ignored,
  // which is exactly the replay case. Reading the row back and comparing
  // timestamps instead would tie two same-second claims, so the write's own
  // affected-row count is the only safe witness.
  return { claimed: result.changes === 1 };
}
