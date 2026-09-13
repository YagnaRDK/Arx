/**
 * Direct SQLite access, used by exactly one scenario.
 *
 * The audit-tamper demo has to act as an attacker with database write access —
 * that is the whole threat model the hash chain exists for. So it edits a
 * historical row out of band, through the file rather than through any API, and
 * then asks `GET /audit/verify` whether Arx notices. Going through an endpoint
 * would prove nothing: a tamper endpoint is a tamper the system consented to.
 *
 * The edit is reverted afterwards so the rest of the run still has an intact
 * chain to report, and the revert is itself verified.
 */

import { Database } from "bun:sqlite";
import { existsSync } from "node:fs";

export type ChainRow = { seq: number; reason: string | null; entry_hash: string };

export class AuditDatabase {
  private readonly db: Database;

  constructor(readonly path: string) {
    if (!existsSync(path)) {
      throw new Error(`Audit database not found at ${path}`);
    }

    this.db = new Database(path, { readwrite: true });
    this.db.run("PRAGMA busy_timeout = 5000;");
  }

  count(): number {
    const row = this.db
      .query("SELECT COUNT(*) AS n FROM audit_chain")
      .get() as { n: number } | null;

    return row?.n ?? 0;
  }

  /** A row in the middle of the chain: the most damaging place to edit, since
   * every later entry's hash depends on it. */
  middleRow(): ChainRow | null {
    const total = this.count();

    if (total < 3) {
      return null;
    }

    return (
      (this.db
        .query(
          "SELECT seq, reason, entry_hash FROM audit_chain ORDER BY seq ASC LIMIT 1 OFFSET ?",
        )
        .get(Math.floor(total / 2)) as ChainRow | null) ?? null
    );
  }

  setReason(seq: number, reason: string | null): void {
    this.db
      .query("UPDATE audit_chain SET reason = ? WHERE seq = ?")
      .run(reason, seq);
  }

  close(): void {
    this.db.close();
  }
}
