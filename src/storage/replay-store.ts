import { db } from "../db/database";

export class ReplayStore {
  private readonly existsStatement = db.prepare(`
    SELECT replay_key
    FROM processed_intents
    WHERE replay_key = ?
  `);

  private readonly insertStatement = db.prepare(`
    INSERT INTO processed_intents (
      replay_key,
      capability_id,
      agent_id,
      nonce,
      processed_at
    )
    VALUES (?, ?, ?, ?, ?)
  `);

  private createReplayKey(
    capabilityId: string,
    agentId: string,
    nonce: number,
  ): string {
    return `${capabilityId}:${agentId}:${nonce}`;
  }

  hasBeenProcessed(
    capabilityId: string,
    agentId: string,
    nonce: number,
  ): boolean {
    const replayKey = this.createReplayKey(capabilityId, agentId, nonce);

    const result = this.existsStatement.get(replayKey) as
      | { replay_key: string }
      | null
      | undefined;

    return Boolean(result);
  }

  markProcessed(capabilityId: string, agentId: string, nonce: number): void {
    const replayKey = this.createReplayKey(capabilityId, agentId, nonce);

    this.insertStatement.run(
      replayKey,
      capabilityId,
      agentId,
      nonce,
      Math.floor(Date.now() / 1000),
    );
  }
}
