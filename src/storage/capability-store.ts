import { db } from "../db/database";
import type { Capability, CapabilityStatus } from "../types/capability";

type CapabilityRow = {
  capability_id: string;
  agent_id: string;
  allowed_actions: string;
  allowed_protocols: string;
  allowed_chains: string;
  allowed_input_tokens: string;
  allowed_output_tokens: string;
  max_amount_usd: number;
  max_slippage_bps: number;
  expires_at: number;
  nonce: number;
  status: CapabilityStatus;
  usage: "SINGLE_USE" | "REUSABLE";
};

function rowToCapability(row: CapabilityRow): Capability {
  return {
    capabilityId: row.capability_id,
    agentId: row.agent_id,
    allowedActions: JSON.parse(row.allowed_actions),
    allowedProtocols: JSON.parse(row.allowed_protocols),
    allowedChains: JSON.parse(row.allowed_chains),
    allowedTokens: {
      input: JSON.parse(row.allowed_input_tokens),
      output: JSON.parse(row.allowed_output_tokens),
    },
    maxAmountUsd: row.max_amount_usd,
    maxSlippageBps: row.max_slippage_bps,
    expiresAt: row.expires_at,
    nonce: row.nonce,
    status: row.status,
    usage: row.usage,
  };
}

export class CapabilityStore {
  private readonly insertStatement = db.prepare(`
    INSERT INTO capabilities (
      capability_id,
      agent_id,
      allowed_actions,
      allowed_protocols,
      allowed_chains,
      allowed_input_tokens,
      allowed_output_tokens,
      max_amount_usd,
      max_slippage_bps,
      expires_at,
      nonce,
      status,
      usage,
      created_at,
      updated_at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  private readonly getStatement = db.prepare(`
    SELECT *
    FROM capabilities
    WHERE capability_id = ?
  `);

  private readonly revokeStatement = db.prepare(`
    UPDATE capabilities
    SET status = 'REVOKED',
        updated_at = ?
    WHERE capability_id = ?
      AND status = 'ACTIVE'
  `);

  private readonly consumeStatement = db.prepare(`
    UPDATE capabilities
    SET status = 'CONSUMED',
        updated_at = ?
    WHERE capability_id = ?
      AND status = 'ACTIVE'
      AND usage = 'SINGLE_USE'
  `);

  create(capability: Capability): Capability {
    const now = Math.floor(Date.now() / 1000);

    this.insertStatement.run(
      capability.capabilityId,
      capability.agentId,
      JSON.stringify(capability.allowedActions),
      JSON.stringify(capability.allowedProtocols),
      JSON.stringify(capability.allowedChains),
      JSON.stringify(capability.allowedTokens.input),
      JSON.stringify(capability.allowedTokens.output),
      capability.maxAmountUsd,
      capability.maxSlippageBps,
      capability.expiresAt,
      capability.nonce,
      capability.status,
      capability.usage,
      now,
      now,
    );

    return capability;
  }

  get(capabilityId: string): Capability | null {
    const row = this.getStatement.get(capabilityId) as
      | CapabilityRow
      | null
      | undefined;

    if (!row) {
      return null;
    }

    return rowToCapability(row);
  }

  revoke(capabilityId: string): boolean {
    const result = this.revokeStatement.run(
      Math.floor(Date.now() / 1000),
      capabilityId,
    );

    return result.changes > 0;
  }

  consume(capabilityId: string): boolean {
    const result = this.consumeStatement.run(
      Math.floor(Date.now() / 1000),
      capabilityId,
    );

    return result.changes > 0;
  }
}
