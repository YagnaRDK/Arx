import { db } from "../db/database";
import {
  CapabilitySchema,
  type Capability,
  type CapabilityStatus,
} from "../types/capability";

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
  recipients: string;
  contracts: string;
  methods: string;
  limits: string;
  human_approval: string;
  max_risk_score: number;
  allow_contract_creation: number;
  value_tolerance_bps: number;
  not_before: number | null;
  label: string | null;
};

/**
 * Rows written before the v2 columns existed hold `'{}'`, so each JSON column is
 * re-parsed through the schema rather than trusted. That way a legacy row picks
 * up the current fail-closed defaults instead of an empty object that would
 * bypass checks reading `capability.recipients.mode`.
 */
function parseJsonColumn(raw: string): unknown {
  if (!raw) {
    return undefined;
  }

  try {
    const parsed = JSON.parse(raw);
    return Object.keys(parsed as object).length === 0 ? undefined : parsed;
  } catch {
    return undefined;
  }
}

function rowToCapability(row: CapabilityRow): Capability {
  return CapabilitySchema.parse({
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
    notBefore: row.not_before ?? undefined,
    nonce: row.nonce,
    status: row.status,
    usage: row.usage,
    recipients: parseJsonColumn(row.recipients),
    contracts: parseJsonColumn(row.contracts),
    methods: parseJsonColumn(row.methods),
    limits: parseJsonColumn(row.limits),
    humanApproval: parseJsonColumn(row.human_approval),
    maxRiskScore: row.max_risk_score,
    allowContractCreation: row.allow_contract_creation === 1,
    valueToleranceBps: row.value_tolerance_bps,
    label: row.label ?? undefined,
  });
}

export class CapabilityStore {
  private readonly insertStatement = db.prepare(`
    INSERT INTO capabilities (
      capability_id, agent_id,
      allowed_actions, allowed_protocols, allowed_chains,
      allowed_input_tokens, allowed_output_tokens,
      max_amount_usd, max_slippage_bps,
      expires_at, nonce, status, usage,
      created_at, updated_at,
      recipients, contracts, methods, limits, human_approval,
      max_risk_score, allow_contract_creation, value_tolerance_bps,
      not_before, label
    )
    VALUES (
      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
    )
  `);

  private readonly getStatement = db.prepare(`
    SELECT * FROM capabilities WHERE capability_id = ?
  `);

  private readonly listStatement = db.prepare(`
    SELECT * FROM capabilities ORDER BY created_at DESC LIMIT ?
  `);

  private readonly listByAgentStatement = db.prepare(`
    SELECT * FROM capabilities WHERE agent_id = ? ORDER BY created_at DESC LIMIT ?
  `);

  private readonly revokeStatement = db.prepare(`
    UPDATE capabilities
    SET status = 'REVOKED', updated_at = ?
    WHERE capability_id = ? AND status = 'ACTIVE'
  `);

  private readonly consumeStatement = db.prepare(`
    UPDATE capabilities
    SET status = 'CONSUMED', updated_at = ?
    WHERE capability_id = ? AND status = 'ACTIVE' AND usage = 'SINGLE_USE'
  `);

  create(capability: Capability, now = Math.floor(Date.now() / 1000)): Capability {
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
      JSON.stringify(capability.recipients),
      JSON.stringify(capability.contracts),
      JSON.stringify(capability.methods),
      JSON.stringify(capability.limits),
      JSON.stringify(capability.humanApproval),
      capability.maxRiskScore,
      capability.allowContractCreation ? 1 : 0,
      capability.valueToleranceBps,
      capability.notBefore ?? null,
      capability.label ?? null,
    );

    return capability;
  }

  get(capabilityId: string): Capability | null {
    const row = this.getStatement.get(capabilityId) as
      | CapabilityRow
      | null
      | undefined;

    return row ? rowToCapability(row) : null;
  }

  list(limit = 100): Capability[] {
    const rows = this.listStatement.all(limit) as CapabilityRow[];
    return rows.map(rowToCapability);
  }

  listByAgent(agentId: string, limit = 100): Capability[] {
    const rows = this.listByAgentStatement.all(
      agentId,
      limit,
    ) as CapabilityRow[];
    return rows.map(rowToCapability);
  }

  revoke(capabilityId: string, now = Math.floor(Date.now() / 1000)): boolean {
    return this.revokeStatement.run(now, capabilityId).changes > 0;
  }

  consume(capabilityId: string, now = Math.floor(Date.now() / 1000)): boolean {
    return this.consumeStatement.run(now, capabilityId).changes > 0;
  }
}
