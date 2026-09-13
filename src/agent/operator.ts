import type { Capability } from "../types/capability";

/**
 * Control-plane actions performed by the human operator, not by the agent.
 *
 * Issuing a capability is the act of granting authority, so it lives here —
 * outside the agent's tool surface and outside the MCP server — and it is the
 * demo harness, standing in for a person, that calls it. The agent process has
 * no import path to this module's credentials and no tool that reaches it,
 * which is what invariant 11 means in practice: the thing being authorised
 * cannot be the thing that authorises.
 */

export type OperatorConfig = {
  baseUrl: string;
  adminToken: string;
  requestTimeoutMs: number;
};

export function loadOperatorConfig(
  baseUrl: string,
  requestTimeoutMs = 10_000,
): OperatorConfig {
  return {
    baseUrl: baseUrl.endsWith("/") ? baseUrl.slice(0, -1) : baseUrl,
    adminToken: process.env.ARX_ADMIN_TOKEN ?? "",
    requestTimeoutMs,
  };
}

function headers(config: OperatorConfig): Record<string, string> {
  const base: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json",
  };

  if (config.adminToken) {
    // Both spellings are sent because the control-plane auth header is still
    // being settled in the HTTP layer; whichever one lands, provisioning works.
    base.authorization = `Bearer ${config.adminToken}`;
    base["x-arx-admin-token"] = config.adminToken;
  }

  return base;
}

export type ProvisionResult =
  | { ok: true; capability: Capability; status: number }
  | { ok: false; status: number; error: string };

export async function provisionCapability(
  config: OperatorConfig,
  capability: Capability,
): Promise<ProvisionResult> {
  try {
    const response = await fetch(`${config.baseUrl}/capabilities`, {
      method: "POST",
      headers: headers(config),
      body: JSON.stringify(capability),
      signal: AbortSignal.timeout(config.requestTimeoutMs),
    });

    const text = await response.text();

    if (!response.ok) {
      return { ok: false, status: response.status, error: text };
    }

    return { ok: true, capability, status: response.status };
  } catch (error) {
    return {
      ok: false,
      status: 0,
      error: `Arx control plane at ${config.baseUrl} is unreachable: ${
        error instanceof Error ? error.message : String(error)
      }`,
    };
  }
}

export async function arxReachable(config: OperatorConfig): Promise<boolean> {
  try {
    const response = await fetch(`${config.baseUrl}/`, {
      signal: AbortSignal.timeout(config.requestTimeoutMs),
    });

    return response.ok;
  } catch {
    return false;
  }
}
