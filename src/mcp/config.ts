/**
 * Configuration for the MCP surface.
 *
 * These values are read here rather than added to `src/config/env.ts` because
 * the MCP server is a *client* of Arx, not part of it: it runs in the agent's
 * process (often on the agent's machine) and talks to Arx over HTTP. Giving it
 * the server's config object would blur exactly the boundary this module exists
 * to make real.
 *
 * Note what is deliberately absent: `ARX_ADMIN_TOKEN`. The control plane mints
 * and revokes capabilities, and invariant 11 says an agent cannot widen its own
 * authority. The MCP process therefore never holds an admin credential, so no
 * sequence of MCP tool calls can produce one.
 */

export type ArxRouteTable = {
  /** Full pipeline: policy -> normalize -> firewall -> approval artifact. */
  propose: string;
  /** Policy + firewall only. Produces a decision but never signing authority. */
  proposeFirewallFallback: string;
  /** Capability evaluation only. Weakest of the three; still never signs. */
  proposePolicyFallback: string;

  approvalById: string;
  sign: string;

  capabilitiesByAgent: readonly string[];
  capabilityById: string;

  auditTrail: readonly string[];
  auditVerify: readonly string[];
};

export type ArxMcpConfig = {
  baseUrl: string;
  requestTimeoutMs: number;
  /**
   * The agent identity this MCP process speaks for. It is a *claim*: Arx binds
   * authority to the capability it looks up, not to this header.
   */
  agentId: string;
  /** Opaque data-plane credential, forwarded as a bearer token when present. */
  agentToken: string;
  routes: ArxRouteTable;
};

const DEFAULT_ROUTES: ArxRouteTable = {
  propose: "/approvals",
  proposeFirewallFallback: "/firewall/submit",
  proposePolicyFallback: "/evaluate",

  approvalById: "/approvals/{approvalId}",
  sign: "/sign",

  // Several spellings are tried because the HTTP surface is still moving. A
  // missing route is reported as missing; it is never treated as a pass.
  capabilitiesByAgent: [
    "/capabilities?agentId={agentId}",
    "/agents/{agentId}/capabilities",
  ],
  capabilityById: "/capabilities/{capabilityId}",

  auditTrail: [
    "/audit/trail/{requestId}",
    "/audit?requestId={requestId}",
    "/audit/{requestId}",
  ],
  auditVerify: ["/audit/verify", "/audit/chain/verify"],
};

function trimTrailingSlash(value: string): string {
  return value.endsWith("/") ? value.slice(0, -1) : value;
}

export function loadArxMcpConfig(
  overrides: Partial<ArxMcpConfig> = {},
): ArxMcpConfig {
  const baseUrl = trimTrailingSlash(
    process.env.ARX_MCP_BASE_URL ??
      process.env.ARX_BASE_URL ??
      "http://127.0.0.1:3000",
  );

  const timeout = Number(process.env.ARX_MCP_TIMEOUT_MS ?? 10_000);

  return {
    baseUrl,
    requestTimeoutMs:
      Number.isFinite(timeout) && timeout > 0 ? timeout : 10_000,
    agentId: process.env.ARX_AGENT_ID ?? "",
    agentToken: process.env.ARX_AGENT_TOKEN ?? "",
    routes: DEFAULT_ROUTES,
    ...overrides,
  };
}
