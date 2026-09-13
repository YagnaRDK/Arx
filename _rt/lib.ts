export const BASE = "http://127.0.0.1:3960";
export const ADMIN = { "x-arx-admin-token": "rtadmin", "content-type": "application/json" };

export async function post(path: string, body: unknown, headers: Record<string,string> = {}) {
  const r = await fetch(BASE + path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
  let j: any; const t = await r.text();
  try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}
export async function postRaw(path: string, raw: string, headers: Record<string,string> = {}) {
  const r = await fetch(BASE + path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: raw });
  const t = await r.text();
  let j: any; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}
export async function get(path: string, headers: Record<string,string> = {}) {
  const r = await fetch(BASE + path, { headers });
  const t = await r.text();
  let j: any; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}

export const now = () => Math.floor(Date.now() / 1000);

export function cap(overrides: Record<string, unknown> = {}) {
  return {
    capabilityId: "cap-" + Math.random().toString(36).slice(2, 10),
    agentId: "agent-a",
    allowedActions: ["pay"],
    allowedProtocols: ["native"],
    allowedChains: [1],
    allowedTokens: { input: ["ETH"], output: ["ETH"] },
    maxAmountUsd: 1_000_000,
    maxSlippageBps: 100,
    expiresAt: now() + 3600,
    nonce: 0,
    status: "ACTIVE",
    usage: "REUSABLE",
    recipients: { mode: "ALLOWLIST", allow: ["0x1111111111111111111111111111111111111111"], deny: [] },
    contracts: { mode: "ALLOWLIST", allow: ["0x2222222222222222222222222222222222222222"], deny: [] },
    methods: { mode: "ALLOWLIST", allow: ["transfer(address,uint256)"], deny: [] },
    limits: { maxValueWei: "1000000000000000000000", maxGasLimit: "500000", maxFeePerGasWei: "500000000000", maxAmountUsdPerWindow: 0, windowSeconds: 86400, maxTxPerWindow: 0 },
    humanApproval: { requiredAboveUsd: 0, requiredForUnknownRecipient: false, requiredForMethods: [], requiredAboveRiskScore: 100, alwaysRequired: false },
    maxRiskScore: 100,
    allowContractCreation: false,
    valueToleranceBps: 500,
    ...overrides,
  };
}

export function intent(capabilityId: string, tx: Record<string, unknown>, overrides: Record<string, unknown> = {}) {
  return {
    capabilityId, agentId: "agent-a",
    action: "pay", protocol: "native", chainId: 1,
    inputToken: "ETH", outputToken: "ETH",
    amountUsd: 100, slippageBps: 0,
    nonce: Math.floor(Math.random() * 1e9), timestamp: now(),
    transaction: { chainId: 1, value: "0", data: "0x", gasLimit: "21000", maxFeePerGas: "20000000000", maxPriorityFeePerGas: "1000000000", nonce: 0, type: "eip1559", ...tx },
    ...overrides,
  };
}
