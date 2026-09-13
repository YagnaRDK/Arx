import { signRequestWithSecret } from "../src/auth/agent-auth";
export const BASE2 = "http://127.0.0.1:3961";
export const ADMIN2 = { "x-arx-admin-token": "rtadmin", "content-type": "application/json" };
export const now = () => Math.floor(Date.now() / 1000);
let n = 0;

export async function signedReq(
  agentId: string, secret: string, method: string, path: string, body?: unknown,
) {
  const ts = now();
  const nonce = `rt-${agentId}-${Date.now()}-${n++}-${Math.random().toString(36).slice(2)}`;
  const sig = signRequestWithSecret(agentId, secret, { method, path, timestamp: ts, nonce, body });
  const headers: Record<string,string> = {
    "content-type": "application/json",
    "x-arx-agent": agentId, "x-arx-timestamp": String(ts), "x-arx-nonce": nonce, "x-arx-signature": sig,
  };
  const r = await fetch(BASE2 + path, { method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  const t = await r.text();
  let j: any; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}

export async function plain(path: string, method = "GET", body?: unknown, headers: Record<string,string> = {}) {
  const r = await fetch(BASE2 + path, { method, headers: { "content-type": "application/json", ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  const t = await r.text();
  let j: any; try { j = JSON.parse(t); } catch { j = t; }
  return { status: r.status, body: j };
}
