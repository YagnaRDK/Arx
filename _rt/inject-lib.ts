import { buildServer } from "../src/api/server";
import { signRequestWithSecret } from "../src/auth/agent-auth";

export const app = await buildServer();
export const ADMIN = { "x-arx-admin-token": "rtadmin" };
let n = 0;

export async function adminPost(url: string, payload: unknown) {
  const r = await app.inject({ method: "POST", url, headers: ADMIN, payload: payload as object });
  return { status: r.statusCode, body: safe(r.body) };
}
export async function adminGet(url: string) {
  const r = await app.inject({ method: "GET", url, headers: ADMIN });
  return { status: r.statusCode, body: safe(r.body) };
}
export async function anonGet(url: string) {
  const r = await app.inject({ method: "GET", url });
  return { status: r.statusCode, body: safe(r.body) };
}
export async function agentReq(agentId: string, secret: string, method: "POST"|"GET", url: string, payload?: unknown) {
  const ts = Math.floor(Date.now()/1000);
  const nonce = `rt-${n++}-${Math.random().toString(36).slice(2)}`;
  const sig = signRequestWithSecret(agentId, secret, { method, path: url, timestamp: ts, nonce, body: payload });
  const r = await app.inject({ method, url, headers: {
    "x-arx-agent": agentId, "x-arx-timestamp": String(ts), "x-arx-nonce": nonce, "x-arx-signature": sig,
    "content-type": "application/json",
  }, ...(payload === undefined ? {} : { payload: payload as object }) });
  return { status: r.statusCode, body: safe(r.body) };
}
function safe(b: string) { try { return JSON.parse(b); } catch { return b; } }
