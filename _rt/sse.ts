import { plain, ADMIN2 } from "./lib2";
import { cap, intent } from "./lib";
// open the stream with NO credentials
const ctrl = new AbortController();
const resp = await fetch("http://127.0.0.1:3961/events/stream", { signal: ctrl.signal });
console.log("SSE status:", resp.status, resp.headers.get("content-type"));
const reader = resp.body!.getReader();
const dec = new TextDecoder();
let captured = "";
const pump = (async () => {
  try { while (true) { const { done, value } = await reader.read(); if (done) break; captured += dec.decode(value); } } catch {}
})();

// Meanwhile, drive a decision as admin+agent on the locked-down server.
const c = cap({ agentId: "agent-leak" });
await plain("/capabilities", "POST", c, ADMIN2);
const { signedReq } = await import("./lib2");
const reg = await plain("/agents", "POST", { agentId: "agent-leak" }, ADMIN2);
const secret = reg.body.secret ?? reg.body.agentSecret ?? JSON.stringify(reg.body);
const i = intent(c.capabilityId, { to: "0x9999999999999999999999999999999999999999", value: "1000000000000000" }, { amountUsd: 3.2, nonce: 7 });
i.agentId = "agent-leak";
const r = await signedReq("agent-leak", String(secret), "POST", "/firewall/submit", i);
console.log("submit:", r.status, r.body.code);
await new Promise((res) => setTimeout(res, 700));
ctrl.abort();
await pump;
console.log("--- captured bytes:", captured.length);
console.log(captured.slice(-1800));
