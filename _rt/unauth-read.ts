import { plain, ADMIN2 } from "./lib2";
import { cap } from "./lib";

// Mint a capability as admin.
const c = cap({ agentId: "agent-a" });
console.log("cap create:", (await plain("/capabilities", "POST", c, ADMIN2)).status);

const probes = [
  "/health", "/signer", "/integrations", "/capabilities",
  `/capabilities/${c.capabilityId}`, "/approvals", "/approvals/pending",
  "/audit", "/audit/verify", "/agents", "/broker/status",
  "/oracle/price?asset=ETH&chainId=1",
];
for (const p of probes) {
  const r = await plain(p);
  console.log(String(r.status).padEnd(4), p.padEnd(42), typeof r.body === "object" ? JSON.stringify(r.body).slice(0, 110) : String(r.body).slice(0,110));
}
