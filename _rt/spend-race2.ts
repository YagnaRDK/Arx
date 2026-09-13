import { post, cap, intent, ADMIN, get } from "./lib";

const c = cap({
  limits: { maxValueWei: "10000000000000000000", maxGasLimit: "500000", maxFeePerGasWei: "500000000000",
            maxAmountUsdPerWindow: 3300, windowSeconds: 86400, maxTxPerWindow: 1 },
});
console.log("cap create", (await post("/capabilities", c, ADMIN)).status);

const ONE_ETH = "1000000000000000000";
const mk = (n: number) => intent(c.capabilityId, { to: "0x1111111111111111111111111111111111111111", value: ONE_ETH, nonce: n }, { amountUsd: 3200, nonce: n + 1 });

const results = await Promise.all(Array.from({ length: 8 }, (_, i) => post("/approvals", mk(i))));
let approved = 0;
for (const r of results) { if (r.status === 201 || r.status === 202) approved++; console.log(r.status, r.body.code ?? r.body.status, (r.body.reason ?? "").slice(0,80)); }
console.log("APPROVED COUNT:", approved);
console.log("spendWindow:", JSON.stringify((await get(`/capabilities/${c.capabilityId}`)).body.spendWindow));
