import { post, cap, intent, ADMIN, get } from "./lib";

const c = cap({
  limits: { maxValueWei: "10000000000000000000", maxGasLimit: "500000", maxFeePerGasWei: "500000000000",
            maxAmountUsdPerWindow: 3300, windowSeconds: 86400, maxTxPerWindow: 1 },
});
const r = await post("/capabilities", c, ADMIN);
console.log("cap create", r.status);

const ONE_ETH = "1000000000000000000";
const mk = () => intent(c.capabilityId, { to: "0x1111111111111111111111111111111111111111", value: ONE_ETH }, { amountUsd: 3200 });

const results = await Promise.all(Array.from({ length: 6 }, () => post("/approvals", mk())));
for (const r of results) console.log(r.status, r.body.code ?? r.body.status, r.body.approval?.approvalId ?? r.body.reason?.slice(0,90));

const usage = await get(`/capabilities/${c.capabilityId}`);
console.log("spendWindow:", JSON.stringify(usage.body.spendWindow));
