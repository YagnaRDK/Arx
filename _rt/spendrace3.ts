import { post, cap, ADMIN, get } from "./lib";
// Repeat the race many times to catch a TOCTOU on the budget check.
let overbudgetSeen = 0;
for (let trial = 0; trial < 8; trial++) {
  const c = cap({
    limits: { maxValueWei: "100000000000000000000", maxGasLimit: "500000", maxFeePerGasWei: "500000000000",
      maxAmountUsdPerWindow: 3300, windowSeconds: 86400, maxTxPerWindow: 1 },
  });
  await post("/capabilities", c, ADMIN);
  const ts = Math.floor(Date.now()/1000);
  const mk = (n:number) => ({ capabilityId: c.capabilityId, agentId: "agent-a", action: "pay", protocol: "native", chainId: 1,
    inputToken: "ETH", outputToken: "ETH", amountUsd: 3200, slippageBps: 0, nonce: n+1, timestamp: ts,
    transaction: { chainId: 1, to: "0x1111111111111111111111111111111111111111", value: "1000000000000000000", data: "0x", gasLimit: "21000", maxFeePerGas: "20000000000", maxPriorityFeePerGas: "1000000000", nonce: n, type: "eip1559" } });
  const res = await Promise.all(Array.from({ length: 12 }, (_, i) => post("/approvals", mk(i))));
  const approved = res.filter(r => r.status === 201 || r.status === 202).length;
  const u = await get(`/capabilities/${c.capabilityId}`);
  const committed = u.body.spendWindow.amountUsd;
  if (approved > 1 || committed > 3300) overbudgetSeen++;
  console.log(`trial ${trial}: approved=${approved} committedUsd=${committed} txCount=${u.body.spendWindow.transactionCount}`);
}
console.log("OVER-BUDGET TRIALS:", overbudgetSeen);
