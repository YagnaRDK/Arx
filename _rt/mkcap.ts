import { post, cap, ADMIN } from "./lib";
const c = cap({
  limits: { maxValueWei: "10000000000000000000", maxGasLimit: "500000", maxFeePerGasWei: "500000000000",
            maxAmountUsdPerWindow: 3300, windowSeconds: 86400, maxTxPerWindow: 1 },
});
await post("/capabilities", c, ADMIN);
const ts = Math.floor(Date.now()/1000);
for (let i = 0; i < 8; i++) {
  const body = { capabilityId: c.capabilityId, agentId: "agent-a", action: "pay", protocol: "native", chainId: 1,
    inputToken: "ETH", outputToken: "ETH", amountUsd: 3200, slippageBps: 0, nonce: i+1, timestamp: ts,
    transaction: { chainId: 1, to: "0x1111111111111111111111111111111111111111", value: "1000000000000000000", data: "0x", gasLimit: "21000", maxFeePerGas: "20000000000", maxPriorityFeePerGas: "1000000000", nonce: i, type: "eip1559" } };
  await Bun.write(`_rt/req${i}.json`, JSON.stringify(body));
}
console.log(c.capabilityId);
