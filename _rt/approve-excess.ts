import { post, cap, intent, ADMIN } from "./lib";
import { encodeFunctionData } from "viem";

const USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
const ROUTER = "0x3333333333333333333333333333333333333333";

const c = cap({
  contracts: { mode: "ALLOWLIST", allow: [USDC], deny: [] },
  recipients: { mode: "ALLOWLIST", allow: [ROUTER], deny: [] },
  methods: { mode: "ALLOWLIST", allow: ["approve(address,uint256)"], deny: [] },
  limits: { maxValueWei: "0", maxGasLimit: "500000", maxFeePerGasWei: "500000000000", maxAmountUsdPerWindow: 0, windowSeconds: 86400, maxTxPerWindow: 0 },
  humanApproval: { requiredAboveUsd: 500, requiredForUnknownRecipient: true, requiredForMethods: [], requiredAboveRiskScore: 60, alwaysRequired: false },
  maxRiskScore: 80,
  maxAmountUsd: 1000,
});
console.log("cap", (await post("/capabilities", c, ADMIN)).status);

const abi = [{ name: "approve", type: "function", inputs: [{type:"address"},{type:"uint256"}], outputs: [] }] as const;

for (const [label, amount] of [
  ["2^256-1", (2n**256n-1n)],
  ["2^128",   (2n**128n)],
  ["2^128-1", (2n**128n-1n)],
  ["10^30 (=1e24 USDC, supply is ~4e10)", 10n**30n],
  ["10^12 (=1e6 USDC)", 10n**12n],
] as Array<[string, bigint]>) {
  const data = encodeFunctionData({ abi, functionName: "approve", args: [ROUTER, amount] });
  const r = await post("/firewall/submit", intent(c.capabilityId, { to: USDC, value: "0", data }, { amountUsd: 100 }));
  console.log(`${label.padEnd(40)} -> ${r.status} ${r.body.decision ?? ""} ${r.body.code ?? ""} :: ${(r.body.reason ?? "").slice(0,110)}`);
  if (r.body.riskScore !== undefined) console.log(`    riskScore=${r.body.riskScore} signals=${(r.body.riskSignals??[]).map((s:any)=>s.id).join(",")}`);
}
