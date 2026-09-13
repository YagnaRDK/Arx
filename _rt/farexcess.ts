import { post, cap, intent, ADMIN } from "./lib";
import { encodeFunctionData } from "viem";
const USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
const ROUTER = "0x3333333333333333333333333333333333333333";
const c = cap({
  contracts: { mode: "ALLOWLIST", allow: [USDC], deny: [] },
  recipients: { mode: "ALLOWLIST", allow: [ROUTER], deny: [] },  // router is the allowlisted spender
  methods: { mode: "ALLOWLIST", allow: ["approve(address,uint256)"], deny: [] },
  limits: { maxValueWei: "0", maxGasLimit: "500000", maxFeePerGasWei: "500000000000", maxAmountUsdPerWindow: 0, windowSeconds: 86400, maxTxPerWindow: 0 },
  // Full escalation policy: far-excess should trigger human approval.
  humanApproval: { requiredAboveUsd: 500, requiredForUnknownRecipient: true, requiredForMethods: [], requiredAboveRiskScore: 60, alwaysRequired: false },
  maxRiskScore: 80, maxAmountUsd: 1000,
});
await post("/capabilities", c, ADMIN);
const abi = [{ name: "approve", type: "function", inputs: [{type:"address"},{type:"uint256"}], outputs: [] }] as const;
// 500,000 USDC allowance = 5e11 base units. Declared action value: $100. That's 5000x, and $500k > $500 threshold.
const data = encodeFunctionData({ abi, functionName: "approve", args: [ROUTER, 500_000n * 10n**6n] });
const r = await post("/firewall/submit", intent(c.capabilityId, { to: USDC, value: "0", data }, { amountUsd: 100 }));
console.log("500,000 USDC approve, declared $100:");
console.log("  ->", r.status, r.body.decision, r.body.code);
console.log("  riskScore:", r.body.riskScore, "signals:", (r.body.riskSignals??[]).map((s:any)=>`${s.id}(${s.weight})`).join(", "));
console.log("  allowanceUsd computed? findings mention far-excess?:", JSON.stringify(r.body.findings?.filter((f:any)=>f.severity!=="INFO")));
