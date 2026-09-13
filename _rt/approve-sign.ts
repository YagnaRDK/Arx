import { post, cap, intent, ADMIN } from "./lib";
import { encodeFunctionData } from "viem";
const USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
const ROUTER = "0x3333333333333333333333333333333333333333";
const c = cap({
  contracts: { mode: "ALLOWLIST", allow: [USDC], deny: [] },
  recipients: { mode: "ALLOWLIST", allow: [ROUTER], deny: [] },
  methods: { mode: "ALLOWLIST", allow: ["approve(address,uint256)"], deny: [] },
  limits: { maxValueWei: "0", maxGasLimit: "500000", maxFeePerGasWei: "500000000000", maxAmountUsdPerWindow: 2000, windowSeconds: 86400, maxTxPerWindow: 5 },
  humanApproval: { requiredAboveUsd: 500, requiredForUnknownRecipient: true, requiredForMethods: [], requiredAboveRiskScore: 60, alwaysRequired: false },
  maxRiskScore: 80, maxAmountUsd: 1000,
});
await post("/capabilities", c, ADMIN);
const abi = [{ name: "approve", type: "function", inputs: [{type:"address"},{type:"uint256"}], outputs: [] }] as const;
const data = encodeFunctionData({ abi, functionName: "approve", args: [ROUTER, 2n**128n-1n] });
const i = intent(c.capabilityId, { to: USDC, value: "0", data }, { amountUsd: 100, nonce: 1 });
const a = await post("/approvals", i);
console.log("approval:", a.status, a.body.status, a.body.approval?.approvalId, "valueUsd=", a.body.valueUsd);
const s = await post("/sign", { approvalId: a.body.approval.approvalId, transaction: i.transaction });
console.log("sign:", s.status, s.body.status, s.body.signatureType, "verified=", s.body.signatureVerified);
console.log("signedTx prefix:", String(s.body.signedTransaction).slice(0, 40));
