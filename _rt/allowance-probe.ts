import { checkValueBinding } from "../src/firewall/checks/value-binding";
import { decodeCalldata } from "../src/firewall/checks/decode-calldata";
import { createPriceOracle } from "../src/oracle/price-oracle";
import { encodeFunctionData } from "viem";

const USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
const ROUTER = "0x3333333333333333333333333333333333333333";
const abi = [{ name: "approve", type: "function", inputs: [{type:"address"},{type:"uint256"}], outputs: [] }] as const;
const oracle = createPriceOracle({ mode: "static" });

for (const amount of [2n**128n-1n, 10n**30n, 10n**12n]) {
  const data = encodeFunctionData({ abi, functionName: "approve", args: [ROUTER, amount] });
  const tx: any = { chainId: 1, to: USDC, value: "0", data, gasLimit: "60000", maxFeePerGas: "20000000000", maxPriorityFeePerGas: "1000000000", nonce: 0, type: "eip1559" };
  const ctx: any = {
    transaction: { transaction: tx, transactionId: "x", createdAt: 1 },
    tx, capability: { valueToleranceBps: 500, maxAmountUsd: 1000 } as any,
    intent: { amountUsd: 100 } as any,
    decodedCall: decodeCalldata({ to: USDC, data, value: "0" }),
    now: 1,
  };
  const r = await checkValueBinding(ctx, { oracle });
  console.log(`amount=${amount}  allowanceUsd=${r.allowanceUsd}  valuePriced=${r.valuePriced} pricingStatus=${r.pricingStatus}`);
}
