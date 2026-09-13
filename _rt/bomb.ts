import { decodeCalldata, flattenCall } from "../src/firewall/checks/decode-calldata";
import { encodeFunctionData } from "viem";

const mcAbi = [{ name: "multicall", type: "function", inputs: [{type:"bytes[]"}], outputs: [] }] as const;
function mc(inner: `0x${string}`[]): `0x${string}` {
  return encodeFunctionData({ abi: mcAbi, functionName: "multicall", args: [inner] });
}
// Build a fanout-heavy tree within 1MB. leaf = short unknown calldata.
const leaf = "0x12345678" as `0x${string}`;
// level 1: 64 leaves
let lvl: `0x${string}` = mc(Array(64).fill(leaf));
// wrap: each level fan 64 would explode size; instead measure depth-limited fanout
// Build the biggest tree that fits under ~950KB.
function sizeOf(h: string) { return (h.length - 2) / 2; }
let best = lvl;
for (let d = 0; d < 6; d++) {
  const cand = mc(Array(20).fill(best));
  if (sizeOf(cand) > 950_000) break;
  best = cand;
}
console.log("calldata bytes:", sizeOf(best));
const t0 = performance.now();
const decoded = decodeCalldata({ to: "0x2222222222222222222222222222222222222222", data: best });
const t1 = performance.now();
const flat = flattenCall(decoded);
const t2 = performance.now();
console.log("nodes:", flat.length, "decode ms:", (t1-t0).toFixed(1), "flatten ms:", (t2-t1).toFixed(1), "topDecoded:", decoded.decoded);
