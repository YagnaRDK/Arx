import { decodeCalldata } from "../src/firewall/checks/decode-calldata";
import { encodeFunctionData, toFunctionSelector } from "viem";

const abi = [{ name: "transfer", type: "function", inputs: [{type:"address"},{type:"uint256"}], outputs: [] }] as const;
const REAL = "0x1111111111111111111111111111111111111111";
const EVIL = "0x000000000000000000000000000000000000dEaD";

// 1. Normal transfer + trailing bytes
const base = encodeFunctionData({ abi, functionName: "transfer", args: [REAL, 5n] });
const trailing = base + "deadbeef".repeat(8);
console.log("trailing bytes:", JSON.stringify(decodeCalldata({ to: "0xtok".padEnd(42,"0"), data: trailing }).recipients ?? "n/a"));
let d = decodeCalldata({ to: "0x2222222222222222222222222222222222222222", data: trailing });
console.log("  kind=", d.kind, "decoded=", d.decoded, "recipients=", d.recipients, "amount=", d.amount);

// 2. Truncated payload (short by bytes)
const short = base.slice(0, base.length - 8);
d = decodeCalldata({ to: "0x2222222222222222222222222222222222222222", data: short });
console.log("truncated: kind=", d.kind, "decoded=", d.decoded, "note=", d.note);

// 3. transfer selector but with dynamic-type args (address, bytes) — signature collision attempt
// find a function whose selector collides? Just test that arg-count mismatch is caught.
const sel = toFunctionSelector("transfer(address,uint256)");
// craft: selector + a single 32-byte word (missing 2nd arg)
const oneword = sel + "00".repeat(31) + "01";
d = decodeCalldata({ to: "0x2222222222222222222222222222222222222222", data: oneword });
console.log("one-word transfer: kind=", d.kind, "decoded=", d.decoded, "recipients=", d.recipients, "note=", d.note);

// 4. address with dirty high bytes (non-zero padding above 20 bytes)
const dirty = sel + "ff".repeat(12) + REAL.slice(2) + "00".repeat(31) + "05";
d = decodeCalldata({ to: "0x2222222222222222222222222222222222222222", data: dirty });
console.log("dirty-padded addr: kind=", d.kind, "decoded=", d.decoded, "recipients=", d.recipients);
