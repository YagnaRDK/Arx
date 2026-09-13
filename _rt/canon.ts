import { canonicalize } from "../src/crypto/canonical";
import { hashCanonical } from "../src/crypto/hash";

// 1. prototype pollution keys
const a = JSON.parse('{"a":1,"__proto__":{"x":9},"b":2}');
console.log("has __proto__ own?:", Object.getOwnPropertyNames(a));
try { console.log("canon proto:", canonicalize(a)); } catch(e:any){ console.log("canon proto threw:", e.message); }

// 2. duplicate keys - JSON.parse keeps last
console.log("dup:", canonicalize(JSON.parse('{"amount":"1","amount":"1000"}')));

// 3. unicode normalization collision
const s1 = "café";       // composed
const s2 = "café"; // decomposed
console.log("nfc vs nfd equal canon?:", canonicalize(s1) === canonicalize(s2), JSON.stringify(s1), JSON.stringify(s2));

// 4. number precision - can two different amountUsd canonicalize identically?
console.log("0.1+0.2:", canonicalize(0.1+0.2), "vs", canonicalize(0.3));
console.log("1e21:", canonicalize(1e21));
console.log("negzero:", canonicalize(-0));

// 5. constructor key
const b = JSON.parse('{"constructor":{"y":1},"z":3}');
console.log("constructor canon:", canonicalize(b));
