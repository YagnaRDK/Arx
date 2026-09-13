import { get } from "./lib";
console.log(JSON.stringify(await get("/oracle/price?asset=ETH&chainId=1")));
