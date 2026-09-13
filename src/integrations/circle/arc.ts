/**
 * Circle Arc chain configuration and agentic USDC payment construction.
 *
 * Arc is the rail; Arx is the decision logic on top of it. The point of this
 * module is that an agentic USDC payment reduces to a transaction whose
 * recipient and amount are both extractable from the calldata, which means the
 * firewall can check them without trusting anything the agent said. So
 * `buildUsdcTransfer` returns the calldata *and* the decoded facts, and
 * `decodeUsdcTransfer` exists so the firewall path can recover the recipient
 * and amount from bytes it was handed by someone else.
 *
 * Verified 2026-09-12 against Circle's own published skill definition,
 * https://github.com/circlefin/skills/blob/master/plugins/circle/skills/use-arc/SKILL.md :
 *   - "Chain ID `5042002` (hex: `0x4CEF52`)"
 *   - RPC `https://rpc.testnet.arc.network`
 *   - explorer `https://testnet.arcscan.app`
 *   - USDC `0x3600000000000000000000000000000000000000`, 6 decimals, ERC-20
 *   - EURC `0x89B50855Aa3bE2F677cD6303Cec089B5F319D72a`, 6 decimals
 *   - and explicitly: "Arc is currently in testnet", "NEVER target mainnet --
 *     Arc is testnet only."
 *
 * Because that last line is Circle's own, there is **no Arc mainnet entry
 * here**. Inventing a mainnet chain id for a network its operator says does not
 * exist yet is exactly the failure mode this file is written to avoid.
 *
 * Live-verified too, on 2026-09-12 against https://rpc.testnet.arc.network :
 * `eth_chainId` returned `0x4cef52` (5042002), and `eth_call` on
 * `0x3600000000000000000000000000000000000000` returned `symbol() = "USDC"`
 * and `decimals() = 6`. `ArcChainAdapter.probe()` performs exactly those
 * checks on demand, so an operator can re-confirm rather than trust a comment.
 */

import {
  decodeFunctionData,
  encodeFunctionData,
  isAddress,
  parseAbi,
} from "viem";

import { env } from "../../config/env";
import { requestJson } from "../http";

export const ARC_TESTNET = {
  name: "Arc Testnet",
  chainId: 5_042_002,
  chainIdHex: "0x4cef52",
  defaultRpcUrl: "https://rpc.testnet.arc.network",
  explorerUrl: "https://testnet.arcscan.app",
  /** USDC is the native gas asset on Arc, exposed at a system address. */
  usdc: {
    address: "0x3600000000000000000000000000000000000000",
    symbol: "USDC",
    decimals: 6,
  },
  eurc: {
    address: "0x89B50855Aa3bE2F677cD6303Cec089B5F319D72a",
    symbol: "EURC",
    decimals: 6,
  },
  faucet: "https://faucet.circle.com",
} as const;

const ERC20_ABI = parseAbi([
  "function transfer(address to, uint256 amount) returns (bool)",
  "function decimals() view returns (uint8)",
  "function symbol() view returns (string)",
]);

/** `transfer(address,uint256)`. */
export const ERC20_TRANSFER_SELECTOR = "0xa9059cbb";

export type UsdcTransfer = {
  chainId: number;
  /** The USDC contract. What the transaction's `to` must be. */
  to: string;
  data: string;
  value: string;
  /** Decoded from the calldata, not taken from the caller. */
  recipient: string;
  amountAtomic: string;
  amountDecimal: string;
  asset: { address: string; symbol: string; decimals: number };
  selector: string;
};

export type ArcAdapterOptions = {
  rpcUrl?: string;
  timeoutMs?: number;
};

export class ArcChainAdapter {
  readonly name = "circle-arc";
  readonly chainId = ARC_TESTNET.chainId;

  private readonly rpcUrl: string;
  private readonly timeoutMs: number;

  constructor(options: ArcAdapterOptions = {}) {
    this.rpcUrl = options.rpcUrl ?? env.rpcUrls.arc;
    this.timeoutMs = options.timeoutMs ?? 5_000;
  }

  /** Calldata construction needs no RPC; only `probe` does. */
  isReady(): boolean {
    return true;
  }

  hasRpc(): boolean {
    return this.rpcUrl.length > 0;
  }

  readinessDetail(): string {
    return this.hasRpc()
      ? `Arc testnet (chain ${this.chainId}) via ${this.rpcUrl}; documentation-verified addresses, call probe() to confirm live`
      : `Arc testnet (chain ${this.chainId}) calldata construction only; set RPC_URL_ARC to ${ARC_TESTNET.defaultRpcUrl} to verify against the live chain`;
  }

  /**
   * Confirms the configured RPC really is Arc testnet and that the documented
   * USDC address really answers as USDC with 6 decimals. Never called
   * implicitly: a security product should verify its constants on demand and
   * report the result, not assert them.
   */
  async probe(): Promise<
    | {
        status: "OK";
        chainId: number;
        chainIdMatches: boolean;
        usdcSymbol: string | null;
        usdcDecimals: number | null;
      }
    | { status: "UNAVAILABLE"; reason: string }
  > {
    if (!this.hasRpc()) {
      return {
        status: "UNAVAILABLE",
        reason: "RPC_URL_ARC is not set",
      };
    }

    const chainIdCall = await this.rpc("eth_chainId", []);

    if (chainIdCall === null) {
      return {
        status: "UNAVAILABLE",
        reason: `Arc RPC at ${this.rpcUrl} did not answer eth_chainId`,
      };
    }

    const chainId = Number(chainIdCall);
    const symbolRaw = await this.rpc("eth_call", [
      { to: ARC_TESTNET.usdc.address, data: "0x95d89b41" },
      "latest",
    ]);
    const decimalsRaw = await this.rpc("eth_call", [
      { to: ARC_TESTNET.usdc.address, data: "0x313ce567" },
      "latest",
    ]);

    return {
      status: "OK",
      chainId,
      chainIdMatches: chainId === ARC_TESTNET.chainId,
      usdcSymbol: symbolRaw === null ? null : decodeAbiString(symbolRaw),
      usdcDecimals:
        decimalsRaw === null || decimalsRaw === "0x"
          ? null
          : Number(BigInt(decimalsRaw)),
    };
  }

  /**
   * Builds a USDC transfer and reports back what the bytes actually say.
   *
   * The returned `recipient` and `amountAtomic` are decoded from the calldata
   * that was just built, not echoed from the arguments. That sounds redundant
   * until the encoder and the policy check disagree — at which point the whole
   * firewall is checking a claim instead of a fact.
   */
  buildUsdcTransfer(input: {
    recipient: string;
    /** Decimal USDC, e.g. "25.50". */
    amount: string;
    asset?: "USDC" | "EURC";
  }): UsdcTransfer {
    if (!isAddress(input.recipient)) {
      throw new Error(`"${input.recipient}" is not an EVM address`);
    }

    const asset =
      input.asset === "EURC" ? ARC_TESTNET.eurc : ARC_TESTNET.usdc;
    const amountAtomic = toAtomic(input.amount, asset.decimals);

    const data = encodeFunctionData({
      abi: ERC20_ABI,
      functionName: "transfer",
      args: [input.recipient as `0x${string}`, BigInt(amountAtomic)],
    });

    const decoded = decodeUsdcTransfer(data);

    if (decoded === null) {
      throw new Error("Constructed calldata did not decode as an ERC-20 transfer");
    }

    return {
      chainId: ARC_TESTNET.chainId,
      to: asset.address,
      data,
      // A token transfer moves no native value. A non-zero value here would be
      // a second, unaccounted-for payment riding along with the first.
      value: "0",
      recipient: decoded.recipient,
      amountAtomic: decoded.amountAtomic,
      amountDecimal: fromAtomic(decoded.amountAtomic, asset.decimals),
      asset: { ...asset },
      selector: ERC20_TRANSFER_SELECTOR,
    };
  }

  private async rpc(method: string, params: unknown[]): Promise<string | null> {
    const outcome = await requestJson<{ result?: string; error?: unknown }>({
      url: this.rpcUrl,
      method: "POST",
      body: { jsonrpc: "2.0", id: 1, method, params },
      timeoutMs: this.timeoutMs,
    });

    if (!outcome.ok || typeof outcome.value.result !== "string") {
      return null;
    }

    return outcome.value.result;
  }
}

/**
 * Recovers the recipient and amount from ERC-20 transfer calldata.
 *
 * This is the function the firewall wants: it turns the agent's claim
 * ("I am paying 25 USDC to the vendor") into something checkable against the
 * only authoritative source, the bytes that will execute.
 */
export function decodeUsdcTransfer(
  data: string,
): { recipient: string; amountAtomic: string } | null {
  if (!data.toLowerCase().startsWith(ERC20_TRANSFER_SELECTOR)) {
    return null;
  }

  try {
    const decoded = decodeFunctionData({
      abi: ERC20_ABI,
      data: data as `0x${string}`,
    });

    if (decoded.functionName !== "transfer") {
      return null;
    }

    const [recipient, amount] = decoded.args;

    return {
      recipient: (recipient as string).toLowerCase(),
      amountAtomic: (amount as bigint).toString(),
    };
  } catch {
    return null;
  }
}

export function toAtomic(amount: string, decimals: number): string {
  if (!/^\d+(\.\d+)?$/.test(amount)) {
    throw new Error(`"${amount}" is not a non-negative decimal amount`);
  }

  const [whole = "0", fraction = ""] = amount.split(".");

  if (fraction.length > decimals) {
    // Silently truncating would move a different amount than the operator
    // wrote down.
    throw new Error(
      `"${amount}" has more than ${decimals} decimal places and cannot be represented exactly`,
    );
  }

  const padded = (fraction + "0".repeat(decimals)).slice(0, decimals);

  return BigInt(`${whole}${padded}`).toString();
}

export function fromAtomic(amount: string, decimals: number): string {
  const padded = amount.padStart(decimals + 1, "0");
  const whole = padded.slice(0, padded.length - decimals);
  const fraction = padded.slice(padded.length - decimals).replace(/0+$/, "");

  return fraction.length === 0 ? whole : `${whole}.${fraction}`;
}

function decodeAbiString(hex: string): string | null {
  if (hex === "0x") {
    return null;
  }

  try {
    const body = hex.slice(2);
    const length = Number(BigInt(`0x${body.slice(64, 128)}`));
    const bytes = body.slice(128, 128 + length * 2);

    return Buffer.from(bytes, "hex").toString("utf8");
  } catch {
    return null;
  }
}
