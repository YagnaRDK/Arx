/**
 * Privy server wallets as an alternative signing boundary.
 *
 * Arx's position on this is specific, and the code is written to make it
 * unmissable: a Privy wallet is a *remote custodial key*, not a hardware
 * signing boundary. It is a legitimate signer for an agent with a small budget
 * on a testnet, and it is not equivalent to a Ledger device, because the key
 * lives in someone else's TEE rather than behind a physical confirmation. So
 * `SignerStatus.emulated` is reported `true` — there is no human at a screen —
 * while `signatureType` is `"REAL"`, because the secp256k1 signature genuinely
 * is one and Arx verifies it by recovering the signer itself.
 *
 * The Privy control this uses is a **policy**: `buildArxMirrorPolicy` turns the
 * Arx capability's recipient/contract allowlist into a Privy `eth_sendTransaction`
 * allowlist, so the same restriction is enforced twice — once by Arx before the
 * request is made, and once by Privy inside its own signing service. That is
 * defence in depth rather than duplication: if Arx is bypassed, Privy still
 * refuses; if Privy's policy is loosened, Arx still refuses.
 *
 * `src/signer/` belongs to another agent. This module only exports a factory
 * and an adapter object shaped to `SignerAdapter`; nothing in `src/signer/` is
 * edited here.
 */

import { parseTransaction, recoverTransactionAddress } from "viem";

import { env } from "../../config/env";
import type { NormalizedTransaction } from "../../types/transaction";
import type {
  SignerAdapter,
  SignerResult,
  SignerStatus,
} from "../../signer/signer-types";
import { ArxError } from "../../core/errors";
import type { PolicySet } from "../../types/policy-sets";
import {
  PrivyClient,
  type PrivyEthereumTransaction,
  type PrivyPolicyRule,
} from "./privy-client";
import type { TypedDataRequest, TypedDataSigner } from "../x402/client";
import type { EvmTransaction } from "../../types/transaction";

export type PrivySignerOptions = {
  appId?: string;
  appSecret?: string;
  walletId?: string;
  /** Expected wallet address. When set, a mismatch is a hard failure. */
  expectedAddress?: string;
  baseUrl?: string;
};

export class PrivySignerAdapter implements SignerAdapter {
  readonly name = "privy-server-wallet";
  /** A real secp256k1 signature — produced remotely, not by local hardware. */
  readonly signatureType = "REAL" as const;

  private readonly client: PrivyClient;
  private readonly walletId: string;
  private readonly expectedAddress: string;
  private cachedAddress: string | null = null;

  constructor(options: PrivySignerOptions = {}) {
    this.client = new PrivyClient({
      appId: options.appId ?? env.privyAppId,
      appSecret: options.appSecret ?? env.privyAppSecret,
      ...(options.baseUrl === undefined ? {} : { baseUrl: options.baseUrl }),
    });
    this.walletId = options.walletId ?? env.privyWalletId;
    this.expectedAddress = (options.expectedAddress ?? "").toLowerCase();
  }

  isReady(): boolean {
    return this.client.configured && this.walletId.length > 0;
  }

  readinessDetail(): string {
    if (!this.client.configured) {
      return "PRIVY_APP_ID and PRIVY_APP_SECRET are required";
    }

    if (this.walletId.length === 0) {
      return "PRIVY_WALLET_ID is required";
    }

    return `Privy server wallet ${this.walletId}. NOTE: privy-authorization-signature is not implemented, so a wallet with an owner/authorization key will be refused by Privy with 401/403.`;
  }

  async getAddress(): Promise<string> {
    if (this.cachedAddress !== null) {
      return this.cachedAddress;
    }

    if (!this.isReady()) {
      throw new ArxError("SIGNER_UNAVAILABLE", this.readinessDetail());
    }

    const outcome = await this.client.getWallet(this.walletId);

    if (!outcome.ok) {
      throw new ArxError(
        "SIGNER_UNAVAILABLE",
        `Could not read Privy wallet ${this.walletId}: ${outcome.failure.message}`,
      );
    }

    const address = outcome.value.address;

    if (typeof address !== "string" || address.length === 0) {
      throw new ArxError(
        "SIGNER_UNAVAILABLE",
        `Privy wallet ${this.walletId} returned no address`,
      );
    }

    if (
      this.expectedAddress.length > 0 &&
      address.toLowerCase() !== this.expectedAddress
    ) {
      // A signer that is not the address Arx thinks it is means every spend
      // ceiling and allowlist was reasoned about for the wrong account.
      throw new ArxError(
        "SIGNER_ADDRESS_MISMATCH",
        `Privy wallet address ${address} does not match the expected ${this.expectedAddress}`,
      );
    }

    this.cachedAddress = address;

    return address;
  }

  async getStatus(): Promise<SignerStatus> {
    const base = {
      adapter: this.name,
      signatureType: this.signatureType,
      // No physical confirmation surface. Reported honestly so a Privy
      // signature is never presented as device-confirmed.
      emulated: true,
    };

    if (!this.isReady()) {
      return { ...base, available: false, detail: this.readinessDetail() };
    }

    try {
      const address = await this.getAddress();

      return {
        ...base,
        available: true,
        address,
        detail:
          "Privy server wallet: remote custodial key in Privy's TEE, gated by a Privy policy. Not a hardware signing boundary.",
      };
    } catch (error) {
      return {
        ...base,
        available: false,
        detail: error instanceof Error ? error.message : String(error),
      };
    }
  }

  async signTransaction(
    transaction: NormalizedTransaction,
  ): Promise<SignerResult> {
    if (!this.isReady()) {
      throw new ArxError("SIGNER_UNAVAILABLE", this.readinessDetail());
    }

    const tx = transaction.transaction;

    if (tx.to === undefined) {
      // Contract creation through a remote custodial wallet is not something
      // this adapter is set up to bound, so it refuses rather than guessing.
      throw new ArxError(
        "CONTRACT_CREATION_NOT_ALLOWED",
        "The Privy adapter does not sign contract-creation transactions",
      );
    }

    const address = await this.getAddress();

    const request: PrivyEthereumTransaction = {
      to: tx.to,
      value: tx.value,
      chain_id: tx.chainId,
      data: tx.data,
      gas_limit: tx.gasLimit,
      nonce: tx.nonce,
      ...(tx.type === "legacy"
        ? { type: 0, gas_price: tx.maxFeePerGas }
        : {
            type: 2,
            max_fee_per_gas: tx.maxFeePerGas,
            max_priority_fee_per_gas: tx.maxPriorityFeePerGas,
          }),
    };

    const outcome = await this.client.signTransaction(this.walletId, request);

    if (!outcome.ok) {
      throw new ArxError(
        "SIGNING_FAILED",
        `Privy signing failed: ${outcome.failure.message}`,
      );
    }

    if (outcome.status >= 400) {
      // Privy's own policy refusing is a policy denial, not an outage. Surfaced
      // with a policy code so the audit log shows which layer refused.
      throw new ArxError(
        "TRANSACTION_NOT_ALLOWED",
        `Privy refused to sign (HTTP ${outcome.status}); a Privy policy likely denied this transaction`,
        { details: outcome.value },
      );
    }

    const signed = outcome.value.data?.signed_transaction;

    if (typeof signed !== "string" || !signed.startsWith("0x")) {
      throw new ArxError(
        "SIGNING_FAILED",
        "Privy returned no signed_transaction",
      );
    }

    const parsed = parseTransaction(signed as `0x${string}`);

    if (parsed.r === undefined || parsed.s === undefined) {
      throw new ArxError(
        "SIGNING_FAILED",
        "Privy's signed transaction carries no signature components",
      );
    }

    // Invariant 3: the transaction signed must be the transaction approved.
    // Privy is a remote service; nothing stops it (or a man in the middle)
    // returning RLP for a different transaction. So the returned bytes are
    // decoded and every field compared against what Arx normalized, and the
    // signature is recovered and checked against the wallet address. An HTTP
    // 200 is not evidence that the right thing was signed.
    const mismatches = compareTransaction(parsed, tx);

    if (mismatches.length > 0) {
      throw new ArxError(
        "TRANSACTION_HASH_MISMATCH",
        `Privy signed a different transaction than Arx approved: ${mismatches.join(", ")}`,
        { details: { mismatches } },
      );
    }

    let recovered = "";

    try {
      recovered = await recoverTransactionAddress({
        serializedTransaction: signed as Parameters<
          typeof recoverTransactionAddress
        >[0]["serializedTransaction"],
      });
    } catch (error) {
      throw new ArxError(
        "SIGNATURE_VERIFICATION_FAILED",
        `Could not recover the signer from Privy's signature: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }

    if (recovered.toLowerCase() !== address.toLowerCase()) {
      throw new ArxError(
        "SIGNER_ADDRESS_MISMATCH",
        `Privy's signature recovers to ${recovered || "nothing"}, not the wallet address ${address}`,
      );
    }

    const yParity =
      parsed.yParity === 0 || parsed.yParity === 1 ? parsed.yParity : undefined;

    return {
      signedTransaction: signed,
      signerAddress: address,
      transactionId: transaction.transactionId,
      signatureType: "REAL",
      r: parsed.r,
      s: parsed.s,
      v:
        parsed.v === undefined
          ? `0x${(yParity ?? 0).toString(16)}`
          : `0x${parsed.v.toString(16)}`,
      ...(yParity === undefined ? {} : { yParity }),
      // Both halves held: the decoded fields match the approved transaction and
      // the recovered signer is the wallet. Either failing threw above.
      verified: true,
      adapter: this.name,
    };
  }
}

/**
 * A Privy typed-data signer, so the x402 payer can be the same Privy wallet the
 * agent signs transactions with. This is what makes the paid-API demo end to
 * end without a local private key anywhere in the process.
 */
export function createPrivyTypedDataSigner(
  options: PrivySignerOptions & { address: string },
): TypedDataSigner {
  const client = new PrivyClient({
    appId: options.appId ?? env.privyAppId,
    appSecret: options.appSecret ?? env.privyAppSecret,
    ...(options.baseUrl === undefined ? {} : { baseUrl: options.baseUrl }),
  });
  const walletId = options.walletId ?? env.privyWalletId;

  return {
    name: "privy-server-wallet",
    address: options.address,

    async signTypedData(request: TypedDataRequest): Promise<string> {
      if (!client.configured || walletId.length === 0) {
        throw new ArxError(
          "SIGNER_UNAVAILABLE",
          "Privy is not configured (PRIVY_APP_ID, PRIVY_APP_SECRET, PRIVY_WALLET_ID)",
        );
      }

      const outcome = await client.signTypedData(walletId, {
        domain: request.domain as unknown as Record<string, unknown>,
        types: request.types as unknown as Record<string, unknown>,
        primary_type: request.primaryType,
        message: request.message as unknown as Record<string, unknown>,
      });

      if (!outcome.ok) {
        throw new ArxError(
          "SIGNING_FAILED",
          `Privy typed-data signing failed: ${outcome.failure.message}`,
        );
      }

      if (outcome.status >= 400) {
        throw new ArxError(
          "TRANSACTION_NOT_ALLOWED",
          `Privy refused to sign the payment authorization (HTTP ${outcome.status})`,
          { details: outcome.value },
        );
      }

      const signature = outcome.value.data?.signature;

      if (typeof signature !== "string" || !signature.startsWith("0x")) {
        throw new ArxError("SIGNING_FAILED", "Privy returned no signature");
      }

      return signature;
    },
  };
}

/**
 * Mirrors an Arx capability's allowlists into a Privy policy.
 *
 * Only `ALLOWLIST` mode produces a policy: an Arx policy set in `ANY` mode has
 * nothing to mirror, and emitting a Privy policy with no conditions would read
 * as "restricted" while permitting everything. Returning `null` and saying so
 * is the honest outcome.
 */
export function buildArxMirrorPolicy(input: {
  capabilityId: string;
  recipients: PolicySet;
  contracts: PolicySet;
}): {
  name: string;
  chain_type: string;
  rules: PrivyPolicyRule[];
} | null {
  const allowed = new Set<string>();

  for (const set of [input.recipients, input.contracts]) {
    if (set.mode !== "ALLOWLIST") {
      return null;
    }

    for (const entry of set.allow) {
      // ENS names cannot be expressed as a Privy condition value; they are
      // resolved by Arx before the transaction exists. Only hex addresses are
      // mirrored, and a set of only names produces no policy rather than an
      // empty allowlist that Privy would read as permitting nothing useful.
      if (/^0x[a-fA-F0-9]{40}$/.test(entry)) {
        allowed.add(entry.toLowerCase());
      }
    }
  }

  if (allowed.size === 0) {
    return null;
  }

  return {
    name: `arx-capability-${input.capabilityId}`.slice(0, 64),
    chain_type: "ethereum",
    rules: [...allowed].map((address, index) => ({
      name: `arx-allow-${index}`,
      method: "eth_sendTransaction",
      action: "ALLOW" as const,
      conditions: [
        {
          field_source: "ethereum_transaction",
          field: "to",
          operator: "eq",
          value: address,
        },
      ],
    })),
  };
}

/**
 * Field-by-field comparison of the transaction a remote signer returned against
 * the one Arx approved. Anything that differs is named, so the audit record
 * says exactly which field was substituted.
 */
function compareTransaction(
  signed: {
    chainId?: number;
    to?: string | null;
    value?: bigint;
    data?: string;
    gas?: bigint;
    nonce?: number;
    gasPrice?: bigint;
    maxFeePerGas?: bigint;
    maxPriorityFeePerGas?: bigint;
  },
  approved: EvmTransaction,
): string[] {
  const mismatches: string[] = [];

  const check = (
    field: string,
    actual: string | number | bigint | undefined,
    expected: string | number | bigint,
  ): void => {
    if (actual === undefined) {
      mismatches.push(`${field} missing`);

      return;
    }

    const left =
      typeof actual === "string" ? actual.toLowerCase() : actual.toString();
    const right =
      typeof expected === "string"
        ? expected.toLowerCase()
        : expected.toString();

    if (left !== right) {
      mismatches.push(`${field}: signed ${left}, approved ${right}`);
    }
  };

  check("chainId", signed.chainId, approved.chainId);
  check("to", signed.to ?? undefined, approved.to ?? "");
  check("value", signed.value, BigInt(approved.value));
  check("data", signed.data ?? "0x", approved.data);
  check("gas", signed.gas, BigInt(approved.gasLimit));
  check("nonce", signed.nonce, approved.nonce);

  if (approved.type === "legacy") {
    check("gasPrice", signed.gasPrice, BigInt(approved.maxFeePerGas));
  } else {
    check("maxFeePerGas", signed.maxFeePerGas, BigInt(approved.maxFeePerGas));
    check(
      "maxPriorityFeePerGas",
      signed.maxPriorityFeePerGas,
      BigInt(approved.maxPriorityFeePerGas),
    );
  }

  return mismatches;
}
