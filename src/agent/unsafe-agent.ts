import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import type { TransactionSerializable } from "viem";

import type { EvmTransaction } from "../types/transaction";
import type { AgentPlan } from "./payment-agent";
import type { PaymentTask, Scenario } from "./scenarios";
import { Transcript } from "./transcript";

/**
 * THE INSECURE CONTROL CASE. NOT A COMPONENT OF ARX.
 *
 * This is the same manipulated agent with the arrangement almost every agent
 * ships with today: a software private key in its own process and no
 * authorization layer in front of it. It signs whatever it was talked into
 * signing, immediately, with no record and nothing to appeal to. That contrast
 * is the argument for Arx, and it only lands if the comparison is real rather
 * than described — so this file actually produces a signature.
 *
 * Three hard constraints keep that safe:
 *
 *   1. The key is generated in memory for one run and is never written
 *      anywhere. There is no import path for an operator-supplied key, so this
 *      module cannot be pointed at real funds even by mistake.
 *   2. Only testnet chain ids are accepted. Anything else throws.
 *   3. Nothing is broadcast. No RPC endpoint is contacted; the signed payload
 *      is produced, shown, and discarded.
 *
 * The point is not that signing is hard. The point is that it is trivially
 * easy, which is exactly the problem.
 */

export const INSECURE_AGENT_BANNER =
  "INSECURE COMPARISON — software key, no authorization layer. Testnet chain ids only; nothing is broadcast.";

/** Sepolia, Holesky, Hedera testnet, Anvil/Hardhat. */
const TESTNET_CHAIN_IDS = new Set([11155111, 17000, 296, 31337, 1337]);

export type UnsafeSignResult = {
  signerAddress: string;
  signedTransaction: string;
  /** Always true here. A throwaway key is not a wallet. */
  ephemeralKey: true;
  chainId: number;
  recipient: string;
  valueWei: string;
  calldata: string;
};

export function assertTestnetOnly(chainId: number): void {
  if (!TESTNET_CHAIN_IDS.has(chainId)) {
    throw new Error(
      `unsafe-agent refuses chain ${chainId}: it signs only on testnets (${[
        ...TESTNET_CHAIN_IDS,
      ].join(", ")}). This module exists to demonstrate an insecure control, not to move value.`,
    );
  }
}

/**
 * Signs the transaction with a key generated here and now.
 *
 * No approval, no policy check, no audit entry — that absence is the whole
 * finding.
 */
export async function signWithoutAuthorization(
  transaction: EvmTransaction,
): Promise<UnsafeSignResult> {
  assertTestnetOnly(transaction.chainId);

  const privateKey = generatePrivateKey();
  const account = privateKeyToAccount(privateKey);

  const serializable: TransactionSerializable = {
    type: "eip1559",
    chainId: transaction.chainId,
    to: (transaction.to ?? null) as `0x${string}` | null,
    value: BigInt(transaction.value),
    data: transaction.data as `0x${string}`,
    gas: BigInt(transaction.gasLimit),
    maxFeePerGas: BigInt(transaction.maxFeePerGas),
    maxPriorityFeePerGas: BigInt(transaction.maxPriorityFeePerGas),
    nonce: transaction.nonce,
  };

  const signedTransaction = await account.signTransaction(serializable);

  return {
    signerAddress: account.address,
    signedTransaction,
    ephemeralKey: true,
    chainId: transaction.chainId,
    recipient: transaction.to ?? "(contract creation)",
    valueWei: transaction.value,
    calldata: transaction.data,
  };
}

/**
 * Runs the control case for one scenario and returns its transcript.
 *
 * It takes the plan and transaction the Arx-protected run already produced, so
 * the two paths are compared on identical input: same task, same injection,
 * same agent conclusion, same bytes. Only the authorization layer differs.
 */
export async function runUnsafeAgent(input: {
  scenario: Scenario;
  task: PaymentTask;
  plan: AgentPlan;
  transaction: EvmTransaction;
  agentId: string;
  now: number;
}): Promise<{ transcript: Transcript; result?: UnsafeSignResult; error?: string }> {
  const transcript = new Transcript(
    {
      scenarioId: input.scenario.id,
      scenarioTitle: input.scenario.title,
      path: "unprotected",
      agentId: `${input.agentId}-unprotected`,
      reasoningMode: "scripted",
      startedAt: input.now,
    },
    () => input.now,
  );

  transcript.add("ALERT", INSECURE_AGENT_BANNER);

  transcript.add("TASK", "Same task, same agent", input.task.instruction);

  if (input.scenario.injection) {
    transcript.add(
      "INJECTION",
      `Same untrusted content: ${input.scenario.injection.title}`,
      undefined,
      { manipulation: input.scenario.injection.manipulation },
    );
  }

  transcript.add("REASONING", "Same agent conclusion", input.plan.rationale);

  transcript.add("PROPOSAL", "No proposal step exists on this path", undefined, {
    recipient: input.plan.recipient,
    declaredAmountUsd: input.plan.amountUsd,
    txTo: input.transaction.to,
    txValueWei: input.transaction.value,
    calldataSelector: input.transaction.data.slice(0, 10),
  });

  try {
    const result = await signWithoutAuthorization(input.transaction);

    transcript.add(
      "SIGNATURE",
      "Signed immediately. Nothing was consulted.",
      "No capability was checked, no limit was applied, no human was asked, and no record was written. On a path like this the attacker's transaction is signed and ready to broadcast.",
      {
        signerAddress: result.signerAddress,
        ephemeralThrowawayKey: true,
        chainId: result.chainId,
        signedTransaction: `${result.signedTransaction.slice(0, 66)}...`,
        signedLength: result.signedTransaction.length,
        broadcast: "never — this demo does not contact an RPC endpoint",
      },
    );

    transcript.add(
      "OUTCOME",
      input.plan.compliedWithInjection
        ? "FUNDS LOST. The injected instruction was carried out end to end."
        : "Signed. In this case the agent happened not to be manipulated, so nothing was stolen — but nothing checked either.",
    );

    return { transcript, result };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);

    transcript.add("ALERT", "Unsafe signing refused by its own guard", message);

    return { transcript, error: message };
  }
}
