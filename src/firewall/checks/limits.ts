import {
  block,
  info,
  type CheckContext,
  type FirewallFinding,
} from "../types";

/**
 * Wei-denominated ceilings.
 *
 * These are deliberately independent of the USD ceilings: they need no oracle,
 * so they still hold when pricing is unavailable. That is the whole reason the
 * capability carries both — a price outage degrades Arx from "value-aware" to
 * "value-bounded", never to "unbounded".
 *
 * `maxValueWei` defaults to `"0"` in the schema, and that default is honoured
 * literally: a capability that never granted authority to move native value
 * does not get to move any. It is the closed position, not an unset one.
 */
export function checkLimits(context: CheckContext): FirewallFinding[] {
  const findings: FirewallFinding[] = [];
  const { tx, capability } = context;
  const limits = capability.limits;

  const value = toBigInt(tx.value);
  const gasLimit = toBigInt(tx.gasLimit);
  const maxFeePerGas = toBigInt(tx.maxFeePerGas);

  const maxValueWei = toBigInt(limits.maxValueWei);
  const maxGasLimit = toBigInt(limits.maxGasLimit);
  const maxFeeCeiling = toBigInt(limits.maxFeePerGasWei);

  if (value === undefined || gasLimit === undefined || maxFeePerGas === undefined) {
    return [
      block(
        "INVALID_TRANSACTION",
        "Transaction value, gas limit or fee is not a readable integer",
        { value: tx.value, gasLimit: tx.gasLimit, maxFeePerGas: tx.maxFeePerGas },
      ),
    ];
  }

  if (maxValueWei !== undefined && value > maxValueWei) {
    findings.push(
      block(
        "VALUE_LIMIT_EXCEEDED",
        maxValueWei === 0n
          ? `Transaction moves ${value} wei of native value, and this capability's maxValueWei is 0 — it grants no authority over native value at all`
          : `Transaction moves ${value} wei, above this capability's per-transaction ceiling of ${maxValueWei} wei`,
        { valueWei: value.toString(), maxValueWei: maxValueWei.toString() },
      ),
    );
  }

  if (maxGasLimit !== undefined && maxGasLimit > 0n && gasLimit > maxGasLimit) {
    findings.push(
      block(
        "GAS_LIMIT_EXCEEDED",
        `Gas limit ${gasLimit} is above this capability's ceiling of ${maxGasLimit}`,
        { gasLimit: gasLimit.toString(), maxGasLimit: maxGasLimit.toString() },
      ),
    );
  }

  if (
    maxFeeCeiling !== undefined &&
    maxFeeCeiling > 0n &&
    maxFeePerGas > maxFeeCeiling
  ) {
    findings.push(
      block(
        "FEE_LIMIT_EXCEEDED",
        `Fee cap ${maxFeePerGas} wei per gas is above this capability's ceiling of ${maxFeeCeiling} wei`,
        {
          maxFeePerGas: maxFeePerGas.toString(),
          ceiling: maxFeeCeiling.toString(),
        },
      ),
    );
  }

  // The worst case a signature commits the wallet to, which is the figure a
  // gas ceiling is actually protecting: limit multiplied by cap.
  if (
    gasLimit !== undefined &&
    maxFeePerGas !== undefined &&
    maxValueWei !== undefined
  ) {
    findings.push(
      info(
        "POLICY_APPROVED",
        `Maximum total cost of this transaction is ${value + gasLimit * maxFeePerGas} wei (${value} value + ${gasLimit * maxFeePerGas} worst-case fee)`,
        {
          valueWei: value.toString(),
          worstCaseFeeWei: (gasLimit * maxFeePerGas).toString(),
        },
      ),
    );
  }

  return findings;
}

function toBigInt(value: string): bigint | undefined {
  try {
    return BigInt(value);
  } catch {
    return undefined;
  }
}
