import type {
  NameResolver,
  PriceOracle,
  RiskSignal,
  RiskSignalProvider,
} from "../core/seams";
import { RiskEngine, type RiskAssessment } from "../risk/risk-engine";
import type { SpendStore } from "../storage/spend-store";
import type { Capability } from "../types/capability";
import {
  allow,
  deny,
  escalate,
  type EvaluationResult,
} from "../types/evaluation";
import type { Intent } from "../types/intent";
import type { NormalizedTransaction } from "../types/transaction";

import { checkApproveSemantics } from "./checks/approve-semantics";
import { checkCalldataRecipient } from "./checks/calldata-recipient";
import { checkChainBinding } from "./checks/chain-binding";
import { checkContractCreation } from "./checks/contract-creation";
import { checkContractPolicy } from "./checks/contract-policy";
import { decodeCalldata } from "./checks/decode-calldata";
import { checkEscalation } from "./checks/escalation";
import { checkLimits } from "./checks/limits";
import { checkMethodPolicy } from "./checks/method-policy";
import { checkMulticall } from "./checks/multicall";
import { checkRecipientPolicy } from "./checks/recipient-policy";
import {
  resolvePolicySet,
  resolvePolicySetSync,
  type ResolvedPolicySet,
} from "./checks/recipient-resolution";
import { checkRiskCeiling } from "./checks/risk-ceiling";
import { checkSpendWindows } from "./checks/spend-windows";
import {
  bindValueWithoutOracle,
  checkValueBinding,
  type ValueBindingResult,
} from "./checks/value-binding";
import {
  firstBlocking,
  firstEscalation,
  info,
  type CheckContext,
  type FirewallDecision,
  type FirewallFinding,
} from "./types";

/**
 * The transaction firewall.
 *
 * The policy engine answers "is this the kind of thing the agent may do?" from
 * the agent's own description of the action. This layer answers the harder
 * question: does the transaction actually do what was described, and to whom.
 * Those are different questions, and only the second one is checkable —
 * `intent.amountUsd`, `intent.action` and `intent.inputToken` are claims made by
 * a process an attacker may already be steering, while the transaction bytes are
 * what the device will sign.
 *
 * Every dependency is optional and injected. With none of them the firewall
 * still enforces chain binding, recipient and contract allowlists, method
 * policy, calldata recipients, batch transparency, approval semantics and the
 * wei/gas/fee ceilings — and degrades USD-dependent decisions to ESCALATE
 * rather than to ALLOW, because a check that cannot run has not passed.
 *
 * Ordering is a control, not a style choice. Blocking checks are resolved before
 * escalation and before risk, so no score and no human-approval rule can clear a
 * policy comparison that failed.
 */

export type FirewallDependencies = {
  /** Price truth for value binding. Absent means USD decisions escalate. */
  priceOracle?: PriceOracle;
  /** Resolves ENS names in the recipient/contract allowlists. */
  nameResolver?: NameResolver;
  /** External reputation providers, consulted by the risk engine. */
  riskProviders?: readonly RiskSignalProvider[];
  /** Supply a pre-built engine to override provider wiring or timeouts. */
  riskEngine?: RiskEngine;
  /** Rolling-window spend accounting. */
  spendStore?: SpendStore;
};

export type FirewallInspectInput = {
  transaction: NormalizedTransaction;
  intent: Intent;
  capability: Capability;
  /** The capability-level verdict. The firewall never overturns a denial. */
  policyResult: EvaluationResult;
  /** The signer's address, when known, so a self-transfer is detectable. */
  signerAddress?: string;
  /** Mean prior transaction value for this capability, USD. */
  historicalMeanUsd?: number;
  historicalSampleCount?: number;
  /** Injected clock. Never read inside a check. */
  now?: number;
};

/** Retained so callers written against the v0.4 firewall still compile. */
export type FirewallProcessContext = {
  capability: Capability;
  intent: Intent;
  signerAddress?: string;
  now?: number;
};

export class TransactionFirewall {
  private readonly deps: FirewallDependencies;
  private readonly riskEngine: RiskEngine;

  constructor(dependencies: FirewallDependencies = {}) {
    this.deps = dependencies;
    this.riskEngine =
      dependencies.riskEngine ??
      new RiskEngine({ providers: dependencies.riskProviders ?? [] });
  }

  /**
   * The full-strength inspection: every check, every injected dependency.
   *
   * This is what an authorization path should call.
   */
  async inspect(input: FirewallInspectInput): Promise<FirewallDecision> {
    if (!input.policyResult.allowed) {
      return this.deferToPolicy(input.policyResult);
    }

    const context = buildContext(input);

    const recipients = await resolvePolicySet(
      input.capability.recipients,
      context.tx.chainId,
      this.deps.nameResolver,
    );

    const contracts = await resolvePolicySet(
      input.capability.contracts,
      context.tx.chainId,
      this.deps.nameResolver,
    );

    const structural = this.structuralChecks(context, recipients, contracts);

    const value = await checkValueBinding(context, {
      oracle: this.deps.priceOracle,
    });

    const risk = await this.riskEngine.assess({
      ...riskInput(context, input, value),
    });

    return this.finish({
      input,
      context,
      recipients,
      findings: [...structural, ...value.findings],
      value,
      risk,
    });
  }

  /**
   * Synchronous inspection, kept for the original two-argument call shape.
   *
   * Without a `context` this is a passthrough and enforces nothing — it exists
   * so an older caller keeps compiling, and it says so in its findings. With a
   * context it runs the whole pipeline except the parts that need to go over the
   * network (pricing, name resolution, external reputation), which therefore
   * resolve to ESCALATE rather than ALLOW.
   *
   * Prefer `inspect()`.
   */
  process(
    transaction: NormalizedTransaction,
    result: EvaluationResult,
    context?: FirewallProcessContext,
  ): FirewallDecision {
    if (!result.allowed) {
      return this.deferToPolicy(result);
    }

    if (!context) {
      return {
        allowed: true,
        decision: "ALLOW",
        result,
        transaction,
        findings: [
          info(
            "INTERNAL_ERROR",
            "TransactionFirewall.process was called without a capability or intent, so no transaction-level check could run. This is the compatibility shim; call inspect() to enforce the firewall.",
          ),
        ],
        riskScore: 0,
        riskSignals: [],
        valueUsd: 0,
        declaredValueUsd: 0,
        valuePriced: false,
        priceQuotes: [],
      };
    }

    const input: FirewallInspectInput = {
      transaction,
      intent: context.intent,
      capability: context.capability,
      policyResult: result,
      ...(context.signerAddress === undefined
        ? {}
        : { signerAddress: context.signerAddress }),
      ...(context.now === undefined ? {} : { now: context.now }),
    };

    const checkContext = buildContext(input);

    const recipients = resolvePolicySetSync(context.capability.recipients);
    const contracts = resolvePolicySetSync(context.capability.contracts);

    const structural = this.structuralChecks(
      checkContext,
      recipients,
      contracts,
    );

    const value = bindValueWithoutOracle(checkContext);
    const risk = this.riskEngine.assessLocal(
      riskInput(checkContext, input, value),
    );

    return this.finish({
      input,
      context: checkContext,
      recipients,
      findings: [...structural, ...value.findings],
      value,
      risk,
    });
  }

  /**
   * The checks that need nothing but the transaction, the capability and the
   * resolved allowlists.
   */
  private structuralChecks(
    context: CheckContext,
    recipients: ResolvedPolicySet,
    contracts: ResolvedPolicySet,
  ): FirewallFinding[] {
    return [
      ...checkChainBinding(context),
      ...checkContractCreation(context),
      ...checkMulticall(context),
      ...checkRecipientPolicy(context, recipients),
      ...checkContractPolicy(context, contracts),
      ...checkMethodPolicy(context),
      ...checkCalldataRecipient(context, recipients),
      ...checkLimits(context),
    ];
  }

  /**
   * Resolves findings into one decision.
   *
   * BLOCK beats ESCALATE beats ALLOW, unconditionally. That ordering is what
   * makes "risk is advisory" true in code rather than in a comment: the risk
   * score is computed after the blocking checks and can only ever add findings.
   */
  private finish(args: {
    input: FirewallInspectInput;
    context: CheckContext;
    recipients: ResolvedPolicySet;
    findings: FirewallFinding[];
    value: ValueBindingResult;
    risk: RiskAssessment;
  }): FirewallDecision {
    const { input, context, recipients, value, risk } = args;

    const findings = [...args.findings];

    findings.push(
      ...checkApproveSemantics(context, {
        declaredValueUsd: input.intent.amountUsd,
        ...(value.allowanceUsd === undefined
          ? {}
          : { allowanceUsd: value.allowanceUsd }),
      }),
    );

    findings.push(
      ...checkSpendWindows(context, {
        ...(this.deps.spendStore === undefined
          ? {}
          : { spendStore: this.deps.spendStore }),
        valueUsd: value.valueUsd,
        valuePriced: value.valuePriced,
      }).findings,
    );

    findings.push(
      ...checkRiskCeiling(context, {
        score: risk.score,
        signals: risk.signals,
      }),
    );

    findings.push(
      ...checkEscalation(context, {
        valueUsd: value.valueUsd,
        valuePriced: value.valuePriced,
        riskScore: risk.score,
        riskSignals: risk.signals,
        recipients,
      }),
    );

    const base = {
      findings,
      riskScore: risk.score,
      riskSignals: risk.signals,
      valueUsd: value.valueUsd,
      declaredValueUsd: input.intent.amountUsd,
      valuePriced: value.valuePriced,
      priceQuotes: value.priceQuotes,
      decodedCall: context.decodedCall,
    };

    const details = {
      findings: findings.filter((finding) => finding.severity !== "INFO"),
      notes: findings.filter((finding) => finding.severity === "INFO"),
      riskScore: risk.score,
      riskSignals: risk.signals,
      valueUsd: value.valueUsd,
      declaredValueUsd: input.intent.amountUsd,
      valuePriced: value.valuePriced,
      priceSources: value.priceQuotes.map((quote) => quote.source),
      transactionId: input.transaction.transactionId,
      unavailableRiskProviders: risk.unavailableProviders,
    };

    const blocking = firstBlocking(findings);

    if (blocking) {
      return {
        ...base,
        allowed: false,
        decision: "DENY",
        result: deny(blocking.code, blocking.message, details),
      };
    }

    const escalation = firstEscalation(findings);

    if (escalation) {
      return {
        ...base,
        allowed: false,
        decision: "ESCALATE",
        // The bytes travel with an escalation: a human approves this exact
        // transaction, not a re-derived one.
        transaction: input.transaction,
        result: escalate(escalation.message, details),
      };
    }

    return {
      ...base,
      allowed: true,
      decision: "ALLOW",
      transaction: input.transaction,
      result: allow(
        value.valuePriced
          ? `Transaction verified against the capability: $${value.valueUsd.toFixed(2)} to a permitted recipient, risk score ${risk.score}`
          : `Transaction verified against the capability's byte-level limits, risk score ${risk.score}`,
      ),
    };
  }

  /** A policy denial stands. The firewall adds nothing and overturns nothing. */
  private deferToPolicy(result: EvaluationResult): FirewallDecision {
    return {
      allowed: false,
      decision: "DENY",
      result,
      findings: [
        info(
          result.code,
          `Capability evaluation already denied this intent (${result.code}); no transaction-level check was run`,
        ),
      ],
      riskScore: 0,
      riskSignals: [],
      valueUsd: 0,
      declaredValueUsd: 0,
      valuePriced: false,
      priceQuotes: [],
    };
  }
}

function buildContext(input: FirewallInspectInput): CheckContext {
  const tx = input.transaction.transaction;

  return {
    transaction: input.transaction,
    tx,
    capability: input.capability,
    intent: input.intent,
    decodedCall: decodeCalldata({
      ...(tx.to === undefined ? {} : { to: tx.to }),
      data: tx.data,
      value: tx.value,
    }),
    now: input.now ?? input.transaction.createdAt,
  };
}

function riskInput(
  context: CheckContext,
  input: FirewallInspectInput,
  value: ValueBindingResult,
) {
  const tx = context.tx;

  return {
    chainId: tx.chainId,
    ...(tx.to === undefined ? {} : { to: tx.to }),
    valueWei: tx.value,
    data: tx.data,
    gasLimit: tx.gasLimit,
    maxFeePerGas: tx.maxFeePerGas,
    maxPriorityFeePerGas: tx.maxPriorityFeePerGas,
    ...(input.signerAddress === undefined
      ? {}
      : { from: input.signerAddress }),
    decodedCall: context.decodedCall,
    capability: context.capability,
    declaredValueUsd: input.intent.amountUsd,
    pricingStatus: value.pricingStatus,
    ...(value.valuePriced ? { valueUsd: value.valueUsd } : {}),
    ...(value.allowanceUsd === undefined
      ? {}
      : { allowanceUsd: value.allowanceUsd }),
    action: input.intent.action,
    ...(input.historicalMeanUsd === undefined
      ? {}
      : { historicalMeanUsd: input.historicalMeanUsd }),
    ...(input.historicalSampleCount === undefined
      ? {}
      : { historicalSampleCount: input.historicalSampleCount }),
  };
}

export type { RiskSignal };
export {
  type FirewallDecision,
  type FirewallFinding,
  type FirewallSeverity,
} from "./types";
export { decodeCalldata, type DecodedCall } from "./checks/decode-calldata";
