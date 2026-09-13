/**
 * The authorization pipeline, in one place.
 *
 * `POST /firewall/submit` and `POST /approvals` must reach identical verdicts on
 * identical input — the first is a dry run and the second commits. When they
 * were separate route handlers they had already drifted: one checked that the
 * transaction's chain matched the intent and the other did not. Both now call
 * this, so a check cannot be added to the preview and forgotten in the commit.
 */

import { ArxError } from "../core/errors";
import { eventBus } from "./events";
import type { TransactionFirewall } from "../firewall/transaction-firewall";
import type { FirewallDecision } from "../firewall/types";
import type { PolicyEngine } from "../policy/policy-engine";
import { POLICY_VERSION } from "../policy/policy-engine";
import type { TransactionNormalizer } from "../normalization/transaction-normalizer";
import type { AuditStore } from "../storage/audit-store";
import type { CapabilityStore } from "../storage/capability-store";
import type { ReplayStore } from "../storage/replay-store";
import type { Capability } from "../types/capability";
import type { EvaluationResult } from "../types/evaluation";
import { deny } from "../types/evaluation";
import type { Intent } from "../types/intent";
import type { NormalizedTransaction } from "../types/transaction";

export type PipelineDependencies = {
  capabilityStore: CapabilityStore;
  replayStore: ReplayStore;
  auditStore: AuditStore;
  policyEngine: PolicyEngine;
  normalizer: TransactionNormalizer;
  firewall: TransactionFirewall;
  maxClockSkewSeconds: number;
};

export type PipelineOutcome =
  | {
      kind: "REJECTED";
      requestId: string;
      result: EvaluationResult;
      capability?: Capability;
    }
  | {
      kind: "DECIDED";
      requestId: string;
      capability: Capability;
      transaction: NormalizedTransaction;
      decision: FirewallDecision;
    };

export class AuthorizationPipeline {
  constructor(private readonly deps: PipelineDependencies) {}

  /**
   * Runs normalization, capability resolution, policy and firewall.
   *
   * Deliberately does NOT claim the nonce or create an approval — evaluation is
   * side-effect free apart from audit records, so a preview cannot consume the
   * agent's authority. Committing is the caller's separate, explicit step.
   */
  async evaluate(input: {
    requestId: string;
    intent: Intent;
    signerAddress?: string;
    requireTransaction: boolean;
    now?: number;
  }): Promise<PipelineOutcome> {
    const now = input.now ?? Math.floor(Date.now() / 1000);
    const { intent, requestId } = input;

    this.deps.auditStore.append({
      eventType: "INTENT_RECEIVED",
      requestId,
      capabilityId: intent.capabilityId,
      agentId: intent.agentId,
      payload: {
        action: intent.action,
        protocol: intent.protocol,
        chainId: intent.chainId,
        declaredAmountUsd: intent.amountUsd,
        nonce: intent.nonce,
        hasTransaction: intent.transaction !== undefined,
      },
      timestamp: now,
    });

    eventBus.publish("intent.received", {
      requestId,
      agentId: intent.agentId,
      capabilityId: intent.capabilityId,
      action: intent.action,
      declaredAmountUsd: intent.amountUsd,
    });

    const capability = this.deps.capabilityStore.get(intent.capabilityId);

    if (!capability) {
      return this.reject(
        requestId,
        intent,
        deny("CAPABILITY_NOT_FOUND", "Capability does not exist"),
        now,
      );
    }

    this.deps.auditStore.append({
      eventType: "CAPABILITY_RESOLVED",
      requestId,
      capabilityId: capability.capabilityId,
      agentId: capability.agentId,
      reason: `status=${capability.status} usage=${capability.usage}`,
      payload: { label: capability.label ?? null },
      timestamp: now,
    });

    const policyResult = this.deps.policyEngine.evaluate(
      capability,
      intent,
      {
        isReplay: this.deps.replayStore.hasBeenProcessed(
          intent.capabilityId,
          intent.agentId,
          intent.nonce,
        ),
        highestAcceptedNonce: this.deps.replayStore.highestNonce(
          intent.capabilityId,
        ),
        maxClockSkewSeconds: this.deps.maxClockSkewSeconds,
      },
      now,
    );

    this.deps.auditStore.write({ requestId, intent, result: policyResult });

    eventBus.publish("policy.evaluated", {
      requestId,
      decision: policyResult.allowed ? "ALLOW" : (policyResult.decision ?? "DENY"),
      code: policyResult.code,
      reason: policyResult.reason,
    });

    if (!policyResult.allowed) {
      return {
        kind: "REJECTED",
        requestId,
        result: policyResult,
        capability,
      };
    }

    if (!intent.transaction) {
      if (input.requireTransaction) {
        return this.reject(
          requestId,
          intent,
          deny(
            "INVALID_TRANSACTION",
            "A transaction is required for firewall inspection",
          ),
          now,
        );
      }

      // Intent-only evaluation: the capability permits this, and there are no
      // bytes to inspect yet.
      return {
        kind: "REJECTED",
        requestId,
        result: policyResult,
        capability,
      };
    }

    let transaction: NormalizedTransaction;

    try {
      transaction = this.deps.normalizer.normalize({
        agentId: intent.agentId,
        capabilityId: intent.capabilityId,
        transaction: intent.transaction,
        now,
      });
    } catch (error) {
      const result =
        error instanceof ArxError
          ? deny(error.code, error.message, error.details)
          : deny("INVALID_TRANSACTION", "Transaction normalization failed");

      return this.reject(requestId, intent, result, now);
    }

    const decision = await this.deps.firewall.inspect({
      transaction,
      intent,
      capability,
      policyResult,
      signerAddress: input.signerAddress,
      now,
    });

    this.deps.auditStore.append({
      eventType: "FIREWALL_CHECKED",
      requestId,
      capabilityId: capability.capabilityId,
      agentId: capability.agentId,
      transactionId: transaction.transactionId,
      decision: decision.decision,
      code: decision.result.code,
      reason: decision.result.reason,
      payload: {
        findings: decision.findings,
        valueUsd: decision.valueUsd,
        declaredValueUsd: decision.declaredValueUsd,
        decodedCall: decision.decodedCall ?? null,
      },
      timestamp: now,
    });

    this.deps.auditStore.append({
      eventType: "RISK_SCORED",
      requestId,
      capabilityId: capability.capabilityId,
      agentId: capability.agentId,
      transactionId: transaction.transactionId,
      reason: `score=${decision.riskScore}`,
      // The signals travel with the score: a number nobody can explain is not
      // auditable.
      payload: { riskScore: decision.riskScore, signals: decision.riskSignals },
      timestamp: now,
    });

    eventBus.publish("firewall.checked", {
      requestId,
      decision: decision.decision,
      code: decision.result.code,
      reason: decision.result.reason,
      riskScore: decision.riskScore,
      riskSignals: decision.riskSignals,
      findings: decision.findings,
      valueUsd: decision.valueUsd,
      declaredValueUsd: decision.declaredValueUsd,
      to: transaction.transaction.to ?? null,
      transactionId: transaction.transactionId,
    });

    return {
      kind: "DECIDED",
      requestId,
      capability,
      transaction,
      decision,
    };
  }

  /**
   * Claims the intent's nonce and consumes a single-use capability.
   *
   * Called only once a decision has been committed to, and atomic: a lost race
   * on `claimNonce` reports a replay rather than allowing two authorizations to
   * share one nonce.
   */
  commitAuthority(input: {
    intent: Intent;
    capability: Capability;
    now?: number;
  }): EvaluationResult | null {
    const now = input.now ?? Math.floor(Date.now() / 1000);

    const claimed = this.deps.replayStore.claimNonce(
      input.intent.capabilityId,
      input.intent.agentId,
      input.intent.nonce,
      now,
    );

    if (!claimed) {
      return deny(
        "REPLAY_DETECTED",
        `Nonce ${input.intent.nonce} was claimed concurrently by another request`,
      );
    }

    if (input.capability.usage === "SINGLE_USE") {
      this.deps.capabilityStore.consume(input.capability.capabilityId, now);
    }

    return null;
  }

  private reject(
    requestId: string,
    intent: Intent,
    result: EvaluationResult,
    now: number,
  ): PipelineOutcome {
    this.deps.auditStore.write({ requestId, intent, result });

    eventBus.publish("policy.evaluated", {
      requestId,
      decision: result.decision ?? "DENY",
      code: result.code,
      reason: result.reason,
    });

    return { kind: "REJECTED", requestId, result };
  }
}

export { POLICY_VERSION };
