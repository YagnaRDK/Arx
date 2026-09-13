import type { AddressProfile, RiskSignal, RiskSignalProvider } from "../core/seams";
import { computeLocalSignals, type LocalSignalInput } from "./local-signals";

/**
 * Explainable risk scoring.
 *
 * Two rules define this module.
 *
 * **The score never widens authority.** It is an input to *escalation* and to
 * the capability's hard ceiling, and nothing else. A score of zero cannot clear
 * a failed recipient check; the firewall runs blocking checks first and risk
 * afterwards precisely so that ordering is structural rather than a convention.
 *
 * **A score without its signals is not auditable.** `assess` always returns the
 * list that produced the number, so an operator reading the log sees *why* a
 * transaction scored 74 rather than being asked to trust it.
 */

export type RiskAssessment = {
  /** 0-100, rounded. */
  score: number;
  /** Every signal that contributed, in contribution order. */
  signals: RiskSignal[];
  profiles: AddressProfile[];
  /** Providers that could not be reached. Never silently dropped. */
  unavailableProviders: Array<{ provider: string; reason: string }>;
};

/**
 * Weight assigned when an external provider cannot be reached.
 *
 * Not zero: "we could not check the counterparty" is itself a reason to be more
 * careful, and a dependency outage must never make a transaction look safer
 * than it did when the check was working.
 */
const PROVIDER_UNAVAILABLE_WEIGHT = 10;

export type RiskEngineOptions = {
  providers?: readonly RiskSignalProvider[];
  /** Hard cap per provider call so a slow reputation API cannot stall a decision. */
  providerTimeoutMs?: number;
};

export type AssessInput = LocalSignalInput & {
  /** Counterparties to ask external providers about. */
  externalAddresses?: readonly string[];
};

export class RiskEngine {
  private readonly providers: readonly RiskSignalProvider[];
  private readonly providerTimeoutMs: number;

  constructor(options: RiskEngineOptions = {}) {
    this.providers = options.providers ?? [];
    this.providerTimeoutMs = options.providerTimeoutMs ?? 2500;
  }

  /**
   * Combines weights into a 0-100 score.
   *
   * Summation is wrong here: three signals worth 40 each would sum to 120 and
   * clamp to 100, making "three moderate oddities" indistinguishable from
   * "certainly an attack". Instead each weight is treated as an independent
   * probability of the transaction being bad and combined as a union, so the
   * score rises monotonically with every additional signal, never exceeds 100,
   * and a single strong signal still dominates a pile of weak ones.
   */
  combine(signals: readonly RiskSignal[]): number {
    let remainingSafety = 1;

    for (const item of signals) {
      const weight = Math.min(100, Math.max(0, item.weight));
      remainingSafety *= 1 - weight / 100;
    }

    return Math.round((1 - remainingSafety) * 100);
  }

  /** Synchronous scoring from local signals only. Used when no provider is wired. */
  assessLocal(input: LocalSignalInput): RiskAssessment {
    const signals = computeLocalSignals(input);

    return {
      score: this.combine(signals),
      signals,
      profiles: [],
      unavailableProviders: [],
    };
  }

  async assess(input: AssessInput): Promise<RiskAssessment> {
    const signals = computeLocalSignals(input);
    const profiles: AddressProfile[] = [];
    const unavailableProviders: Array<{ provider: string; reason: string }> = [];

    const addresses = dedupe([
      ...(input.externalAddresses ?? []),
      ...(input.to === undefined ? [] : [input.to]),
      ...input.decodedCall.recipients,
    ]);

    for (const provider of this.providers) {
      if (!provider.isReady()) {
        continue;
      }

      for (const address of addresses) {
        const result = await this.callProvider(provider, {
          address,
          chainId: input.chainId,
          valueWei: input.valueWei,
          selector: input.decodedCall.selector,
        });

        if (result.status === "UNAVAILABLE") {
          unavailableProviders.push({
            provider: provider.name,
            reason: result.reason,
          });

          signals.push({
            id: "RISK_PROVIDER_UNAVAILABLE",
            weight: PROVIDER_UNAVAILABLE_WEIGHT,
            explanation: `Risk provider "${provider.name}" could not be reached, so ${address} is unverified: ${result.reason}`,
            evidence: { provider: provider.name, address },
          });

          continue;
        }

        signals.push(...result.value.signals);

        if (result.value.profile) {
          profiles.push(result.value.profile);
        }
      }
    }

    return {
      score: this.combine(signals),
      signals,
      profiles,
      unavailableProviders,
    };
  }

  private async callProvider(
    provider: RiskSignalProvider,
    input: {
      address: string;
      chainId: number;
      valueWei: string;
      selector?: string;
    },
  ) {
    let timer: ReturnType<typeof setTimeout> | undefined;

    try {
      return await Promise.race([
        provider.signalsFor(input),
        new Promise<{
          status: "UNAVAILABLE";
          reason: string;
          retryable: boolean;
        }>((resolve) => {
          timer = setTimeout(
            () =>
              resolve({
                status: "UNAVAILABLE",
                reason: `timed out after ${this.providerTimeoutMs}ms`,
                retryable: true,
              }),
            this.providerTimeoutMs,
          );
        }),
      ]);
    } catch (error) {
      // A provider that throws has not checked anything. It must not be able to
      // fail the whole assessment shut, and it must not look like a clean pass.
      return {
        status: "UNAVAILABLE" as const,
        reason: error instanceof Error ? error.message : String(error),
        retryable: true,
      };
    } finally {
      if (timer !== undefined) {
        clearTimeout(timer);
      }
    }
  }
}

function dedupe(values: readonly string[]): string[] {
  return [...new Set(values.map((value) => value.toLowerCase()))];
}

export {
  computeLocalSignals,
  findLookalike,
  RISK_SIGNAL_WEIGHTS,
  ZERO_ADDRESS,
  DEAD_ADDRESS,
  type LocalSignalInput,
} from "./local-signals";
