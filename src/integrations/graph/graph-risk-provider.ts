/**
 * Recipient reputation from The Graph, as a `RiskSignalProvider`.
 *
 * This is load-bearing rather than decorative: the score this produces feeds
 * `humanApproval.requiredAboveRiskScore` and `capability.maxRiskScore`, so live
 * Graph data is what decides whether a transaction runs autonomously, escalates
 * to a person at the device, or is refused outright.
 *
 * Every signal is derived from data the caller can re-check, and carries the
 * evidence that produced it. A risk score an operator cannot explain is a
 * number they will learn to override.
 *
 * Two failure modes are kept strictly apart:
 *   - "checked, nothing suspicious" -> `OK` with an empty or zero-weight signal
 *     list, and a profile.
 *   - "could not check" -> `UNAVAILABLE`. No key, an unindexed chain, a timeout
 *     and a 500 all land here. A risk provider that returns a clean result when
 *     it could not reach its data source is an authorization bypass with extra
 *     steps.
 */

import { env } from "../../config/env";
import {
  ok,
  unavailable,
  type AddressProfile,
  type Availability,
  type RiskSignal,
  type RiskSignalProvider,
} from "../../core/seams";
import { cacheKey, readCache, writeCache } from "../cache";
import { failureToUnavailable } from "../http";
import { fixtureFor, type AddressFixture } from "./fixtures";
import {
  CHAIN_ID_TO_TOKEN_API_NETWORK,
  TokenApiClient,
  rowsOf,
  type TokenApiNetwork,
  type TransferRow,
} from "./token-api";

const PROFILE_TTL_SECONDS = 120;

/** Page size and page cap bound both latency and the evidence window. */
const PAGE_SIZE = 200;
const MAX_PAGES = 2;

const DAY_SECONDS = 86_400;

/**
 * Hosts that no longer serve the Token API. Kept explicit so a stale
 * `GRAPH_TOKEN_API_URL` makes the adapter report itself unready with a useful
 * reason, instead of every risk lookup timing out at request time.
 */
const DECOMMISSIONED_HOSTS = new Set(["token-api.thegraph.com"]);

export type GraphRiskMode = "LIVE" | "FIXTURES";

export type GraphRiskProviderOptions = {
  apiKey?: string;
  baseUrl?: string;
  /**
   * `FIXTURES` runs the same scoring logic over `fixtures.ts` so the demo is
   * reproducible with zero API keys. It is labelled everywhere it surfaces.
   */
  mode?: GraphRiskMode;
  now?: () => number;
  timeoutMs?: number;
};

type Observation = {
  firstSeenAt: number | null;
  /**
   * True when the page cap was hit, so `firstSeenAt` is an upper bound on the
   * true first-seen time. An address with more history than we can page through
   * is by definition not new, so a bounded scan never produces a false
   * "brand new address" signal.
   */
  firstSeenIsUpperBound: boolean;
  transferCount: number;
  transferCountIsLowerBound: boolean;
  uniqueCounterparties: number;
};

export class GraphRiskSignalProvider implements RiskSignalProvider {
  readonly name = "graph";

  readonly mode: GraphRiskMode;
  readonly baseUrl: string;

  private readonly apiKey: string;
  private readonly now: () => number;
  private readonly client: TokenApiClient | null;

  constructor(options: GraphRiskProviderOptions = {}) {
    this.apiKey = options.apiKey ?? env.graphApiKey;
    this.baseUrl = options.baseUrl ?? env.graphTokenApiUrl;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));

    const liveCapable = this.apiKey.length > 0 && !this.hostIsDecommissioned();

    this.mode = options.mode ?? (liveCapable ? "LIVE" : "FIXTURES");
    this.client =
      this.mode === "LIVE"
        ? new TokenApiClient({
            baseUrl: this.baseUrl,
            apiKey: this.apiKey,
            timeoutMs: options.timeoutMs ?? 5_000,
          })
        : null;
  }

  /**
   * Fixture mode is "ready" in the sense that it answers, and its answers are
   * labelled as fixtures. Live mode needs a key and a reachable base URL.
   */
  isReady(): boolean {
    if (this.mode === "FIXTURES") {
      return true;
    }

    return this.apiKey.length > 0 && !this.hostIsDecommissioned();
  }

  get source(): string {
    return this.mode === "LIVE"
      ? "graph-token-api:LIVE"
      : "graph-token-api:FIXTURES";
  }

  /** Operator-facing readiness detail for `/integrations`. */
  readinessDetail(): string {
    if (this.mode === "LIVE") {
      return `Live Token API at ${this.baseUrl}`;
    }

    if (this.apiKey.length === 0) {
      return "No GRAPH_API_KEY: running on labelled offline fixtures, not live data";
    }

    return `GRAPH_API_KEY is set but GRAPH_TOKEN_API_URL points at the decommissioned host ${hostOf(this.baseUrl)}; set it to https://api.pinax.network to go live. Running on labelled fixtures meanwhile.`;
  }

  async signalsFor(input: {
    address: string;
    chainId: number;
    valueWei: string;
    selector?: string;
  }): Promise<
    Availability<{ signals: RiskSignal[]; profile?: AddressProfile }>
  > {
    const address = input.address.toLowerCase();
    const now = this.now();

    if (this.mode === "FIXTURES") {
      return this.fixtureSignals(address, input.chainId, now);
    }

    const network = CHAIN_ID_TO_TOKEN_API_NETWORK[input.chainId];

    if (network === undefined) {
      // Answering from another chain's index would be worse than not
      // answering, so this is an explicit non-retryable unavailability.
      return unavailable(
        `The Graph Token API does not index chain ${input.chainId}`,
        false,
      );
    }

    const key = cacheKey("graph:profile", network, address);
    const cached = readCache<Observation>(key, now);

    if (cached !== null) {
      return ok(
        this.scoreObservation({
          observation: cached.value,
          address,
          chainId: input.chainId,
          now,
          cachedAt: cached.fetchedAt,
        }),
      );
    }

    const observation = await this.observe(network, address);

    if (observation.status !== "OK") {
      return observation;
    }

    writeCache({
      key,
      value: observation.value,
      source: this.source,
      now,
      ttlSeconds: PROFILE_TTL_SECONDS,
    });

    return ok(
      this.scoreObservation({
        observation: observation.value,
        address,
        chainId: input.chainId,
        now,
      }),
    );
  }

  /**
   * Pages a bounded number of inbound and outbound transfer pages and folds
   * them into the four quantities the signals are derived from.
   */
  private async observe(
    network: TokenApiNetwork,
    address: string,
  ): Promise<Availability<Observation>> {
    const client = this.client;

    if (client === null) {
      return unavailable<Observation>(
        "Token API client not configured",
        false,
      );
    }

    const rows: TransferRow[] = [];
    let capped = false;

    for (const direction of ["to", "from"] as const) {
      for (const kind of ["erc20", "native"] as const) {
        for (let page = 1; page <= MAX_PAGES; page += 1) {
          const outcome =
            kind === "erc20"
              ? await client.transfers({
                  network,
                  address,
                  direction,
                  limit: PAGE_SIZE,
                  page,
                })
              : await client.nativeTransfers({
                  network,
                  address,
                  direction,
                  limit: PAGE_SIZE,
                  page,
                });

          if (!outcome.ok) {
            // One failed page means the observation is incomplete, and an
            // incomplete observation would understate activity and so
            // overstate risk in one direction and understate it in the other.
            // Neither is acceptable: abort the whole lookup.
            return failureToUnavailable<Observation>(
              "The Graph Token API",
              outcome.failure,
            );
          }

          const page_rows = rowsOf(outcome.value);

          rows.push(...page_rows);

          if (page_rows.length < PAGE_SIZE) {
            break;
          }

          if (page === MAX_PAGES) {
            capped = true;
          }
        }
      }
    }

    return ok(foldObservation(rows, address, capped));
  }

  private fixtureSignals(
    address: string,
    chainId: number,
    now: number,
  ): Availability<{ signals: RiskSignal[]; profile?: AddressProfile }> {
    const fixture = fixtureFor(address);

    if (fixture === undefined) {
      // An address with no fixture is genuinely unknown. Returning "clean"
      // here would let the offline demo silently approve anything.
      return unavailable(
        `No offline fixture for ${address}; live Graph data required (set GRAPH_API_KEY)`,
        false,
      );
    }

    const observation: Observation = {
      firstSeenAt: fixture.firstSeenAt,
      firstSeenIsUpperBound: false,
      transferCount: fixture.transferCount,
      transferCountIsLowerBound: false,
      uniqueCounterparties: fixture.uniqueCounterparties,
    };

    const scored = this.scoreObservation({
      observation,
      address,
      chainId,
      now,
      fixture,
    });

    return ok(scored);
  }

  private scoreObservation(input: {
    observation: Observation;
    address: string;
    chainId: number;
    now: number;
    cachedAt?: number;
    fixture?: AddressFixture;
  }): { signals: RiskSignal[]; profile?: AddressProfile } {
    const { observation, now } = input;
    const signals: RiskSignal[] = [];

    const evidenceBase = {
      source: this.source,
      ...(this.mode === "FIXTURES"
        ? { WARNING: "FIXTURE DATA — NOT LIVE CHAIN DATA" }
        : {}),
      ...(input.cachedAt === undefined
        ? {}
        : { observedAt: input.cachedAt, ageSeconds: now - input.cachedAt }),
      ...(input.fixture === undefined ? {} : { fixtureNote: input.fixture.note }),
    };

    if (
      observation.transferCount === 0 &&
      !observation.transferCountIsLowerBound
    ) {
      signals.push({
        id: "RECIPIENT_UNSEEN_BY_INDEXER",
        weight: 45,
        explanation:
          "The Graph has indexed no transfers for this address. A counterparty with no history at all is the most common shape of a freshly created drain address.",
        evidence: { ...evidenceBase, transferCount: 0 },
      });
    } else {
      const ageDays =
        observation.firstSeenAt === null
          ? null
          : Math.max(0, (now - observation.firstSeenAt) / DAY_SECONDS);

      if (ageDays !== null && !observation.firstSeenIsUpperBound) {
        if (ageDays < 1) {
          signals.push({
            id: "RECIPIENT_FIRST_SEEN_RECENTLY",
            weight: 35,
            explanation: `First indexed activity was ${formatAge(ageDays)} ago. An address created today has no reputation to lose.`,
            evidence: {
              ...evidenceBase,
              firstSeenAt: observation.firstSeenAt,
              ageDays: round(ageDays),
            },
          });
        } else if (ageDays < 7) {
          signals.push({
            id: "RECIPIENT_FIRST_SEEN_RECENTLY",
            weight: 20,
            explanation: `First indexed activity was ${formatAge(ageDays)} ago, inside the one-week window where new counterparties concentrate.`,
            evidence: {
              ...evidenceBase,
              firstSeenAt: observation.firstSeenAt,
              ageDays: round(ageDays),
            },
          });
        } else if (ageDays < 30) {
          signals.push({
            id: "RECIPIENT_FIRST_SEEN_RECENTLY",
            weight: 8,
            explanation: `First indexed activity was ${formatAge(ageDays)} ago.`,
            evidence: {
              ...evidenceBase,
              firstSeenAt: observation.firstSeenAt,
              ageDays: round(ageDays),
            },
          });
        }
      }

      if (!observation.transferCountIsLowerBound) {
        if (observation.transferCount <= 2) {
          signals.push({
            id: "RECIPIENT_LOW_TRANSFER_COUNT",
            weight: 20,
            explanation: `Only ${observation.transferCount} indexed transfer(s) touch this address.`,
            evidence: {
              ...evidenceBase,
              transferCount: observation.transferCount,
            },
          });
        } else if (observation.transferCount <= 10) {
          signals.push({
            id: "RECIPIENT_LOW_TRANSFER_COUNT",
            weight: 10,
            explanation: `${observation.transferCount} indexed transfers is thin history for a payment recipient.`,
            evidence: {
              ...evidenceBase,
              transferCount: observation.transferCount,
            },
          });
        }
      }

      if (
        observation.uniqueCounterparties <= 1 &&
        !observation.transferCountIsLowerBound
      ) {
        signals.push({
          id: "RECIPIENT_LOW_COUNTERPARTY_DIVERSITY",
          weight: 15,
          explanation:
            "This address has interacted with at most one other address. Funnel addresses look exactly like this.",
          evidence: {
            ...evidenceBase,
            uniqueCounterparties: observation.uniqueCounterparties,
          },
        });
      }
    }

    if (signals.length === 0) {
      // A zero-weight signal, not an empty list: the dashboard and the audit
      // record should say "checked and found established", which is different
      // from "no provider ran".
      signals.push({
        id: "RECIPIENT_ESTABLISHED",
        weight: 0,
        explanation: observation.transferCountIsLowerBound
          ? `More than ${observation.transferCount} indexed transfers — too much history to page through, which is itself evidence the address is not new.`
          : `${observation.transferCount} indexed transfers across ${observation.uniqueCounterparties} counterparties.`,
        evidence: {
          ...evidenceBase,
          transferCount: observation.transferCount,
          uniqueCounterparties: observation.uniqueCounterparties,
        },
      });
    }

    const profile: AddressProfile = {
      address: input.address,
      chainId: input.chainId,
      transactionCount: observation.transferCount,
      uniqueCounterparties: observation.uniqueCounterparties,
      source: this.source,
      ...(observation.firstSeenAt === null
        ? {}
        : { firstSeenAt: observation.firstSeenAt }),
      ...(input.fixture === undefined
        ? {}
        : { isContract: input.fixture.isContract, labels: input.fixture.labels }),
    };

    return { signals, profile };
  }

  private hostIsDecommissioned(): boolean {
    return DECOMMISSIONED_HOSTS.has(hostOf(this.baseUrl));
  }
}

function foldObservation(
  rows: readonly TransferRow[],
  address: string,
  capped: boolean,
): Observation {
  const counterparties = new Set<string>();
  const seenTransactions = new Set<string>();
  let firstSeenAt: number | null = null;

  for (const row of rows) {
    const timestamp = typeof row.timestamp === "number" ? row.timestamp : null;

    if (timestamp !== null && (firstSeenAt === null || timestamp < firstSeenAt)) {
      firstSeenAt = timestamp;
    }

    for (const side of [row.from, row.to]) {
      if (typeof side === "string" && side.toLowerCase() !== address) {
        counterparties.add(side.toLowerCase());
      }
    }

    if (typeof row.transaction_id === "string") {
      seenTransactions.add(row.transaction_id.toLowerCase());
    }
  }

  return {
    firstSeenAt,
    firstSeenIsUpperBound: capped,
    // Rows are counted, not transactions, but deduplicated by transaction hash
    // where one is present so a single transaction with many log entries does
    // not inflate the apparent history of a brand-new address.
    transferCount: seenTransactions.size > 0 ? seenTransactions.size : rows.length,
    transferCountIsLowerBound: capped,
    uniqueCounterparties: counterparties.size,
  };
}

function formatAge(days: number): string {
  if (days < 1) {
    return `${Math.max(1, Math.round(days * 24))}h`;
  }

  return `${Math.round(days)}d`;
}

function round(value: number): number {
  return Math.round(value * 100) / 100;
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
