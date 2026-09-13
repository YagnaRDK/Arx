/**
 * The honesty machine, made machine-readable.
 *
 * `GET /integrations` reads this. Its job is to let a judge, an operator or the
 * dashboard see — without reading any code — which sponsor integration is
 * actually talking to a live service right now, which is running on labelled
 * fixtures, which is dormant for want of a key, and which is a design sketch
 * that has never executed. A demo that quietly implies nine live integrations
 * when three are live is the exact failure this file exists to prevent.
 *
 * Four states, and the distinctions between them are load-bearing:
 *
 *   LIVE          talking to a real external service with real configuration
 *   FIXTURES      answering from checked-in fixtures, labelled as such in every
 *                 response it produces — never presented as live data
 *   DORMANT       correctly implemented, not enabled: a missing key, flag or
 *                 RPC URL. Returns `unavailable(...)`, never a clean result.
 *   DESIGN_SKETCH written down, never executed. Says so.
 *
 * `describe()` is deliberately cheap: it reports configured readiness and does
 * not make outbound calls. A status endpoint that probes nine third parties
 * becomes both slow and a way to make Arx generate traffic on demand. Probing
 * is opt-in via `describe({ probe: true })`.
 */

import { env } from "../config/env";
import { EnsNameResolver } from "./ens";
import { GraphRiskSignalProvider } from "./graph";
import { X402Gate } from "./x402";
import { WorldSelfieCheckVerifier } from "./world";
import { PrivySignerAdapter } from "./privy";
import { ArcChainAdapter } from "./circle";
import { UniswapV3Venue } from "./uniswap";
import { AquaSwapVmVenue, OneInchClassicSwapVenue } from "./oneinch";

export type IntegrationState =
  | "LIVE"
  | "FIXTURES"
  | "DORMANT"
  | "DESIGN_SKETCH";

export type IntegrationDescriptor = {
  /** Stable key for the dashboard. */
  id: string;
  /** Sponsor or provider name, as a human reads it. */
  sponsor: string;
  /** Which seam in `src/core/seams.ts` this plugs into. */
  seam: string;
  state: IntegrationState;
  /**
   * The adapter's own `isReady()`. Note this is `true` for a `FIXTURES`
   * adapter — it really will answer — so `state` is the field to read when the
   * question is "is this live data?". Keeping them separate is the point.
   */
  ready: boolean;
  /** Why it is in this state, in one operator-facing sentence. */
  detail: string;
  /** Env vars that move it towards `LIVE`. */
  enabledBy: string[];
  /** What a result from it is labelled as, when it produces one. */
  dataSource: string;
  /** Documentation URLs the configuration was verified against. */
  verifiedAgainst: string[];
  /** Present only when `probe: true` and the adapter supports probing. */
  probe?: unknown;
};

export type DescribeOptions = {
  /**
   * Make outbound calls to confirm the adapters that support it. Off by
   * default: a status endpoint must not be a traffic generator.
   */
  probe?: boolean;
};

export class IntegrationRegistry {
  readonly ens: EnsNameResolver;
  readonly graph: GraphRiskSignalProvider;
  readonly x402: X402Gate;
  readonly world: WorldSelfieCheckVerifier;
  readonly privy: PrivySignerAdapter;
  readonly arc: ArcChainAdapter;
  readonly uniswap: UniswapV3Venue;
  readonly oneInch: OneInchClassicSwapVenue;
  readonly aqua: AquaSwapVmVenue;

  constructor() {
    this.ens = new EnsNameResolver();
    this.graph = new GraphRiskSignalProvider();
    this.x402 = new X402Gate();
    this.world = new WorldSelfieCheckVerifier();
    this.privy = new PrivySignerAdapter();
    this.arc = new ArcChainAdapter();
    this.uniswap = new UniswapV3Venue();
    this.oneInch = new OneInchClassicSwapVenue();
    this.aqua = new AquaSwapVmVenue();
  }

  async describe(
    options: DescribeOptions = {},
  ): Promise<IntegrationDescriptor[]> {
    const descriptors: IntegrationDescriptor[] = [
      {
        id: "ens",
        sponsor: "ENS",
        seam: "NameResolver",
        state: this.ens.isReady() ? "LIVE" : "DORMANT",
        ready: this.ens.isReady(),
        detail: this.ens.isReady()
          ? `ENSv2 resolution on ${this.ens.chainName} via viem's Universal Resolver (${this.ens.universalResolverAddress ?? "chain default"}); resolutions are bound at authorization time so a re-pointed name cannot redirect funds`
          : `Dormant: ${
              env.ensEnabled
                ? `ENS_ENABLED is set but no RPC URL for ${this.ens.chainName}`
                : "ENS_ENABLED is false"
            }`,
        enabledBy: ["ENS_ENABLED", "ENS_CHAIN", "RPC_URL_SEPOLIA"],
        dataSource: this.ens.source,
        verifiedAgainst: [
          "https://docs.ens.domains/learn/deployments/",
          "https://docs.ens.domains/resolvers/universal/",
          "https://docs.ens.domains/ensv2/overview/",
        ],
      },
      {
        id: "graph",
        sponsor: "The Graph",
        seam: "RiskSignalProvider",
        state: this.graph.mode === "LIVE" ? "LIVE" : "FIXTURES",
        ready: this.graph.isReady(),
        detail: this.graph.readinessDetail(),
        enabledBy: ["GRAPH_API_KEY", "GRAPH_TOKEN_API_URL"],
        dataSource: this.graph.source,
        verifiedAgainst: [
          "https://thegraph.com/docs/en/token-api/quick-start/",
          "https://app.pinax.network/docs/api/",
        ],
      },
      {
        id: "x402",
        sponsor: "Hedera / x402",
        seam: "paid-resource gate + agent payer",
        state: this.x402.isReady() ? "LIVE" : "DORMANT",
        ready: this.x402.isReady(),
        detail: this.x402.readinessDetail(),
        enabledBy: [
          "X402_ENABLED",
          "X402_PAY_TO",
          "X402_NETWORK",
          "X402_PRICE_USDC",
          "X402_FACILITATOR_URL",
        ],
        dataSource: `x402-v1:${this.x402.settlementMode}`,
        verifiedAgainst: [
          "https://github.com/coinbase/x402/blob/main/specs/x402-specification-v1.md",
          "https://github.com/coinbase/x402/blob/main/specs/transports-v1/http.md",
          "https://docs.x402.org/core-concepts/network-and-token-support",
        ],
      },
      {
        id: "world",
        sponsor: "World",
        seam: "HumanVerifier",
        state: this.world.isReady() ? "LIVE" : "DORMANT",
        ready: this.world.isReady(),
        detail: this.world.readinessDetail(),
        enabledBy: ["WORLD_APP_ID", "WORLD_ACTION"],
        dataSource: "world-selfie-check",
        verifiedAgainst: [
          "https://docs.world.org/world-id/SKILL",
          "https://docs.world.org/world-id/idkit/integrate",
        ],
      },
      {
        id: "privy",
        sponsor: "Privy",
        seam: "SignerAdapter",
        state: this.privy.isReady() ? "LIVE" : "DORMANT",
        ready: this.privy.isReady(),
        detail: this.privy.readinessDetail(),
        enabledBy: ["PRIVY_APP_ID", "PRIVY_APP_SECRET", "PRIVY_WALLET_ID"],
        dataSource: "privy-server-wallet (remote custodial key, not hardware)",
        verifiedAgainst: [
          "https://docs.privy.io/api-reference/wallets/ethereum/eth-sign-transaction",
          "https://docs.privy.io/api-reference/wallets/ethereum/eth-signtypeddata-v4",
          "https://docs.privy.io/controls/policies/example-policies/ethereum",
        ],
      },
      {
        id: "circle-arc",
        sponsor: "Arc / Circle",
        seam: "payment rail",
        // Calldata construction needs no configuration, and it is the part the
        // firewall actually depends on, so this is LIVE without an RPC — but
        // the detail says plainly whether a live chain is reachable.
        state: "LIVE",
        ready: true,
        detail: this.arc.readinessDetail(),
        enabledBy: ["RPC_URL_ARC"],
        dataSource: "arc-testnet-calldata",
        verifiedAgainst: [
          "https://github.com/circlefin/skills/blob/master/plugins/circle/skills/use-arc/SKILL.md",
        ],
      },
      {
        id: "uniswap",
        sponsor: "Uniswap",
        seam: "ExecutionVenue",
        state: this.uniswap.isReady() ? "LIVE" : "DORMANT",
        ready: this.uniswap.isReady(),
        detail: this.uniswap.readinessDetail(),
        enabledBy: ["RPC_URL_ETHEREUM", "RPC_URL_SEPOLIA"],
        dataSource: "uniswap-v3-quoterv2 (on-chain eth_call)",
        verifiedAgainst: [
          "https://developers.uniswap.org/contracts/v3/reference/deployments/ethereum-deployments",
        ],
      },
      {
        id: "oneinch",
        sponsor: "1inch",
        seam: "ExecutionVenue",
        state: this.oneInch.isReady() ? "LIVE" : "DORMANT",
        ready: this.oneInch.isReady(),
        detail: `${this.oneInch.readinessDetail()} Aqua/SwapVM: ${this.aqua.readinessDetail()}`,
        enabledBy: [],
        dataSource: "1inch-classic-swap-v6.1",
        verifiedAgainst: [
          "https://business.1inch.com/portal/documentation/apis/swap/classic-swap/quick-start",
          "https://github.com/1inch/aqua",
        ],
      },
      {
        id: "chainlink-cre",
        sponsor: "Chainlink",
        seam: "confidential policy evaluation",
        // Never anything but DESIGN_SKETCH until a workflow has actually run.
        state: "DESIGN_SKETCH",
        ready: false,
        detail:
          "Design sketch. The confidential policy evaluation is real, deterministic code (src/integrations/chainlink/cre/confidential-policy.ts); the CRE workflow that would host it in a TEE has never been executed, on CRE or in the simulator. See CRE_CONFIDENTIAL_WORKFLOW.md.",
        enabledBy: [],
        dataSource: "LOCAL_UNATTESTED (no TEE attestation exists)",
        verifiedAgainst: [
          "https://docs.chain.link/cre/concepts/confidential-workflows",
          "https://docs.chain.link/cre/reference/project-configuration-ts",
        ],
      },
    ];

    if (options.probe !== true) {
      return descriptors;
    }

    return Promise.all(
      descriptors.map(async (descriptor) => {
        const probe = await this.probeOne(descriptor.id);

        return probe === undefined ? descriptor : { ...descriptor, probe };
      }),
    );
  }

  /** A one-line summary for a log line or a demo banner. */
  async summary(): Promise<{
    live: string[];
    fixtures: string[];
    dormant: string[];
    designSketch: string[];
  }> {
    const descriptors = await this.describe();

    return {
      live: descriptors.filter((d) => d.state === "LIVE").map((d) => d.id),
      fixtures: descriptors
        .filter((d) => d.state === "FIXTURES")
        .map((d) => d.id),
      dormant: descriptors.filter((d) => d.state === "DORMANT").map((d) => d.id),
      designSketch: descriptors
        .filter((d) => d.state === "DESIGN_SKETCH")
        .map((d) => d.id),
    };
  }

  private async probeOne(id: string): Promise<unknown> {
    try {
      if (id === "circle-arc") {
        return await this.arc.probe();
      }

      if (id === "x402") {
        return this.x402.status();
      }

      return undefined;
    } catch (error) {
      // A probe failure is information, not a reason to fail the whole
      // status endpoint.
      return {
        status: "UNAVAILABLE",
        reason: error instanceof Error ? error.message : String(error),
      };
    }
  }
}

/** The singleton `src/api/server.ts` imports. */
export const integrationRegistry = new IntegrationRegistry();
