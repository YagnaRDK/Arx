function readPort(): number {
  const port = Number(process.env.PORT ?? 3000);

  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error("PORT must be a valid TCP port");
  }

  return port;
}

function readNumber(name: string, fallback: number): number {
  const raw = process.env[name];

  if (raw === undefined || raw === "") {
    return fallback;
  }

  const value = Number(raw);

  if (!Number.isFinite(value)) {
    throw new Error(`${name} must be a number`);
  }

  return value;
}

function readBoolean(name: string, fallback: boolean): boolean {
  const raw = process.env[name];

  if (raw === undefined || raw === "") {
    return fallback;
  }

  return raw === "1" || raw.toLowerCase() === "true";
}

const SIGNER_MODES = ["mock", "sim", "speculos", "dmk", "privy"] as const;
export type SignerMode = (typeof SIGNER_MODES)[number];

function readSignerMode(): SignerMode {
  const raw = (process.env.SIGNER_MODE ?? "mock") as SignerMode;

  if (!SIGNER_MODES.includes(raw)) {
    throw new Error(
      `SIGNER_MODE must be one of: ${SIGNER_MODES.join(", ")} (got "${raw}")`,
    );
  }

  return raw;
}

export const env = {
  nodeEnv: process.env.NODE_ENV ?? "development",
  port: readPort(),
  databasePath: process.env.DATABASE_PATH ?? "./data/arx.sqlite",

  /**
   * `mock` is the default so a clean clone runs the full demo with no hardware.
   * `sim` produces a real secp256k1 signature over the real RLP through the
   * real APDU codec, keyed from the published Speculos test mnemonic — the
   * device is simulated, the cryptography is not.
   * The mode is reported on every signing response and on `/signer` so a mock
   * result can never be mistaken for a device-backed one.
   */
  signerMode: readSignerMode(),

  signerDerivationPath: process.env.SIGNER_DERIVATION_PATH ?? "44'/60'/0'/0/0",

  speculosApiUrl: process.env.SPECULOS_API_URL ?? "http://127.0.0.1:5000",
  speculosApduHost: process.env.SPECULOS_APDU_HOST ?? "127.0.0.1",
  speculosApduPort: readNumber("SPECULOS_APDU_PORT", 9999),
  /**
   * Speculos transport. `http` posts APDUs to the REST API; `tcp` speaks the
   * raw length-prefixed APDU socket.
   */
  speculosTransport: (process.env.SPECULOS_TRANSPORT ?? "http") as
    | "http"
    | "tcp",
  /** Auto-press the device's confirm button. Demo convenience only. */
  speculosAutoApprove: readBoolean("SPECULOS_AUTO_APPROVE", false),

  /**
   * Arx's authorization key. Signs approval artifacts so the signer boundary can
   * verify Arx authorized a transaction, independently of the database row.
   * Generated ephemerally at boot if unset, which means approvals do not survive
   * a restart — fine for a demo, not for production.
   */
  authorizationKeyPem: process.env.ARX_AUTHORIZATION_KEY_PEM ?? "",

  /** Control plane. Absent in development leaves capability routes open. */
  adminToken: process.env.ARX_ADMIN_TOKEN ?? "",
  /** Require HMAC authentication on agent-facing routes. */
  requireAgentAuth: readBoolean("ARX_REQUIRE_AGENT_AUTH", false),
  /** Maximum accepted clock skew on a signed request, in seconds. */
  maxClockSkewSeconds: readNumber("ARX_MAX_CLOCK_SKEW_SECONDS", 300),

  approvalTtlSeconds: readNumber("ARX_APPROVAL_TTL_SECONDS", 300),
  humanApprovalTtlSeconds: readNumber("ARX_HUMAN_APPROVAL_TTL_SECONDS", 900),

  // --- Integrations. Every one is optional; absent means the adapter reports
  // itself unavailable rather than silently returning a permissive result.
  rpcUrls: {
    ethereum: process.env.RPC_URL_ETHEREUM ?? "",
    sepolia: process.env.RPC_URL_SEPOLIA ?? "",
    arc: process.env.RPC_URL_ARC ?? "",
    hedera: process.env.RPC_URL_HEDERA ?? "",
  },

  priceOracleMode: (process.env.PRICE_ORACLE_MODE ?? "static") as
    | "static"
    | "chainlink",
  priceMaxAgeSeconds: readNumber("PRICE_MAX_AGE_SECONDS", 3600),

  ensEnabled: readBoolean("ENS_ENABLED", false),
  ensChain: (process.env.ENS_CHAIN ?? "sepolia") as "sepolia" | "mainnet",

  graphApiKey: process.env.GRAPH_API_KEY ?? "",
  /**
   * The Graph's hosted Token API. `token-api.thegraph.com` no longer serves —
   * its TLS handshake fails and the docs redirect to Pinax — so the default
   * points at the operator that now hosts it.
   */
  graphTokenApiUrl:
    process.env.GRAPH_TOKEN_API_URL ?? "https://api.pinax.network",

  x402Enabled: readBoolean("X402_ENABLED", false),
  x402PayTo: process.env.X402_PAY_TO ?? "",
  x402Network: process.env.X402_NETWORK ?? "hedera-testnet",
  x402PriceUsdc: process.env.X402_PRICE_USDC ?? "0.01",
  x402FacilitatorUrl: process.env.X402_FACILITATOR_URL ?? "",
  /**
   * Serve a paid request when no facilitator can settle it.
   *
   * The gate refuses by default: accepting a payment it cannot verify as
   * settled would make the paywall decorative. Enabling this is an explicit
   * operator choice for a demo, never a fallback Arx takes on its own.
   */
  x402AllowUnsettledPayments: readBoolean("X402_ALLOW_UNSETTLED_PAYMENTS", false),
  /** Local demo key for the x402 payer. Never a production posture. */
  x402PayerPrivateKey: process.env.X402_PAYER_PRIVATE_KEY ?? "",

  worldAppId: process.env.WORLD_APP_ID ?? "",
  worldAction: process.env.WORLD_ACTION ?? "arx-high-risk-approval",
  /** World documents rp_id separately from app_id; they are not always equal. */
  worldRpId: process.env.WORLD_RP_ID ?? "",

  privyAppId: process.env.PRIVY_APP_ID ?? "",
  privyAppSecret: process.env.PRIVY_APP_SECRET ?? "",
  privyWalletId: process.env.PRIVY_WALLET_ID ?? "",

  oneInchApiKey: process.env.ONEINCH_API_KEY ?? "",
  oneInchAquaRouter: process.env.ONEINCH_AQUA_ROUTER ?? "",
  oneInchAquaChainId: readNumber("ONEINCH_AQUA_CHAIN_ID", 0),

  dashboardEnabled: readBoolean("ARX_DASHBOARD", true),
} as const;

export function isProduction(): boolean {
  return env.nodeEnv === "production";
}
