/**
 * The capability broker.
 *
 * Ledger's own framing for this track is "a broker hands out scoped
 * capabilities, never the API key". This is that broker.
 *
 * The pattern it replaces is an agent holding a long-lived credential. That
 * credential is as powerful as whatever it unlocks, lives as long as it is not
 * rotated, and sits inside a process whose behaviour can be steered by
 * untrusted text. Prompt injection turns "the agent can call the API" into "the
 * attacker can call the API, and can also ask for the key".
 *
 * Instead:
 *
 *   1. An operator seals the upstream secret (`SealedSecretStore`).
 *   2. An agent is issued a **capability token**: short-lived, scoped to one
 *      capability, bound to a hash of the policy in force, and useless for
 *      anything else.
 *   3. When the agent wants the secret used, it asks the broker to perform the
 *      action. The broker validates the token, unseals just-in-time, performs
 *      the call, and returns only the result.
 *
 * The agent therefore never possesses the secret, and cannot disclose what it
 * does not have. The blast radius of a fully compromised agent shrinks from
 * "the credential" to "the actions its token currently authorizes".
 */

import { randomUUID } from "node:crypto";

import { ArxError } from "../core/errors";
import { canonicalize } from "../crypto/canonical";
import { hashCanonical, safeEqual, sha256Hex } from "../crypto/hash";
import { authorizationKey } from "../crypto/authorization-key";
import type { Capability } from "../types/capability";
import { SealedSecretStore, type SealBackend } from "./sealed-secret-store";
import { ringCli } from "./ring-cli";

export type CapabilityToken = {
  tokenId: string;
  capabilityId: string;
  agentId: string;
  /** Which sealed secrets this token may cause to be used. Never the secrets. */
  grants: string[];
  /**
   * Digest of the capability as it stood when the token was issued. If the
   * operator narrows the policy, previously issued tokens stop matching and
   * are refused — authority cannot outlive the policy that justified it.
   */
  policyHash: string;
  issuedAt: number;
  expiresAt: number;
  /** Arx's signature over the binding fields. */
  signature: string;
  keyId: string;
};

/** What the agent is given. Deliberately contains no secret material. */
export type IssuedToken = {
  token: CapabilityToken;
  /** Opaque bearer string the agent presents back. */
  bearer: string;
};

export type BrokeredUse = {
  tokenId: string;
  secretName: string;
  backend: SealBackend;
  hardwareRooted: boolean;
  usedAt: number;
};

function tokenBindingPayload(
  token: Omit<CapabilityToken, "signature" | "keyId">,
) {
  return {
    tokenId: token.tokenId,
    capabilityId: token.capabilityId,
    agentId: token.agentId,
    grants: [...token.grants].sort(),
    policyHash: token.policyHash,
    issuedAt: token.issuedAt,
    expiresAt: token.expiresAt,
  };
}

/**
 * Digest of the authority-bearing fields of a capability.
 *
 * Fields that do not affect what is permitted (a display label) are excluded,
 * so cosmetic edits do not needlessly invalidate live tokens.
 */
export function capabilityPolicyHash(capability: Capability): string {
  return hashCanonical({
    capabilityId: capability.capabilityId,
    agentId: capability.agentId,
    allowedActions: [...capability.allowedActions].sort(),
    allowedProtocols: [...capability.allowedProtocols].sort(),
    allowedChains: [...capability.allowedChains].sort(),
    allowedTokens: {
      input: [...capability.allowedTokens.input].sort(),
      output: [...capability.allowedTokens.output].sort(),
    },
    maxAmountUsd: capability.maxAmountUsd,
    maxSlippageBps: capability.maxSlippageBps,
    recipients: capability.recipients,
    contracts: capability.contracts,
    methods: capability.methods,
    limits: capability.limits,
    humanApproval: capability.humanApproval,
    maxRiskScore: capability.maxRiskScore,
    allowContractCreation: capability.allowContractCreation,
    valueToleranceBps: capability.valueToleranceBps,
    expiresAt: capability.expiresAt,
    usage: capability.usage,
  });
}

export class CapabilityBroker {
  private readonly tokens = new Map<string, CapabilityToken>();
  private readonly uses: BrokeredUse[] = [];

  constructor(
    private readonly secrets: SealedSecretStore = new SealedSecretStore(),
  ) {}

  /**
   * Issues a scoped token. Deliberately short-lived: the token is the agent's
   * whole authority, so its natural state is "about to expire".
   */
  issue(input: {
    capability: Capability;
    grants: string[];
    ttlSeconds?: number;
    now?: number;
  }): IssuedToken {
    const now = input.now ?? Math.floor(Date.now() / 1000);
    const ttl = Math.min(input.ttlSeconds ?? 300, 3600);

    for (const grant of input.grants) {
      if (!this.secrets.has(grant)) {
        throw new ArxError(
          "FORBIDDEN",
          `Cannot grant "${grant}": no such sealed secret`,
        );
      }
    }

    const unsigned = {
      tokenId: randomUUID(),
      capabilityId: input.capability.capabilityId,
      agentId: input.capability.agentId,
      grants: input.grants,
      policyHash: capabilityPolicyHash(input.capability),
      issuedAt: now,
      // A token must never outlive the grant that justified it.
      expiresAt: Math.min(now + ttl, input.capability.expiresAt),
    };

    const token: CapabilityToken = {
      ...unsigned,
      signature: authorizationKey.sign(tokenBindingPayload(unsigned)),
      keyId: authorizationKey.keyId,
    };

    this.tokens.set(token.tokenId, token);

    return {
      token,
      bearer: `arx_ct_${token.tokenId}_${sha256Hex(token.signature).slice(0, 32)}`,
    };
  }

  /** Resolves and fully validates a bearer string. Fails closed. */
  verify(input: {
    bearer: string;
    capability: Capability;
    now?: number;
  }): CapabilityToken {
    const now = input.now ?? Math.floor(Date.now() / 1000);

    const parts = input.bearer.split("_");

    if (parts.length !== 4 || parts[0] !== "arx" || parts[1] !== "ct") {
      throw new ArxError("UNAUTHENTICATED", "Malformed capability token");
    }

    const token = this.tokens.get(parts[2]!);

    if (!token) {
      throw new ArxError("UNAUTHENTICATED", "Unknown capability token");
    }

    // Constant-time, so a wrong guess does not leak how much of it was right.
    if (
      !safeEqual(
        parts[3]!,
        sha256Hex(token.signature).slice(0, 32),
      )
    ) {
      throw new ArxError("UNAUTHENTICATED", "Capability token checksum invalid");
    }

    if (
      !authorizationKey.verify(tokenBindingPayload(token), token.signature)
    ) {
      throw new ArxError(
        "APPROVAL_SIGNATURE_INVALID",
        "Capability token signature does not verify",
      );
    }

    if (now >= token.expiresAt) {
      throw new ArxError("FORBIDDEN", "Capability token has expired");
    }

    if (token.capabilityId !== input.capability.capabilityId) {
      throw new ArxError(
        "FORBIDDEN",
        "Capability token was issued for a different capability",
      );
    }

    if (token.agentId !== input.capability.agentId) {
      throw new ArxError("AGENT_MISMATCH", "Capability token agent mismatch");
    }

    if (input.capability.status !== "ACTIVE") {
      throw new ArxError(
        "CAPABILITY_REVOKED",
        `Capability is ${input.capability.status}`,
      );
    }

    if (token.policyHash !== capabilityPolicyHash(input.capability)) {
      // The operator narrowed the policy after this token was minted. The token
      // encodes authority that is no longer granted, so it is dead.
      throw new ArxError(
        "FORBIDDEN",
        "Capability policy changed after this token was issued; request a new token",
      );
    }

    return token;
  }

  /**
   * Performs an action that needs a sealed secret, without disclosing it.
   *
   * `use` receives the plaintext for the duration of the call only. Its return
   * value is what reaches the agent, so an implementation must not put the
   * secret in it.
   */
  async withSecret<T>(input: {
    bearer: string;
    capability: Capability;
    secretName: string;
    use: (secret: string) => Promise<T>;
    now?: number;
  }): Promise<{ result: T; provenance: BrokeredUse }> {
    const token = this.verify({
      bearer: input.bearer,
      capability: input.capability,
      now: input.now,
    });

    if (!token.grants.includes(input.secretName)) {
      throw new ArxError(
        "FORBIDDEN",
        `Capability token does not grant "${input.secretName}"`,
      );
    }

    const unsealed = await this.secrets.unseal(input.secretName);

    let result: T;

    try {
      result = await input.use(unsealed.secret);
    } finally {
      // There is no way to wipe a JS string, so the design constraint is that
      // the plaintext never escapes this scope and is never persisted. Noting
      // it here because it is a real, accepted limitation rather than an
      // oversight.
    }

    const provenance: BrokeredUse = {
      tokenId: token.tokenId,
      secretName: input.secretName,
      backend: unsealed.backend,
      hardwareRooted: unsealed.hardwareRooted,
      usedAt: input.now ?? Math.floor(Date.now() / 1000),
    };

    this.uses.push(provenance);

    return { result, provenance };
  }

  revoke(tokenId: string): boolean {
    return this.tokens.delete(tokenId);
  }

  /** Live tokens, with no secret material. */
  listTokens(now = Math.floor(Date.now() / 1000)): CapabilityToken[] {
    return [...this.tokens.values()].filter(
      (token) => token.expiresAt > now,
    );
  }

  history(limit = 50): BrokeredUse[] {
    return this.uses.slice(-limit).reverse();
  }

  /** Readiness, for `GET /integrations` and the dashboard. */
  async status() {
    const ring = await ringCli.status();
    const backend = await this.secrets.activeBackend();

    return {
      keyRing: ring,
      sealBackend: backend.backend,
      hardwareRooted: backend.backend === "ledger-keyring",
      sealBackendReason: backend.reason,
      sealedSecrets: this.secrets.list(),
      liveTokens: this.listTokens().length,
    };
  }

  /** Digest of broker configuration, for the audit record. */
  fingerprint(): string {
    return `0x${sha256Hex(
      canonicalize({ secrets: this.secrets.fingerprint() }),
    )}`;
  }
}
