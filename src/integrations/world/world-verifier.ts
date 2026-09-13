/**
 * World ID Selfie Check as a `HumanVerifier`.
 *
 * Where this sits in the pipeline matters. Arx already escalates a high-risk
 * proposal to a human, and the Ledger device already proves *a* human pressed a
 * button. Neither proves a *unique, real* person approved: a device can be left
 * confirming in a loop, and an agent operator can stand up as many
 * pseudonymous approvers as they like. Selfie Check closes that gap — it proves
 * proof-of-personhood, bound to a specific action, with a nullifier that Arx
 * can refuse to see twice.
 *
 * So the strong claim is the conjunction, and `combineHumanFactors` below is
 * deliberately shaped so neither factor can stand in for the other:
 *
 *   personhood (World) AND device confirmation (Ledger) -> authorized
 *
 * Verification is server-side only. A client-side "verified: true" is a claim
 * by the agent's own process, which is the one thing Arx never trusts.
 *
 * Sources (fetched 2026-09-12):
 *   - backend verification route `POST https://developer.world.org/api/v4/verify/{rp_id}`,
 *     "Forward the IDKit result payload as-is. No field remapping is required.",
 *     payload fields `protocol_version`, `nonce`, `action`, `environment`,
 *     `responses[]` (each with `identifier`, `proof`, `nullifier`,
 *     `merkle_root`, `issuer_schema_id`), and Selfie Check being identified by
 *     `responses[].identifier === "selfie"`:
 *       https://docs.world.org/world-id/SKILL
 *       https://docs.world.org/world-id/idkit/integrate
 *   - `rp_id` is the relying-party id and is distinct from the Developer Portal
 *     `app_id`, per the same SKILL page.
 *
 * NOT verified: the exact success-response body. The documentation states only
 * that success is signalled by a 2xx and failure by a 400 with an
 * `invalid_proof` / `verification_failed` / `not_registered` code. This adapter
 * therefore treats the HTTP status as authoritative and records whatever body
 * came back as evidence, rather than asserting a field shape it could not
 * confirm.
 */

import { z } from "zod";

import { env } from "../../config/env";
import {
  ok,
  unavailable,
  type Availability,
  type HumanVerification,
  type HumanVerifier,
} from "../../core/seams";
import { claimOnce } from "../cache";
import { requestJson } from "../http";

const DEFAULT_VERIFY_BASE = "https://developer.world.org";

/** Selfie Check's response identifier, per the World docs. */
const SELFIE_IDENTIFIER = "selfie";

/**
 * How long a proof's nullifier is held against replay. A proof is bound to one
 * approval; re-presenting it is a replay, not a second approval by the same
 * person.
 */
const NULLIFIER_CLAIM_TTL_SECONDS = 3_600;

/**
 * Loose on purpose. World versions this payload (`protocol_version` 3.0 and
 * 4.0 carry different response members) and the documented instruction is to
 * forward it unmodified, so Arx validates only what it must reason about and
 * passes the rest through untouched. Over-validating here would reject valid
 * future proofs; under-validating would let Arx skip the action check. The
 * middle is: require the fields Arx enforces, allow everything else.
 */
const IdkitResponseSchema = z.object({
  identifier: z.string().optional(),
  nullifier: z.string().optional(),
  session_nullifier: z.string().optional(),
  merkle_root: z.string().optional(),
  issuer_schema_id: z.string().optional(),
});

const IdkitPayloadSchema = z
  .object({
    protocol_version: z.string().optional(),
    nonce: z.string().optional(),
    action: z.string().optional(),
    environment: z.string().optional(),
    signal: z.string().optional(),
    responses: z.array(IdkitResponseSchema).optional(),
  })
  .loose();

export type IdkitPayload = z.infer<typeof IdkitPayloadSchema>;

/**
 * What Arx accepts as `proof` on the seam: either the bare IDKit payload, or
 * the payload wrapped alongside `expectedSignal` — what the human was shown.
 * Arx checks the signal matches the approval it is about to release, so a proof
 * captured for a $5 payment cannot be replayed against a $50,000 one.
 */
const ProofEnvelopeSchema = z.object({
  idkit: z.unknown(),
  expectedSignal: z.string().min(1).optional(),
});

export type WorldVerificationOutcome =
  | { status: "VERIFIED"; verification: HumanVerification }
  | {
      /** The proof was evaluated and is not acceptable. Definite, not an outage. */
      status: "REJECTED";
      code:
        | "MALFORMED_PROOF"
        | "ACTION_MISMATCH"
        | "SIGNAL_MISMATCH"
        | "NOT_SELFIE_CHECK"
        | "NULLIFIER_REPLAYED"
        | "REJECTED_BY_WORLD";
      reason: string;
      evidence?: Record<string, unknown>;
    }
  | {
      /** Arx could not establish whether the proof is good. */
      status: "UNAVAILABLE";
      reason: string;
      retryable: boolean;
    };

export type WorldVerifierOptions = {
  appId?: string;
  /**
   * Relying-party id for the verification route. Distinct from `app_id` in the
   * World docs; there is no `WORLD_RP_ID` in `src/config/env.ts` yet, so
   * `WORLD_APP_ID` is used as a fallback and the substitution is reported.
   */
  rpId?: string;
  action?: string;
  baseUrl?: string;
  /** Require `responses[].identifier === "selfie"`. On by default. */
  requireSelfieCheck?: boolean;
  now?: () => number;
  timeoutMs?: number;
};

export class WorldSelfieCheckVerifier implements HumanVerifier {
  readonly name = "world-selfie-check";

  readonly action: string;
  readonly baseUrl: string;

  private readonly appId: string;
  private readonly explicitRpId: string;
  private readonly requireSelfie: boolean;
  private readonly now: () => number;
  private readonly timeoutMs: number;

  constructor(options: WorldVerifierOptions = {}) {
    this.appId = options.appId ?? env.worldAppId;
    this.explicitRpId = options.rpId ?? "";
    this.action = options.action ?? env.worldAction;
    this.baseUrl = (options.baseUrl ?? DEFAULT_VERIFY_BASE).replace(/\/+$/, "");
    this.requireSelfie = options.requireSelfieCheck ?? true;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
    this.timeoutMs = options.timeoutMs ?? 8_000;
  }

  get rpId(): string {
    return this.explicitRpId.length > 0 ? this.explicitRpId : this.appId;
  }

  isReady(): boolean {
    return this.rpId.length > 0 && this.action.length > 0;
  }

  readinessDetail(): string {
    if (this.rpId.length === 0) {
      return "WORLD_APP_ID is unset, so there is no relying party to verify against";
    }

    if (this.explicitRpId.length === 0) {
      return `Using WORLD_APP_ID as the verification rp_id (World documents rp_id as distinct from app_id; add a WORLD_RP_ID env var if they differ for your app). Action "${this.action}".`;
    }

    return `rp_id ${this.rpId}, action "${this.action}"`;
  }

  /**
   * Seam entry point. An unacceptable proof comes back as non-retryable
   * `UNAVAILABLE` rather than a successful `HumanVerification`, because the
   * seam's success value means "a real, unique human approved this" and nothing
   * weaker may be allowed to occupy it. Use `verifyDetailed` when the caller
   * needs to tell "proof rejected" apart from "World unreachable".
   */
  async verify(proof: unknown): Promise<Availability<HumanVerification>> {
    const outcome = await this.verifyDetailed(proof);

    if (outcome.status === "VERIFIED") {
      return ok(outcome.verification);
    }

    if (outcome.status === "REJECTED") {
      return unavailable<HumanVerification>(
        `World Selfie Check rejected the proof (${outcome.code}): ${outcome.reason}`,
        false,
      );
    }

    return unavailable<HumanVerification>(outcome.reason, outcome.retryable);
  }

  async verifyDetailed(proof: unknown): Promise<WorldVerificationOutcome> {
    if (!this.isReady()) {
      return {
        status: "UNAVAILABLE",
        reason: `World Selfie Check is not configured: ${this.readinessDetail()}`,
        retryable: false,
      };
    }

    const envelope = ProofEnvelopeSchema.safeParse(proof);
    const wrapped =
      envelope.success && envelope.data.idkit !== undefined
        ? envelope.data
        : null;
    const parsedPayload = IdkitPayloadSchema.safeParse(
      wrapped === null ? proof : wrapped.idkit,
    );

    if (!parsedPayload.success) {
      return {
        status: "REJECTED",
        code: "MALFORMED_PROOF",
        reason: "Proof is not a recognizable IDKit payload",
      };
    }

    const payload = parsedPayload.data;
    const expectedSignal = wrapped?.expectedSignal;

    // Action binding. Without this check a proof produced for a harmless
    // action would authorize a dangerous one, which is the classic World ID
    // integration mistake.
    if (payload.action !== undefined && payload.action !== this.action) {
      return {
        status: "REJECTED",
        code: "ACTION_MISMATCH",
        reason: `Proof is for action "${payload.action}", not "${this.action}"`,
      };
    }

    if (
      expectedSignal !== undefined &&
      payload.signal !== undefined &&
      payload.signal !== expectedSignal
    ) {
      return {
        status: "REJECTED",
        code: "SIGNAL_MISMATCH",
        reason:
          "Proof is bound to a different signal than the approval being released",
        evidence: { proofSignal: payload.signal, expectedSignal },
      };
    }

    const responses = payload.responses ?? [];
    const selfie = responses.find(
      (response) => response.identifier === SELFIE_IDENTIFIER,
    );

    if (this.requireSelfie && selfie === undefined) {
      return {
        status: "REJECTED",
        code: "NOT_SELFIE_CHECK",
        reason: `No responses[] entry with identifier "${SELFIE_IDENTIFIER}"; this proof is not a Selfie Check result`,
        evidence: {
          identifiers: responses.map((response) => response.identifier ?? null),
        },
      };
    }

    const nullifier =
      selfie?.nullifier ??
      selfie?.session_nullifier ??
      responses[0]?.nullifier ??
      responses[0]?.session_nullifier;

    if (typeof nullifier !== "string" || nullifier.length === 0) {
      return {
        status: "REJECTED",
        code: "MALFORMED_PROOF",
        reason: "Proof carries no nullifier, so it cannot be replay-protected",
      };
    }

    // Forwarded byte-for-byte: the documentation is explicit that the payload
    // must not be mutated, re-encoded or trimmed, because the proof is bound to
    // its own serialization.
    const response = await requestJson<unknown>({
      url: `${this.baseUrl}/api/v4/verify/${encodeURIComponent(this.rpId)}`,
      method: "POST",
      body: payload,
      timeoutMs: this.timeoutMs,
      expectStatuses: [400, 401, 403, 404, 422],
    });

    if (!response.ok) {
      return {
        status: "UNAVAILABLE",
        reason: `World verification endpoint unreachable: ${response.failure.message}`,
        retryable:
          response.failure.kind === "TIMEOUT" ||
          response.failure.kind === "NETWORK",
      };
    }

    if (response.status >= 400) {
      return {
        status: "REJECTED",
        code: "REJECTED_BY_WORLD",
        reason: `World returned HTTP ${response.status}`,
        evidence: { body: response.value },
      };
    }

    // Nullifier replay is checked only after World has accepted the proof, so
    // a rejected proof cannot burn a legitimate nullifier.
    const claim = claimOnce({
      key: `world:nullifier:${this.action}:${nullifier.toLowerCase()}:${expectedSignal ?? ""}`,
      source: "world-selfie-check",
      now: this.now(),
      ttlSeconds: NULLIFIER_CLAIM_TTL_SECONDS,
    });

    if (!claim.claimed) {
      return {
        status: "REJECTED",
        code: "NULLIFIER_REPLAYED",
        reason:
          "This proof's nullifier has already been used for this action; a proof authorizes exactly one approval",
      };
    }

    return {
      status: "VERIFIED",
      verification: {
        factor: "world-selfie-check",
        // The nullifier is the subject: it is unique per person per action and
        // carries no personal detail, which is exactly what an audit log should
        // hold instead of a biometric or a name.
        subject: nullifier,
        verifiedAt: this.now(),
        evidence: {
          action: this.action,
          rpId: this.rpId,
          protocolVersion: payload.protocol_version ?? null,
          environment: payload.environment ?? null,
          identifier: selfie?.identifier ?? null,
          issuerSchemaId: selfie?.issuer_schema_id ?? null,
          ...(expectedSignal === undefined ? {} : { signal: expectedSignal }),
          verifiedBy: `${this.baseUrl}/api/v4/verify/${this.rpId}`,
        },
      },
    };
  }
}

export type HumanFactorVerdict = {
  satisfied: boolean;
  factors: string[];
  missing: string[];
  reason: string;
};

/**
 * The conjunction rule. Proof-of-personhood and a device confirmation answer
 * different questions — "is this a unique real human?" and "did the key holder
 * physically consent to *these exact bytes*?" — so one can never substitute for
 * the other. Written as an explicit AND rather than a score so it cannot drift
 * into a threshold that a single factor can clear.
 */
export function combineHumanFactors(input: {
  personhood?: HumanVerification;
  deviceConfirmation?: { confirmed: boolean; detail?: string };
  requirePersonhood: boolean;
  requireDeviceConfirmation: boolean;
}): HumanFactorVerdict {
  const factors: string[] = [];
  const missing: string[] = [];

  if (input.requirePersonhood) {
    if (input.personhood === undefined) {
      missing.push("proof-of-personhood");
    } else {
      factors.push(input.personhood.factor);
    }
  }

  if (input.requireDeviceConfirmation) {
    if (input.deviceConfirmation?.confirmed !== true) {
      missing.push("device-confirmation");
    } else {
      factors.push("device-confirmation");
    }
  }

  const satisfied = missing.length === 0;

  return {
    satisfied,
    factors,
    missing,
    reason: satisfied
      ? `Satisfied by: ${factors.join(" AND ")}`
      : `Missing required factor(s): ${missing.join(", ")}`,
  };
}
