import { env } from "../config/env";
import { ArxError } from "../core/errors";
import { safeEqual } from "../crypto/hash";

/**
 * Control-plane authentication: a bearer token.
 *
 * The control plane is where authority is *granted* — minting capabilities,
 * resolving escalations, enabling agents. Keeping it on a different credential
 * from the data plane is the whole point: an agent's HMAC secret must not open
 * any route that can widen the agent's own authority (invariant 11). That is
 * why this is a separate token and not a scope on the agent credential.
 */

export type AdminIdentity = {
  readonly plane: "CONTROL";
  /** Who to record as the actor on control-plane writes. */
  readonly subject: string;
  /**
   * `TOKEN` — a configured token was presented and matched.
   * `OPEN`  — no token is configured, so the control plane is unauthenticated.
   */
  readonly mode: "TOKEN" | "OPEN";
  readonly authenticated: boolean;
};

export const ADMIN_HEADER = "x-arx-admin-token";

export class AdminAuthenticator {
  constructor(private readonly token: string = env.adminToken) {}

  /** True when a token is configured, i.e. the control plane is closed. */
  get configured(): boolean {
    return this.token.trim().length > 0;
  }

  /**
   * The warning the server should log at boot when the control plane is open.
   * Returned rather than logged here so the transport owns its own output —
   * but it must be surfaced: an unauthenticated control plane means anyone who
   * can reach the port can grant themselves authority, which is a
   * development-only posture.
   */
  warning(): string | null {
    if (this.configured) {
      return null;
    }

    return (
      "ARX_ADMIN_TOKEN is not set: the control plane is UNAUTHENTICATED. " +
      "Any process that can reach this port can mint capabilities and resolve " +
      "escalations. Set ARX_ADMIN_TOKEN before running outside a local demo."
    );
  }

  /**
   * Resolves a control-plane identity, or throws.
   *
   * When no token is configured this allows the request and reports
   * `mode: "OPEN"`, so the response and the audit trail both show that the
   * action was taken without authentication. It never silently looks
   * authenticated.
   */
  authenticate(headers: Record<string, unknown>): AdminIdentity {
    const presented = readAdminToken(headers);

    if (!this.configured) {
      return {
        plane: "CONTROL",
        subject: "operator:unauthenticated",
        mode: "OPEN",
        authenticated: false,
      };
    }

    if (!presented) {
      throw new ArxError(
        "UNAUTHENTICATED",
        "Control-plane routes require an admin bearer token",
      );
    }

    if (!safeEqual(presented, this.token)) {
      throw new ArxError("FORBIDDEN", "Admin token is not valid");
    }

    return {
      plane: "CONTROL",
      // The token is a shared operator credential, so there is no richer
      // identity to record. A per-operator credential would be the upgrade.
      subject: "operator:admin-token",
      mode: "TOKEN",
      authenticated: true,
    };
  }
}

function readAdminToken(
  headers: Record<string, unknown>,
): string | undefined {
  const authorization = headerValue(headers, "authorization");

  if (authorization) {
    const match = /^Bearer\s+(.+)$/i.exec(authorization.trim());

    if (match?.[1]) {
      return match[1].trim();
    }
  }

  return headerValue(headers, ADMIN_HEADER)?.trim();
}

function headerValue(
  headers: Record<string, unknown>,
  name: string,
): string | undefined {
  const raw =
    headers[name] ??
    Object.entries(headers).find(
      ([key]) => key.toLowerCase() === name.toLowerCase(),
    )?.[1];

  if (typeof raw === "string") {
    return raw.length > 0 ? raw : undefined;
  }

  if (Array.isArray(raw) && typeof raw[0] === "string") {
    return raw[0].length > 0 ? raw[0] : undefined;
  }

  return undefined;
}
