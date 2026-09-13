import type { FastifyReply, FastifyRequest } from "fastify";

import { env } from "../config/env";
import { ArxError, isArxError } from "../core/errors";
import { AgentAuthenticator, type AuthenticatedAgent } from "./agent-auth";
import { AdminAuthenticator, type AdminIdentity } from "./admin-auth";

/**
 * Fastify `preHandler` factories for the two planes.
 *
 * Both throw `ArxError`, so the server needs one error handler that maps an
 * `ArxError` onto `error.status` and `error.toJSON()` — see `sendArxError`.
 * Throwing rather than replying keeps the decision code attached to the error
 * all the way to the audit layer.
 */

declare module "fastify" {
  interface FastifyRequest {
    /** Set by `requireAgent` once an agent's HMAC signature verifies. */
    arxAgent?: AuthenticatedAgent;
    /** Set by `requireAdmin`. `mode: "OPEN"` means no token was configured. */
    arxAdmin?: AdminIdentity;
  }
}

export type AuthMiddlewareDependencies = {
  agentAuthenticator: AgentAuthenticator;
  adminAuthenticator: AdminAuthenticator;
};

export type RequireAgentOptions = {
  /**
   * Whether unauthenticated requests are refused. Defaults to
   * `env.requireAgentAuth` so the demo runs open and production can be locked
   * down with `ARX_REQUIRE_AGENT_AUTH=1`.
   *
   * Note what "open" does *not* mean: if credentials are presented, they are
   * always verified, and a bad signature is always a rejection. Open mode only
   * tolerates their absence.
   */
  enforce?: boolean;
  /**
   * Cross-check the authenticated agent against `body.agentId`. Leave on for
   * any route that exercises a capability.
   */
  bindBodyAgentId?: boolean;
};

export function createAuthMiddleware(
  dependencies: AuthMiddlewareDependencies,
) {
  const { agentAuthenticator, adminAuthenticator } = dependencies;

  /**
   * Control plane. Granting authority — capabilities, escalation decisions,
   * agent registration — goes behind this and never behind `requireAgent`.
   */
  function requireAdmin() {
    return async function adminPreHandler(
      request: FastifyRequest,
      _reply: FastifyReply,
    ): Promise<void> {
      request.arxAdmin = adminAuthenticator.authenticate(
        request.headers as Record<string, unknown>,
      );
    };
  }

  /**
   * Data plane. Verifies the HMAC signature and, critically, that the
   * authenticated agent is the agent named in the body: without that check,
   * agent A could authenticate as itself and then exercise agent B's
   * capability, and per-agent least privilege would be decorative.
   */
  function requireAgent(options: RequireAgentOptions = {}) {
    const enforce = options.enforce ?? env.requireAgentAuth;
    const bindBodyAgentId = options.bindBodyAgentId ?? true;

    return async function agentPreHandler(
      request: FastifyRequest,
      _reply: FastifyReply,
    ): Promise<void> {
      const headers = request.headers as Record<string, unknown>;
      const present = AgentAuthenticator.hasCredentials(headers);

      if (!present) {
        if (enforce) {
          throw new ArxError(
            "UNAUTHENTICATED",
            "Agent authentication is required",
          );
        }

        // Open posture: no identity to bind. The route still cannot escape its
        // capability, because the capability — not the transport — is what
        // bounds authority.
        return;
      }

      const identity = agentAuthenticator.authenticate({
        method: request.method,
        // `request.url` is the path plus query string exactly as received,
        // which is what the client signed.
        path: request.url,
        headers,
        body: request.body,
      });

      request.arxAgent = identity;

      if (!bindBodyAgentId) {
        return;
      }

      const claimedAgentId = readBodyAgentId(request.body);

      if (claimedAgentId && claimedAgentId !== identity.agentId) {
        throw new ArxError(
          "FORBIDDEN",
          "Authenticated agent does not match the agentId in the request",
          {
            details: {
              authenticatedAgentId: identity.agentId,
              requestedAgentId: claimedAgentId,
            },
          },
        );
      }

      if (!claimedAgentId && enforce) {
        // Fail closed: an enforced route whose body omits `agentId` cannot be
        // bound to the caller, so it must not proceed.
        throw new ArxError(
          "FORBIDDEN",
          "Request body must name the agentId it acts as",
        );
      }
    };
  }

  return { requireAdmin, requireAgent };
}

/**
 * Maps a thrown error onto an Arx response. Intended for
 * `app.setErrorHandler`, which the server must install for the middleware's
 * thrown errors to surface with the right status and decision code.
 */
export function sendArxError(reply: FastifyReply, error: unknown): FastifyReply {
  if (isArxError(error)) {
    return reply.code(error.status).send(error.toJSON());
  }

  return reply.code(500).send({
    allowed: false,
    code: "INTERNAL_ERROR",
    reason: "Unhandled error",
  });
}

function readBodyAgentId(body: unknown): string | undefined {
  if (!body || typeof body !== "object") {
    return undefined;
  }

  const candidate = (body as { agentId?: unknown }).agentId;

  return typeof candidate === "string" && candidate.length > 0
    ? candidate
    : undefined;
}
