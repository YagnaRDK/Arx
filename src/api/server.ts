import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";

import { env } from "../config/env";
import { ArxError, isArxError } from "../core/errors";
import { httpStatusForCode } from "../core/codes";

import { CapabilityStore } from "../storage/capability-store";
import { ReplayStore } from "../storage/replay-store";
import { AuditStore } from "../storage/audit-store";
import { ApprovalStore } from "../storage/approval-store";
import { SpendStore } from "../storage/spend-store";
import { AgentStore } from "../storage/agent-store";
import { IdempotencyStore, hashIntentBody } from "../storage/idempotency-store";

import { PolicyEngine, POLICY_VERSION } from "../policy/policy-engine";
import { validateCapability, validateIntent } from "../policy/validators";
import { TransactionNormalizer } from "../normalization/transaction-normalizer";
import { TransactionFirewall } from "../firewall/transaction-firewall";

import { ApprovalService } from "../approval/approval-service";
import { HumanApprovalQueue } from "../approval/human-approval";
import { ApprovalExpirySweeper } from "../approval/expiry-sweeper";

import { createSignerService } from "../signer/signer-factory";
import { createPriceOracle } from "../oracle/price-oracle";
import { createAuthMiddleware, sendArxError } from "../auth/middleware";
import { AgentAuthenticator } from "../auth/agent-auth";
import { AdminAuthenticator } from "../auth/admin-auth";

import { CapabilityBroker } from "../broker/capability-broker";
import { SealedSecretStore } from "../broker/sealed-secret-store";

import { intentIdentityPayload } from "../types/intent";
import { AuthorizationPipeline } from "./pipeline";
import { eventBus } from "./events";

const SERVICE_VERSION = "1.0.0";

/**
 * Optional adapters are loaded lazily so a missing or broken one cannot stop the
 * boot. The specifier is held in a variable deliberately: the registry is an
 * optional module, and a static import would make the build depend on a file
 * that is absent when no integration is configured.
 */
type LoadedRegistry = {
  describe: (options?: unknown) => Promise<unknown>;
  ens?: unknown;
  graph?: unknown;
};

async function loadIntegrationRegistry(): Promise<LoadedRegistry | null> {
  const specifier = "../integrations/registry";

  try {
    const module = (await import(specifier)) as {
      integrationRegistry?: LoadedRegistry;
    };

    return module.integrationRegistry ?? null;
  } catch {
    return null;
  }
}

export async function buildServer() {
  const app = Fastify({
    logger: { level: env.nodeEnv === "test" ? "silent" : "info" },
    // Arx is an authorization layer: a request body large enough to be a DoS
    // vector has no legitimate shape here.
    bodyLimit: 1_000_000,
  });

  // ── Stores ────────────────────────────────────────────────────────────────
  const capabilityStore = new CapabilityStore();
  const replayStore = new ReplayStore();
  const auditStore = new AuditStore();
  const approvalStore = new ApprovalStore();
  const spendStore = new SpendStore();
  const agentStore = new AgentStore();
  const idempotencyStore = new IdempotencyStore();

  // ── Decision layer ────────────────────────────────────────────────────────
  const policyEngine = new PolicyEngine();
  const normalizer = new TransactionNormalizer();
  const priceOracle = createPriceOracle({ mode: env.priceOracleMode });

  const integrationRegistry = await loadIntegrationRegistry();

  /*
   * ENS and The Graph are wired into the firewall itself, not bolted alongside
   * it. That is what makes them load-bearing: an allowlist entry written as an
   * ENS name is resolved during authorization, and recipient reputation feeds
   * the risk score that decides escalation. Both adapters report their own
   * readiness and return "could not check" rather than a clean result when
   * their data source is unreachable, so an outage cannot widen what is
   * permitted.
   */
  const firewall = new TransactionFirewall({
    priceOracle,
    spendStore,
    ...(integrationRegistry?.ens
      ? { nameResolver: integrationRegistry.ens as never }
      : {}),
    ...(integrationRegistry?.graph
      ? { riskProviders: [integrationRegistry.graph as never] }
      : {}),
  });

  const pipeline = new AuthorizationPipeline({
    capabilityStore,
    replayStore,
    auditStore,
    policyEngine,
    normalizer,
    firewall,
    maxClockSkewSeconds: env.maxClockSkewSeconds,
  });

  // ── Approval layer ────────────────────────────────────────────────────────
  const approvalService = new ApprovalService(approvalStore);

  const humanApprovalQueue = new HumanApprovalQueue({
    approvalStore,
    spendStore,
    auditStore,
  });

  const expirySweeper = new ApprovalExpirySweeper({
    approvalStore,
    spendStore,
    auditStore,
  });

  // ── Signer boundary ───────────────────────────────────────────────────────
  const signerService = createSignerService(env.signerMode);

  // ── Capability broker ─────────────────────────────────────────────────────
  const sealedSecrets = new SealedSecretStore();
  const broker = new CapabilityBroker(sealedSecrets);

  // ── Auth ──────────────────────────────────────────────────────────────────
  const auth = createAuthMiddleware({
    agentAuthenticator: new AgentAuthenticator(agentStore),
    adminAuthenticator: new AdminAuthenticator(),
  });

  /**
   * An unauthenticated control plane means anything that can reach the port can
   * grant itself unlimited authority, which defeats the entire premise. It is
   * allowed for local development, but never silently.
   */
  if (!env.adminToken && env.nodeEnv !== "test") {
    app.log.warn(
      "ARX_ADMIN_TOKEN is unset: the control plane is OPEN. Anything that can reach this port can mint capabilities. Set it before exposing Arx beyond localhost.",
    );
  }

  if (!env.authorizationKeyPem && env.nodeEnv !== "test") {
    app.log.warn(
      "ARX_AUTHORIZATION_KEY_PEM is unset: an ephemeral approval-signing key was generated, so approvals will not survive a restart.",
    );
  }

  app.setErrorHandler((error, request, reply) => {
    if (isArxError(error)) {
      return sendArxError(reply, error);
    }

    request.log.error(error);

    return reply.code(500).send({
      allowed: false,
      code: "INTERNAL_ERROR",
      reason: "An unexpected error occurred",
    });
  });

  // ── Static dashboard ──────────────────────────────────────────────────────
  const publicDir = resolve(process.cwd(), "public");

  if (env.dashboardEnabled && existsSync(resolve(publicDir, "index.html"))) {
    const fastifyStatic = await import("@fastify/static");

    await app.register(fastifyStatic.default, {
      root: publicDir,
      prefix: "/",
    });
  } else {
    app.get("/", async () => ({
      service: "Arx",
      tagline:
        "The agent proposes. Arx authorizes. The device signs.",
      version: SERVICE_VERSION,
      policyVersion: POLICY_VERSION,
      status: "operational",
    }));
  }

  // ── Observability ─────────────────────────────────────────────────────────
  app.get("/health", async () => {
    const chain = auditStore.verifyChain();

    return {
      status: "ok",
      version: SERVICE_VERSION,
      policyVersion: POLICY_VERSION,
      signerMode: env.signerMode,
      databasePath: env.databasePath,
      auditChain: chain.valid
        ? { valid: true, entries: chain.entries }
        : { valid: false, brokenAtSeq: chain.brokenAtSeq, problem: chain.problem },
    };
  });

  app.get("/signer", async () => {
    const info = await signerService.getSignerInfo();

    return {
      ...info,
      mode: env.signerMode,
      derivationPath: env.signerDerivationPath,
      // Restated at the boundary so a caller cannot miss it.
      warning:
        info.signatureType === "MOCK"
          ? "MOCK signer: output is not a blockchain signature and must never be broadcast."
          : undefined,
    };
  });

  app.get("/integrations", { preHandler: auth.requireReader() }, async (request) => {
    const brokerStatus = await broker.status();
    const query = request.query as { probe?: string };

    // `describe()` makes no outbound calls unless asked, so the default
    // response is fast and offline. `?probe=1` performs the live checks.
    const adapters = integrationRegistry
      ? await integrationRegistry.describe(
          query.probe === "1" ? { probe: true } : undefined,
        )
      : [];

    return {
      signer: {
        mode: env.signerMode,
        ...(await signerService.getSignerInfo()),
      },
      priceOracle: {
        name: priceOracle.name,
        ready: priceOracle.isReady(),
        mode: env.priceOracleMode,
      },
      keyRing: brokerStatus.keyRing,
      sealBackend: {
        backend: brokerStatus.sealBackend,
        hardwareRooted: brokerStatus.hardwareRooted,
        reason: brokerStatus.sealBackendReason,
      },
      adapters,
    };
  });

  app.get("/events/stream", async (request, reply) => {
    reply.raw.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    });

    const send = (event: { seq: number; type: string; at: number; data: unknown }) => {
      reply.raw.write(`id: ${event.seq}\n`);
      reply.raw.write(`event: ${event.type}\n`);
      reply.raw.write(`data: ${JSON.stringify(event)}\n\n`);
    };

    // Replay recent events so a freshly opened dashboard is not blank.
    for (const event of eventBus.backlog()) {
      send(event);
    }

    const unsubscribe = eventBus.subscribe(send);
    const heartbeat = setInterval(() => reply.raw.write(": ping\n\n"), 15_000);

    request.raw.on("close", () => {
      clearInterval(heartbeat);
      unsubscribe();
    });
  });

  // ── Capabilities (control plane) ──────────────────────────────────────────
  app.post(
    "/capabilities",
    { preHandler: auth.requireAdmin() },
    async (request, reply) => {
      const validation = validateCapability(request.body);

      if (!validation.success) {
        return reply.code(400).send({
          allowed: false,
          code: "INVALID_CAPABILITY",
          reason: "Capability validation failed",
          details: validation.error.flatten(),
        });
      }

      const capability = validation.data;

      if (capabilityStore.get(capability.capabilityId)) {
        return reply.code(409).send({
          allowed: false,
          code: "CAPABILITY_ALREADY_EXISTS",
          reason: `Capability "${capability.capabilityId}" already exists`,
        });
      }

      capabilityStore.create(capability);

      auditStore.append({
        eventType: "CAPABILITY_CREATED",
        capabilityId: capability.capabilityId,
        agentId: capability.agentId,
        reason: capability.label ?? "capability granted",
        payload: {
          maxAmountUsd: capability.maxAmountUsd,
          recipients: capability.recipients,
          usage: capability.usage,
          expiresAt: capability.expiresAt,
        },
      });

      eventBus.publish("capability.created", {
        capabilityId: capability.capabilityId,
        agentId: capability.agentId,
      });

      return reply.code(201).send({ capability });
    },
  );

  app.get("/capabilities", { preHandler: auth.requireReader() }, async (request) => {
    const query = request.query as { agentId?: string; limit?: string };
    const limit = Math.min(Number(query.limit ?? 100) || 100, 500);

    return {
      capabilities: query.agentId
        ? capabilityStore.listByAgent(query.agentId, limit)
        : capabilityStore.list(limit),
    };
  });

  app.get<{ Params: { capabilityId: string } }>(
    "/capabilities/:capabilityId",
    async (request, reply) => {
      const capability = capabilityStore.get(request.params.capabilityId);

      if (!capability) {
        return reply.code(404).send({
          allowed: false,
          code: "CAPABILITY_NOT_FOUND",
          reason: "Capability does not exist",
        });
      }

      const usage = spendStore.usage(
        capability.capabilityId,
        capability.limits.windowSeconds,
      );

      return { capability, spendWindow: usage };
    },
  );

  app.post<{ Params: { capabilityId: string } }>(
    "/capabilities/:capabilityId/revoke",
    { preHandler: auth.requireAdmin() },
    async (request, reply) => {
      const revoked = capabilityStore.revoke(request.params.capabilityId);

      if (!revoked) {
        return reply.code(404).send({
          allowed: false,
          code: "CAPABILITY_NOT_FOUND",
          reason: "Capability does not exist or is not active",
        });
      }

      auditStore.append({
        eventType: "CAPABILITY_REVOKED",
        capabilityId: request.params.capabilityId,
        reason: "revoked by operator",
      });

      eventBus.publish("capability.revoked", {
        capabilityId: request.params.capabilityId,
      });

      return { capabilityId: request.params.capabilityId, status: "REVOKED" };
    },
  );

  // ── Evaluation ────────────────────────────────────────────────────────────

  /** Parses and validates an intent body, throwing a specific ArxError. */
  function parseIntent(body: unknown) {
    const validation = validateIntent(body);

    if (!validation.success) {
      throw new ArxError("INVALID_INTENT", "Intent validation failed", {
        details: validation.error.flatten(),
      });
    }

    return validation.data;
  }

  app.post(
    "/evaluate",
    { preHandler: auth.requireAgent() },
    async (request, reply) => {
      const requestId = randomUUID();
      const intent = parseIntent(request.body);

      const outcome = await pipeline.evaluate({
        requestId,
        intent,
        requireTransaction: false,
      });

      if (outcome.kind === "REJECTED") {
        const status = outcome.result.allowed
          ? 200
          : httpStatusForCode(outcome.result.code);

        return reply.code(status).send({ requestId, ...outcome.result });
      }

      return reply.code(outcome.decision.allowed ? 200 : 403).send({
        requestId,
        ...outcome.decision.result,
        decision: outcome.decision.decision,
        riskScore: outcome.decision.riskScore,
      });
    },
  );

  app.post(
    "/firewall/submit",
    { preHandler: auth.requireAgent() },
    async (request, reply) => {
      const requestId = randomUUID();
      const intent = parseIntent(request.body);

      const signerInfo = await signerService.getSignerInfo();

      const outcome = await pipeline.evaluate({
        requestId,
        intent,
        requireTransaction: true,
        signerAddress: signerInfo.address,
      });

      if (outcome.kind === "REJECTED") {
        return reply
          .code(httpStatusForCode(outcome.result.code))
          .send({ requestId, ...outcome.result });
      }

      const { decision, transaction } = outcome;

      // A dry run: it reports what would happen and consumes no authority.
      return reply.code(decision.allowed ? 200 : httpStatusForCode(decision.result.code)).send({
        requestId,
        status: decision.allowed
          ? "READY_FOR_APPROVAL"
          : decision.decision === "ESCALATE"
            ? "REQUIRES_HUMAN_APPROVAL"
            : "BLOCKED",
        decision: decision.decision,
        ...decision.result,
        transactionId: transaction.transactionId,
        transaction: transaction.transaction,
        findings: decision.findings,
        riskScore: decision.riskScore,
        riskSignals: decision.riskSignals,
        valueUsd: decision.valueUsd,
        declaredValueUsd: decision.declaredValueUsd,
        valuePriced: decision.valuePriced,
        decodedCall: decision.decodedCall ?? null,
        note: "Evaluation only. No approval was created and no authority was consumed.",
      });
    },
  );

  // ── Approvals ─────────────────────────────────────────────────────────────
  app.post(
    "/approvals",
    { preHandler: auth.requireAgent() },
    async (request, reply) => {
      const requestId = randomUUID();
      const intent = parseIntent(request.body);

      // Idempotency: a retried request must replay its original decision rather
      // than mint a second authorization.
      const intentHash = hashIntentBody(intentIdentityPayload(intent));

      if (intent.intentId) {
        const existing = idempotencyStore.begin(
          intent.capabilityId,
          intent.intentId,
          intentHash,
        );

        if (existing.kind === "REPLAY") {
          /*
           * The original decision, replayed. No second approval exists and no
           * further authority was consumed, so a retried request — or an agent
           * talked into submitting the same payment twice — cannot pay twice.
           *
           * The marker goes in the body as well as the header: a client reading
           * only the body could otherwise not distinguish a replayed decision
           * from a fresh authorization, and in an authorization layer that
           * ambiguity is itself a defect.
           */
          return reply
            .code(existing.status)
            .header("x-arx-idempotent-replay", "true")
            .send({
              ...(existing.body as Record<string, unknown>),
              idempotentReplay: true,
              idempotencyNote:
                "This is the original decision for this intentId, replayed. No new approval was created and no additional authority was consumed.",
            });
        }

        if (existing.kind === "CONFLICT") {
          return reply.code(409).send({
            requestId,
            allowed: false,
            code: "INTENT_ID_CONFLICT",
            reason:
              "This intentId was already used with a different payload. Use a new intentId for a new action.",
          });
        }
      }

      const finish = (status: number, body: Record<string, unknown>) => {
        if (intent.intentId) {
          idempotencyStore.complete(
            intent.capabilityId,
            intent.intentId,
            status,
            body,
          );
        }

        return reply.code(status).send(body);
      };

      const signerInfo = await signerService.getSignerInfo();

      const outcome = await pipeline.evaluate({
        requestId,
        intent,
        requireTransaction: true,
        signerAddress: signerInfo.address,
      });

      if (outcome.kind === "REJECTED") {
        return finish(httpStatusForCode(outcome.result.code), {
          requestId,
          ...outcome.result,
        });
      }

      const { decision, transaction, capability } = outcome;

      // Nothing mints an approval from a denial.
      if (decision.decision !== "ALLOW" && decision.decision !== "ESCALATE") {
        return finish(httpStatusForCode(decision.result.code), {
          requestId,
          ...decision.result,
          decision: decision.decision,
          findings: decision.findings,
          riskScore: decision.riskScore,
          riskSignals: decision.riskSignals,
        });
      }

      const replayed = pipeline.commitAuthority({ intent, capability });

      if (replayed) {
        return finish(httpStatusForCode(replayed.code), {
          requestId,
          ...replayed,
        });
      }

      const approval = approvalService.createApproval({
        requestId,
        capabilityId: intent.capabilityId,
        agentId: intent.agentId,
        transaction,
        decision: decision.result.allowed
          ? decision.result
          : { ...decision.result, decision: decision.decision },
        capabilityExpiresAt: capability.expiresAt,
        valueUsd: decision.valueUsd,
        riskScore: decision.riskScore,
        // So an operator reviewing an escalation can see who is being paid,
        // including a payee that only appears inside the calldata.
        summary: {
          to: transaction.transaction.to ?? null,
          valueWei: transaction.transaction.value,
          chainId: transaction.transaction.chainId,
          selector:
            transaction.transaction.data.length >= 10
              ? transaction.transaction.data.slice(0, 10)
              : null,
          method: decision.decodedCall?.signature ?? null,
          calldataRecipients: decision.decodedCall?.recipients ?? [],
        },
      });

      // Reserve the spend now: an outstanding approval is authority already
      // granted, and counting only signatures would let an agent stockpile
      // approvals against a one-transaction budget.
      spendStore.reserve({
        capabilityId: approval.capabilityId,
        agentId: approval.agentId,
        approvalId: approval.approvalId,
        amountUsd: decision.valueUsd,
        valueWei: transaction.transaction.value,
      });

      auditStore.append({
        eventType:
          approval.status === "PENDING_HUMAN"
            ? "HUMAN_APPROVAL_REQUESTED"
            : "APPROVAL_CREATED",
        requestId,
        capabilityId: approval.capabilityId,
        agentId: approval.agentId,
        approvalId: approval.approvalId,
        transactionId: approval.transactionId,
        decision: decision.decision,
        code: approval.policyCode,
        reason: approval.reason,
        payload: {
          transactionHash: approval.transactionHash,
          expiresAt: approval.expiresAt,
          riskScore: approval.riskScore,
          valueUsd: approval.valueUsd,
        },
      });

      eventBus.publish(
        approval.status === "PENDING_HUMAN"
          ? "approval.pending_human"
          : "approval.created",
        {
          requestId,
          approvalId: approval.approvalId,
          status: approval.status,
          riskScore: approval.riskScore,
          valueUsd: approval.valueUsd,
          to: transaction.transaction.to ?? null,
          reason: approval.reason,
        },
      );

      return finish(approval.status === "PENDING_HUMAN" ? 202 : 201, {
        requestId,
        status: approval.status,
        decision: decision.decision,
        approval,
        findings: decision.findings,
        riskScore: decision.riskScore,
        riskSignals: decision.riskSignals,
        valueUsd: decision.valueUsd,
        declaredValueUsd: decision.declaredValueUsd,
        decodedCall: decision.decodedCall ?? null,
      });
    },
  );

  /** The escalation queue, which is what the human approval UI reads. */
  app.get("/approvals/pending", { preHandler: auth.requireReader() }, async () => ({
    approvals: humanApprovalQueue.listPending(),
  }));

  app.get("/approvals", { preHandler: auth.requireReader() }, async (request) => {
    const query = request.query as { status?: string; limit?: string };
    const limit = Math.min(Number(query.limit ?? 100) || 100, 500);

    return {
      approvals: query.status
        ? approvalStore.listByStatus(
            query.status as Parameters<typeof approvalStore.listByStatus>[0],
            limit,
          )
        : approvalStore.list(limit),
      authorizationKey: approvalService.authorizationKeyInfo(),
    };
  });

  app.get<{ Params: { approvalId: string } }>(
    "/approvals/:approvalId",
    { preHandler: auth.requireReader() },
    async (request, reply) => {
      const approval = approvalStore.get(request.params.approvalId);

      if (!approval) {
        return reply.code(404).send({
          allowed: false,
          code: "APPROVAL_NOT_FOUND",
          reason: "Approval does not exist",
        });
      }

      return { approval, trail: auditStore.byRequest(approval.requestId) };
    },
  );

  /**
   * Resolving an escalation is a control-plane action.
   *
   * If an agent could approve its own escalation, escalation would be
   * decoration. The admin credential is what makes the human gate real.
   */
  app.post<{ Params: { approvalId: string } }>(
    "/approvals/:approvalId/approve",
    { preHandler: auth.requireAdmin() },
    async (request, reply) => {
      const body = (request.body ?? {}) as { decidedBy?: string };

      const approval = humanApprovalQueue.approve(
        request.params.approvalId,
        body.decidedBy ?? "operator",
      );

      eventBus.publish("approval.human_granted", {
        approvalId: approval.approvalId,
        decidedBy: approval.decidedBy ?? "operator",
      });

      return { approval, status: approval.status };
    },
  );

  app.post<{ Params: { approvalId: string } }>(
    "/approvals/:approvalId/reject",
    { preHandler: auth.requireAdmin() },
    async (request, reply) => {
      const body = (request.body ?? {}) as {
        decidedBy?: string;
        reason?: string;
      };

      // The queue releases the spend reservation itself, so a rejection does
      // not consume the agent's budget.
      const approval = humanApprovalQueue.reject(
        request.params.approvalId,
        body.decidedBy ?? "operator",
        body.reason ?? "rejected by operator",
      );

      eventBus.publish("approval.human_denied", {
        approvalId: approval.approvalId,
        decidedBy: approval.decidedBy ?? "operator",
        reason: body.reason,
      });

      return { approval, status: approval.status };
    },
  );

  // ── Signing ───────────────────────────────────────────────────────────────
  app.post(
    "/sign",
    { preHandler: auth.requireAgent({ bindBodyAgentId: false }) },
    async (request, reply) => {
      const requestId = randomUUID();
      const body = (request.body ?? {}) as {
        approvalId?: unknown;
        transaction?: unknown;
      };

      if (typeof body.approvalId !== "string" || !body.approvalId) {
        return reply.code(400).send({
          requestId,
          allowed: false,
          code: "APPROVAL_INVALID",
          reason: "approvalId is required",
        });
      }

      const approval = approvalStore.get(body.approvalId);

      if (!approval) {
        return reply.code(404).send({
          requestId,
          allowed: false,
          code: "APPROVAL_NOT_FOUND",
          reason: "Approval does not exist",
        });
      }

      // Re-normalize the transaction the caller is presenting *now*. The
      // approval is bound to a hash, so a mutated transaction cannot match.
      let transaction;

      try {
        transaction = normalizer.normalize({
          agentId: approval.agentId,
          capabilityId: approval.capabilityId,
          transaction: body.transaction,
        });
      } catch (error) {
        const arx = isArxError(error)
          ? error
          : new ArxError("INVALID_TRANSACTION", "Transaction is not valid");

        return reply.code(arx.status).send({ requestId, ...arx.toJSON() });
      }

      const verification = approvalService.verifyApproval({
        approval,
        transaction,
      });

      if (!verification.valid) {
        auditStore.append({
          eventType: "SIGNING_REFUSED",
          requestId,
          approvalId: approval.approvalId,
          agentId: approval.agentId,
          capabilityId: approval.capabilityId,
          transactionId: transaction.transactionId,
          decision: "DENY",
          code: verification.code,
          reason: verification.reason,
        });

        eventBus.publish("signing.refused", {
          requestId,
          approvalId: approval.approvalId,
          code: verification.code,
          reason: verification.reason,
        });

        return reply.code(httpStatusForCode(verification.code)).send({
          requestId,
          allowed: false,
          code: verification.code,
          reason: verification.reason,
        });
      }

      // The capability may have been revoked after the approval was issued.
      const capability = capabilityStore.get(approval.capabilityId);

      if (!capability || capability.status !== "ACTIVE") {
        const code = capability ? "CAPABILITY_REVOKED" : "CAPABILITY_NOT_FOUND";

        auditStore.append({
          eventType: "SIGNING_REFUSED",
          requestId,
          approvalId: approval.approvalId,
          decision: "DENY",
          code,
          reason: "Capability is no longer active",
        });

        return reply.code(403).send({
          requestId,
          allowed: false,
          code,
          reason:
            "The granting capability is no longer active, so this approval can no longer be used",
        });
      }

      /*
       * Claim the approval atomically BEFORE the signer is touched.
       *
       * This is the fix for the double-sign race. `claimForSigning` is a
       * compare-and-swap from APPROVED to SIGNING, so of two concurrent
       * requests exactly one proceeds. Signing first and consuming afterwards —
       * as the previous implementation did — leaves a window in which both
       * callers obtain a signature.
       */
      if (!approvalService.claimForSigning(approval.approvalId)) {
        return reply.code(409).send({
          requestId,
          allowed: false,
          code: "APPROVAL_ALREADY_CONSUMED",
          reason:
            "This approval was claimed for signing by another request. An approval authorizes exactly one signature.",
        });
      }

      auditStore.append({
        eventType: "SIGNING_STARTED",
        requestId,
        approvalId: approval.approvalId,
        agentId: approval.agentId,
        capabilityId: approval.capabilityId,
        transactionId: transaction.transactionId,
        reason: `signer=${env.signerMode}`,
      });

      eventBus.publish("signing.started", {
        requestId,
        approvalId: approval.approvalId,
        signerMode: env.signerMode,
      });

      try {
        const signerResult = await signerService.sign(transaction);

        approvalService.markSigned(approval.approvalId);
        spendStore.settle(approval.approvalId);

        auditStore.append({
          eventType: "SIGNING_SUCCEEDED",
          requestId,
          approvalId: approval.approvalId,
          agentId: approval.agentId,
          capabilityId: approval.capabilityId,
          transactionId: transaction.transactionId,
          decision: "ALLOW",
          code: "POLICY_APPROVED",
          reason: `signatureType=${signerResult.signatureType} verified=${signerResult.verified}`,
          payload: {
            signerAddress: signerResult.signerAddress,
            signatureType: signerResult.signatureType,
            verified: signerResult.verified,
            deviceScreens: signerResult.deviceScreens ?? null,
          },
        });

        eventBus.publish("signing.succeeded", {
          requestId,
          approvalId: approval.approvalId,
          signatureType: signerResult.signatureType,
          verified: signerResult.verified,
          signerAddress: signerResult.signerAddress,
          deviceScreens: signerResult.deviceScreens ?? null,
        });

        return reply.code(200).send({
          requestId,
          status: "SIGNED",
          approvalId: approval.approvalId,
          signer: {
            adapter: signerResult.adapter,
            mode: env.signerMode,
            address: signerResult.signerAddress,
            derivationPath: signerResult.derivationPath,
          },
          transactionId: signerResult.transactionId,
          signedTransaction: signerResult.signedTransaction,
          signatureType: signerResult.signatureType,
          /** True only when the signature was cryptographically recovered to the device address. */
          signatureVerified: signerResult.verified,
          signature:
            signerResult.signatureType === "REAL"
              ? { r: signerResult.r, s: signerResult.s, v: signerResult.v, yParity: signerResult.yParity }
              : undefined,
          deviceScreens: signerResult.deviceScreens,
          warning:
            signerResult.signatureType === "MOCK"
              ? "MOCK signature. Not a valid blockchain signature; do not broadcast."
              : undefined,
        });
      } catch (error) {
        // Terminal: a failed attempt is never retryable with the same approval.
        approvalService.markSigningFailed(approval.approvalId);
        spendStore.release(approval.approvalId);

        const arx = isArxError(error)
          ? error
          : new ArxError(
              "SIGNING_FAILED",
              error instanceof Error ? error.message : "Signer adapter failed",
            );

        auditStore.append({
          eventType: "SIGNING_FAILED",
          requestId,
          approvalId: approval.approvalId,
          agentId: approval.agentId,
          capabilityId: approval.capabilityId,
          transactionId: transaction.transactionId,
          decision: "DENY",
          code: arx.code,
          reason: arx.message,
        });

        eventBus.publish("signing.failed", {
          requestId,
          approvalId: approval.approvalId,
          code: arx.code,
          reason: arx.message,
        });

        return reply.code(arx.status).send({ requestId, ...arx.toJSON() });
      }
    },
  );

  // ── Audit ─────────────────────────────────────────────────────────────────
  app.get("/audit", { preHandler: auth.requireReader() }, async (request) => {
    const query = request.query as { limit?: string };
    const limit = Math.min(Number(query.limit ?? 100) || 100, 1000);

    return { head: auditStore.head(), entries: auditStore.list(limit) };
  });

  app.get("/audit/verify", { preHandler: auth.requireReader() }, async () => {
    const result = auditStore.verifyChain();

    return {
      ...result,
      explanation: result.valid
        ? "Every entry's hash recomputes and links to its predecessor. No decision has been altered or removed."
        : "The chain is broken: a historical entry was altered, removed, or inserted.",
    };
  });

  app.get<{ Params: { requestId: string } }>(
    "/audit/:requestId",
    { preHandler: auth.requireReader() },
    async (request) => ({
      requestId: request.params.requestId,
      trail: auditStore.byRequest(request.params.requestId),
    }),
  );

  // ── Broker (control plane) ────────────────────────────────────────────────
  app.get(
    "/broker/status",
    { preHandler: auth.requireReader() },
    async () => broker.status(),
  );

  app.post(
    "/broker/secrets",
    { preHandler: auth.requireAdmin() },
    async (request, reply) => {
      const body = (request.body ?? {}) as { name?: string; secret?: string };

      if (!body.name || !body.secret) {
        return reply.code(400).send({
          allowed: false,
          code: "INVALID_INTENT",
          reason: "name and secret are required",
        });
      }

      const sealed = await sealedSecrets.seal({
        name: body.name,
        secret: body.secret,
      });

      // The response deliberately omits the ciphertext as well as the secret.
      return reply.code(201).send({
        name: sealed.name,
        backend: sealed.backend,
        hardwareRooted: sealed.backend === "ledger-keyring",
        keyName: sealed.keyName,
        createdAt: sealed.createdAt,
      });
    },
  );

  app.post(
    "/broker/tokens",
    { preHandler: auth.requireAdmin() },
    async (request, reply) => {
      const body = (request.body ?? {}) as {
        capabilityId?: string;
        grants?: string[];
        ttlSeconds?: number;
      };

      const capability = body.capabilityId
        ? capabilityStore.get(body.capabilityId)
        : null;

      if (!capability) {
        return reply.code(404).send({
          allowed: false,
          code: "CAPABILITY_NOT_FOUND",
          reason: "Capability does not exist",
        });
      }

      const issued = broker.issue({
        capability,
        grants: body.grants ?? [],
        ttlSeconds: body.ttlSeconds,
      });

      return reply.code(201).send(issued);
    },
  );

  // ── Agents (control plane) ────────────────────────────────────────────────
  app.post(
    "/agents",
    { preHandler: auth.requireAdmin() },
    async (request, reply) => {
      const body = (request.body ?? {}) as { agentId?: string; label?: string };

      if (!body.agentId) {
        return reply.code(400).send({
          allowed: false,
          code: "INVALID_INTENT",
          reason: "agentId is required",
        });
      }

      // The secret is returned exactly once and cannot be recovered later.
      return reply
        .code(201)
        .send(agentStore.register({ agentId: body.agentId, label: body.label }));
    },
  );

  app.get(
    "/agents",
    { preHandler: auth.requireReader() },
    async () => ({ agents: agentStore.list() }),
  );

  app.post<{ Params: { agentId: string } }>(
    "/agents/:agentId/enable",
    { preHandler: auth.requireAdmin() },
    async (request, reply) => {
      if (!agentStore.setEnabled(request.params.agentId, true)) {
        return reply.code(404).send({
          allowed: false,
          code: "AGENT_NOT_FOUND",
          reason: "Agent does not exist",
        });
      }

      return { agentId: request.params.agentId, enabled: true };
    },
  );

  app.post<{ Params: { agentId: string } }>(
    "/agents/:agentId/disable",
    { preHandler: auth.requireAdmin() },
    async (request, reply) => {
      if (!agentStore.setEnabled(request.params.agentId, false)) {
        return reply.code(404).send({
          allowed: false,
          code: "AGENT_NOT_FOUND",
          reason: "Agent does not exist",
        });
      }

      // Disabling revokes the agent's ability to authenticate. It does not
      // revoke approvals already issued — those expire or are revoked
      // individually, so a disable is not silently retroactive.
      return { agentId: request.params.agentId, enabled: false };
    },
  );

  /** Read-only price probe, so a viewer can see which oracle answered. */
  app.get("/oracle/price", async (request, reply) => {
    const query = request.query as { asset?: string; chainId?: string };
    const asset = (query.asset ?? "ETH").toUpperCase();
    const chainId = Number(query.chainId ?? 1) || 1;

    const quote = await priceOracle.getUsdPrice(asset, chainId);

    if (quote.status !== "OK") {
      return reply.code(503).send({
        allowed: false,
        code: "PRICE_UNAVAILABLE",
        reason: quote.reason,
        asset,
        chainId,
      });
    }

    return { ...quote.value, chainId };
  });

  // Sweeping expired approvals is a background concern, not a request concern.
  if (env.nodeEnv !== "test") {
    expirySweeper.start();
    app.addHook("onClose", async () => expirySweeper.stop());
  }

  return app;
}

export type ArxServer = Awaited<ReturnType<typeof buildServer>>;
