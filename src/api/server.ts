import Fastify from "fastify";
import { randomUUID } from "node:crypto";

import { CapabilityStore } from "../storage/capability-store";
import { ReplayStore } from "../storage/replay-store";
import { AuditStore } from "../storage/audit-store";
import { PolicyEngine } from "../policy/policy-engine";
import { validateCapability, validateIntent } from "../policy/validators";
import { TransactionNormalizer } from "../normalization/transaction-normalizer";
import { TransactionFirewall } from "../firewall/transaction-firewall";

export function buildServer() {
  const app = Fastify({
    logger: true,
  });

  const capabilityStore = new CapabilityStore();
  const replayStore = new ReplayStore();
  const auditStore = new AuditStore();
  const policyEngine = new PolicyEngine();
  const transactionNormalizer = new TransactionNormalizer();
  const transactionFirewall = new TransactionFirewall();

  app.get("/", async () => {
    return {
      service: "Arx Policy Engine",
      status: "operational",
      version: "0.3.0",
    };
  });

  app.post("/capabilities", async (request, reply) => {
    const validation = validateCapability(request.body);

    if (!validation.success) {
      return reply.code(400).send({
        error: "INVALID_CAPABILITY",
        details: validation.error.flatten(),
      });
    }

    try {
      const capability = capabilityStore.create(validation.data);

      return reply.code(201).send({
        capability,
      });
    } catch (error) {
      request.log.error(error);

      return reply.code(409).send({
        error: "CAPABILITY_ALREADY_EXISTS",
      });
    }
  });

  app.get<{
    Params: {
      capabilityId: string;
    };
  }>("/capabilities/:capabilityId", async (request, reply) => {
    const capability = capabilityStore.get(request.params.capabilityId);

    if (!capability) {
      return reply.code(404).send({
        error: "CAPABILITY_NOT_FOUND",
      });
    }

    return {
      capability,
    };
  });

  app.post<{
    Params: {
      capabilityId: string;
    };
  }>("/capabilities/:capabilityId/revoke", async (request, reply) => {
    const revoked = capabilityStore.revoke(request.params.capabilityId);

    if (!revoked) {
      return reply.code(404).send({
        error: "CAPABILITY_NOT_FOUND_OR_INACTIVE",
      });
    }

    return {
      capabilityId: request.params.capabilityId,
      status: "REVOKED",
    };
  });

  app.post("/evaluate", async (request, reply) => {
    const requestId = randomUUID();
    const validation = validateIntent(request.body);

    if (!validation.success) {
      return reply.code(400).send({
        requestId,
        allowed: false,
        code: "INVALID_INTENT",
        reason: "Intent validation failed",
        details: validation.error.flatten(),
      });
    }

    const intent = validation.data;
    const capability = capabilityStore.get(intent.capabilityId);

    if (!capability) {
      const result = {
        allowed: false,
        code: "CAPABILITY_NOT_FOUND" as const,
        reason: "Capability does not exist",
      };

      auditStore.write({
        requestId,
        intent,
        result,
      });

      return reply.code(403).send({
        requestId,
        ...result,
      });
    }

    const isReplay = replayStore.hasBeenProcessed(
      intent.capabilityId,
      intent.agentId,
      intent.nonce,
    );

    const result = policyEngine.evaluate(capability, intent, isReplay);

    auditStore.write({
      requestId,
      intent,
      result,
    });

    if (!result.allowed) {
      return reply.code(403).send({
        requestId,
        ...result,
      });
    }

    replayStore.markProcessed(
      intent.capabilityId,
      intent.agentId,
      intent.nonce,
    );

    if (capability.usage === "SINGLE_USE") {
      capabilityStore.consume(capability.capabilityId);
    }

    return reply.code(200).send({
      requestId,
      ...result,
    });
  });

  app.post("/firewall/submit", async (request, reply) => {
    const requestId = randomUUID();
    const validation = validateIntent(request.body);

    if (!validation.success) {
      return reply.code(400).send({
        requestId,
        allowed: false,
        code: "INVALID_INTENT",
        reason: "Intent validation failed",
        details: validation.error.flatten(),
      });
    }

    const intent = validation.data;

    if (!intent.transaction) {
      return reply.code(400).send({
        requestId,
        allowed: false,
        code: "INVALID_TRANSACTION",
        reason: "A transaction is required for firewall submission",
      });
    }

    const capability = capabilityStore.get(intent.capabilityId);

    if (!capability) {
      const result = {
        allowed: false,
        code: "CAPABILITY_NOT_FOUND" as const,
        reason: "Capability does not exist",
      };

      auditStore.write({
        requestId,
        intent,
        result,
      });

      return reply.code(403).send({
        requestId,
        ...result,
      });
    }

    const isReplay = replayStore.hasBeenProcessed(
      intent.capabilityId,
      intent.agentId,
      intent.nonce,
    );

    const policyResult = policyEngine.evaluate(capability, intent, isReplay);

    if (!policyResult.allowed) {
      auditStore.write({
        requestId,
        intent,
        result: policyResult,
      });

      return reply.code(403).send({
        requestId,
        ...policyResult,
      });
    }

    let normalizedTransaction;

    try {
      normalizedTransaction = transactionNormalizer.normalize({
        agentId: intent.agentId,
        capabilityId: intent.capabilityId,
        transaction: intent.transaction,
      });
    } catch {
      const result = {
        allowed: false,
        code: "INVALID_TRANSACTION" as const,
        reason: "Transaction normalization failed",
      };

      auditStore.write({
        requestId,
        intent,
        result,
      });

      return reply.code(400).send({
        requestId,
        ...result,
      });
    }

    if (normalizedTransaction.transaction.chainId !== intent.chainId) {
      const result = {
        allowed: false,
        code: "TRANSACTION_NOT_ALLOWED" as const,
        reason: "Transaction chain does not match intent chain",
      };

      auditStore.write({
        requestId,
        intent,
        result,
      });

      return reply.code(403).send({
        requestId,
        ...result,
      });
    }

    const firewallDecision = transactionFirewall.process(
      normalizedTransaction,
      policyResult,
    );

    if (!firewallDecision.allowed) {
      return reply.code(403).send({
        requestId,
        ...firewallDecision.result,
      });
    }

    replayStore.markProcessed(
      intent.capabilityId,
      intent.agentId,
      intent.nonce,
    );

    if (capability.usage === "SINGLE_USE") {
      capabilityStore.consume(capability.capabilityId);
    }

    return reply.code(200).send({
      requestId,
      status: "READY_FOR_SIGNING",
      transactionId: normalizedTransaction.transactionId,
      policy: policyResult,
      transaction: normalizedTransaction.transaction,
    });
  });

  return app;
}
