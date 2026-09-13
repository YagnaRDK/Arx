import Fastify from "fastify";
import { randomUUID } from "node:crypto";

import { CapabilityStore } from "../storage/capability-store";
import { ReplayStore } from "../storage/replay-store";
import { AuditStore } from "../storage/audit-store";

import { PolicyEngine } from "../policy/policy-engine";
import { validateCapability, validateIntent } from "../policy/validators";

import { TransactionNormalizer } from "../normalization/transaction-normalizer";
import { TransactionFirewall } from "../firewall/transaction-firewall";

import { MockSignerAdapter } from "../signer/mock-signer";
import { SignerService } from "../signer/signer-service";

import { env } from "../config/env";
import { ApprovalStore } from "../storage/approval-store";
import { ApprovalService } from "../approval/approval-service";

import { SpeculosSignerAdapter } from "../signer/speculos-signer";

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

  const approvalStore = new ApprovalStore();
  const approvalService = new ApprovalService(approvalStore);

  const signerAdapter =
    env.signerMode === "speculos"
      ? new SpeculosSignerAdapter({
          apiUrl: env.speculosApiUrl,
          signerAddress: env.speculosSignerAddress,
        })
      : new MockSignerAdapter();

  const signerService = new SignerService(signerAdapter);

  app.get("/", async () => {
    return {
      service: "Arx Policy Engine",
      status: "operational",
      version: "0.4.0",
    };
  });

  app.get("/signer", async () => {
    return signerService.getSignerInfo();
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

  app.post("/sign", async (request, reply) => {
    const requestId = randomUUID();
    const body = request.body as {
      approvalId?: unknown;
      transaction?: unknown;
    };

    if (typeof body.approvalId !== "string" || !body.approvalId) {
      return reply.code(400).send({
        requestId,
        allowed: false,
        code: "INVALID_APPROVAL",
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

    const transactionValidation = transactionNormalizer.normalize({
      agentId: approval.agentId,
      capabilityId: approval.capabilityId,
      transaction: body.transaction,
    });

    const verification = approvalService.verifyApproval({
      approval,
      transaction: transactionValidation,
    });

    if (!verification.valid) {
      return reply.code(403).send({
        requestId,
        allowed: false,
        code: "APPROVAL_INVALID",
        reason: verification.reason,
      });
    }

    try {
      const signerResult = await signerService.sign(transactionValidation);

      const consumed = approvalStore.consume(approval.approvalId);

      if (!consumed) {
        return reply.code(409).send({
          requestId,
          allowed: false,
          code: "APPROVAL_ALREADY_CONSUMED",
          reason: "Approval could not be consumed",
        });
      }

      return reply.code(200).send({
        requestId,
        status: "SIGNED",
        approvalId: approval.approvalId,
        signer: {
          adapter: signerAdapter.name,
          address: signerResult.signerAddress,
        },
        transactionId: signerResult.transactionId,
        signedTransaction: signerResult.signedTransaction,
      });
    } catch (error) {
      request.log.error(error);

      return reply.code(500).send({
        requestId,
        allowed: false,
        code: "SIGNING_FAILED",
        reason:
          error instanceof Error ? error.message : "Signer adapter failed",
      });
    }
  });

  app.get<{
    Params: {
      approvalId: string;
    };
  }>("/approvals/:approvalId", async (request, reply) => {
    const approval = approvalStore.get(request.params.approvalId);

    if (!approval) {
      return reply.code(404).send({
        error: "APPROVAL_NOT_FOUND",
      });
    }

    return {
      approval,
    };
  });

  app.post("/approvals", async (request, reply) => {
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
        reason: "A transaction is required",
      });
    }

    const capability = capabilityStore.get(intent.capabilityId);

    if (!capability) {
      return reply.code(403).send({
        requestId,
        allowed: false,
        code: "CAPABILITY_NOT_FOUND",
        reason: "Capability does not exist",
      });
    }

    const isReplay = replayStore.hasBeenProcessed(
      intent.capabilityId,
      intent.agentId,
      intent.nonce,
    );

    const policyResult = policyEngine.evaluate(capability, intent, isReplay);

    auditStore.write({
      requestId,
      intent,
      result: policyResult,
    });

    if (!policyResult.allowed) {
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
      return reply.code(400).send({
        requestId,
        allowed: false,
        code: "INVALID_TRANSACTION",
        reason: "Transaction normalization failed",
      });
    }

    if (normalizedTransaction.transaction.chainId !== intent.chainId) {
      return reply.code(403).send({
        requestId,
        allowed: false,
        code: "TRANSACTION_NOT_ALLOWED",
        reason: "Transaction chain does not match intent chain",
      });
    }

    const firewallDecision = transactionFirewall.process(
      normalizedTransaction,
      policyResult,
    );

    if (!firewallDecision.allowed || !firewallDecision.transaction) {
      return reply.code(403).send({
        requestId,
        ...firewallDecision.result,
      });
    }

    const now = Math.floor(Date.now() / 1000);

    const approval = approvalService.createApproval({
      requestId,
      capabilityId: intent.capabilityId,
      agentId: intent.agentId,
      transaction: firewallDecision.transaction,
      expiresAt: Math.min(capability.expiresAt, now + 300),
    });

    replayStore.markProcessed(
      intent.capabilityId,
      intent.agentId,
      intent.nonce,
    );

    if (capability.usage === "SINGLE_USE") {
      capabilityStore.consume(capability.capabilityId);
    }

    return reply.code(201).send({
      requestId,
      status: "APPROVED",
      approval,
    });
  });

  return app;
}
