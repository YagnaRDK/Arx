import Fastify from "fastify";

// import { CapabilitySchema } from "../types/capability";
// import { IntentSchema } from "../types/intent";

import { PolicyEngine } from "../policy/policy-engine";
import { validateCapability, validateIntent } from "../policy/validators";

import { CapabilityStore } from "../storage/capability-store";
import { ReplayStore } from "../storage/replay-store";

export function buildServer() {
  const app = Fastify({
    logger: true,
  });

  const capabilityStore = new CapabilityStore();
  const replayStore = new ReplayStore();
  const policyEngine = new PolicyEngine();

  app.get("/", async () => {
    return {
      name: "Arx Policy Engine",
      status: "running",
    };
  });

  app.post("/capabilities", async (request, reply) => {
    const validation = validateCapability(request.body);

    if (!validation.success) {
      return reply.status(400).send({
        error: "INVALID_CAPABILITY",
        details: validation.errors,
      });
    }

    try {
      const capability = capabilityStore.create(validation.data);

      return reply.status(201).send({
        capability,
      });
    } catch (error) {
      return reply.status(409).send({
        error: "CAPABILITY_CREATION_FAILED",
        reason: error instanceof Error ? error.message : "Unknown error",
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
      return reply.status(404).send({
        error: "CAPABILITY_NOT_FOUND",
      });
    }

    return reply.send({
      capability,
    });
  });

  app.post<{
    Params: {
      capabilityId: string;
    };
  }>("/capabilities/:capabilityId/revoke", async (request, reply) => {
    const capability = capabilityStore.revoke(request.params.capabilityId);

    if (!capability) {
      return reply.status(404).send({
        error: "CAPABILITY_NOT_FOUND",
      });
    }

    return reply.send({
      message: "Capability revoked",
      capability,
    });
  });

  app.post("/evaluate", async (request, reply) => {
    const validation = validateIntent(request.body);

    if (!validation.success) {
      return reply.status(400).send({
        error: "INVALID_INTENT",
        details: validation.errors,
      });
    }

    const intent = validation.data;

    const capability = capabilityStore.get(intent.capabilityId);

    if (!capability) {
      return reply.status(404).send({
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

    const result = policyEngine.evaluate(capability, intent, isReplay);

    if (result.allowed) {
      replayStore.markProcessed(
        intent.capabilityId,
        intent.agentId,
        intent.nonce,
      );

      if (capability.usage === "SINGLE_USE") {
        capabilityStore.consume(capability.capabilityId);
      }
    }

    return reply.send(result);
  });

  return app;
}
