import { requestApproval } from "../lib/flows";
import { ADDRESS, buildIntent, nativeTransfer, weiForUsd } from "../lib/fixtures";
import { seedCapability } from "../lib/seeding";
import { BlockedError, type Scenario } from "../lib/scenario";

/**
 * Authority has an end date.
 *
 * A grant that outlives its purpose is the standing risk in every agent
 * deployment: the task finished in March and the key is still signing in
 * November. Invariant 6.
 *
 * The capability is seeded already expired. If the server refuses to store a
 * grant that is dead on arrival — a reasonable thing for it to do — the scenario
 * falls back to a two-second grant and waits it out, and says so.
 */
export const expiredCapability: Scenario = {
  name: "expired-capability",
  title: "Expired capability: the grant lapsed, the request dies with it",
  kind: "CONTROL",
  story: [
    "The agent holds a capability whose validity window has closed.",
    "Everything else about the request is impeccable: allowlisted",
    "recipient, small amount, correct chain, fresh nonce.",
  ],
  expectation: "DENY CAPABILITY_EXPIRED",

  async run(ctx, trace): Promise<void> {
    let capabilityId = ctx.seeds.expired.capabilityId;

    const existing = trace.requireRoute(
      await ctx.client.get(`/capabilities/${capabilityId}`),
    );

    if (existing.status === 404) {
      trace.note(
        "The pre-expired grant was not accepted by the control plane; seeding a two-second grant and waiting for it to lapse instead.",
      );

      const shortLived = {
        ...ctx.seeds.expired,
        capabilityId: `${capabilityId}-short`,
        expiresAt: Math.floor(Date.now() / 1000) + 2,
      };

      const seeded = await seedCapability(ctx.client, shortLived);

      if (!seeded.created && !seeded.existed) {
        throw new BlockedError(
          `Could not seed a capability to expire: HTTP ${seeded.status} ${seeded.code ?? ""} ${seeded.reason ?? ""}`.trim(),
        );
      }

      capabilityId = shortLived.capabilityId;

      await ctx.sleep(2_600);
    }

    const transaction = nativeTransfer(
      ADDRESS.vendor,
      weiForUsd(10, ctx.ethUsd),
    );

    const intent = buildIntent({
      capabilityId,
      nonce: ctx.nextNonce(capabilityId),
      timestamp: Math.floor(Date.now() / 1000),
      amountUsd: 10,
      transaction,
    });

    const result = await requestApproval(ctx, trace, intent);

    trace.expectVerdict("the request is refused", result, "DENY");
    trace.expectCode("refusal names expiry", result, {
      code: "CAPABILITY_EXPIRED",
      alsoAcceptable: ["CAPABILITY_INACTIVE"],
    });
  },
};
