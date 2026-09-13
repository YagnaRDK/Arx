/**
 * Capability seeding.
 *
 * Creating a capability is a control-plane action — an agent cannot mint its own
 * authority (invariant 11) — so these calls carry the admin credential. If the
 * server rejects them for lack of one, the scenarios that depend on the
 * capability report BLOCKED with that reason rather than silently running
 * against no grant at all.
 */

import { ArxClient, codeOf, reasonOf, type ApiResult } from "./api";
import type { CapabilitySeed } from "./fixtures";

export type SeedOutcome = {
  capabilityId: string;
  created: boolean;
  /** Already present from an earlier run; not an error. */
  existed: boolean;
  status: number;
  code: string | null;
  reason: string | null;
  routeMissing: boolean;
};

function classify(seed: CapabilitySeed, result: ApiResult): SeedOutcome {
  const existed =
    result.status === 409 ||
    codeOf(result) === "INTENT_ID_CONFLICT" ||
    /already exists/i.test(result.rawBody);

  return {
    capabilityId: seed.capabilityId,
    created: result.status >= 200 && result.status < 300,
    existed,
    status: result.status,
    code: codeOf(result),
    reason: reasonOf(result),
    routeMissing: result.routeMissing,
  };
}

export async function seedCapability(
  client: ArxClient,
  seed: CapabilitySeed,
): Promise<SeedOutcome> {
  const result = await client.post("/capabilities", seed, { admin: true });

  return classify(seed, result);
}

export async function seedCapabilities(
  client: ArxClient,
  seeds: CapabilitySeed[],
): Promise<SeedOutcome[]> {
  const outcomes: SeedOutcome[] = [];

  for (const seed of seeds) {
    outcomes.push(await seedCapability(client, seed));
  }

  return outcomes;
}

export function seedFailures(outcomes: SeedOutcome[]): SeedOutcome[] {
  return outcomes.filter((outcome) => !outcome.created && !outcome.existed);
}
