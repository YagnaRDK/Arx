/**
 * The scenario registry, in demo order.
 *
 * The order is the argument: prove the authorised path works, then take it apart
 * one control at a time, then show that the record of all of it cannot be
 * rewritten.
 */

import type { Scenario } from "../lib/scenario";

import { allowedPayment } from "./01-allowed-payment";
import { promptInjection } from "./02-prompt-injection";
import { highValueEscalation } from "./03-high-value-escalation";
import { replay } from "./04-replay";
import { expiredCapability } from "./05-expired-capability";
import { transactionMutation } from "./06-transaction-mutation";
import { declaredValueLie } from "./07-declared-value-lie";
import { calldataSmuggling } from "./08-calldata-smuggling";
import { unlimitedApproval } from "./09-unlimited-approval";
import { addressPoisoning } from "./10-address-poisoning";
import { doubleSignRace } from "./11-double-sign-race";
import { auditTamper } from "./12-audit-tamper";
import { spendWindow } from "./13-spend-window";
import { revocationMidFlight } from "./14-revocation-mid-flight";

export const scenarios: Scenario[] = [
  allowedPayment,
  promptInjection,
  highValueEscalation,
  replay,
  expiredCapability,
  transactionMutation,
  declaredValueLie,
  calldataSmuggling,
  unlimitedApproval,
  addressPoisoning,
  doubleSignRace,
  auditTamper,
  spendWindow,
  revocationMidFlight,
];

export function findScenario(name: string): Scenario | undefined {
  const needle = name.trim().toLowerCase();

  return scenarios.find(
    (scenario) =>
      scenario.name === needle ||
      scenario.name.replace(/-/g, "") === needle.replace(/-/g, ""),
  );
}

export function scenarioNames(): string[] {
  return scenarios.map((scenario) => scenario.name);
}
