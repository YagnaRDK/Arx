#!/usr/bin/env bun
/**
 * Single-attack runner, for a live demo.
 *
 *   bun run scripts/attack.ts                  pick from a menu
 *   bun run scripts/attack.ts prompt-injection run one immediately
 *   bun run scripts/attack.ts --loop           stay in the menu after each run
 *
 * `demo.ts` is the suite a judge runs once; this is the thing to have open when
 * someone in the room says "what happens if the agent tries X". It seeds only
 * what the chosen scenario needs, runs it, and returns to the menu.
 *
 * It attaches to a running server and never starts one, so the dashboard a
 * presenter has on screen is the dashboard the attack shows up in.
 */

import { ArxClient } from "./lib/api";
import {
  createContext,
  DEFAULT_ADMIN_TOKEN,
  discoverEthPrice,
  makeNonceBase,
  makeTag,
} from "./lib/context";
import { seedList } from "./lib/fixtures";
import { reportedDatabasePath } from "./lib/server";
import { seedCapabilities } from "./lib/seeding";
import {
  BlockedError,
  printExpectation,
  printStory,
  Trace,
  type Scenario,
} from "./lib/scenario";
import { findScenario, scenarios } from "./scenarios/index";
import {
  banner,
  field,
  pad,
  rule,
  setColorEnabled,
  statusBadge,
  style,
  write,
} from "./lib/term";

const argv = process.argv.slice(2);
const loop = argv.includes("--loop");
const noColor = argv.includes("--no-color");
const positional = argv.filter((argument) => !argument.startsWith("-"));

setColorEnabled(!noColor);

const baseUrl =
  process.env.ARX_BASE_URL ?? `http://127.0.0.1:${process.env.PORT ?? 3000}`;
const adminToken = process.env.ARX_ADMIN_TOKEN ?? DEFAULT_ADMIN_TOKEN;
const client = new ArxClient({ baseUrl, adminToken });

const health = await client.get("/health");

if (health.transportError) {
  write(
    style.red(
      `No Arx server is listening on ${baseUrl}. Start one first:\n  bun run dev`,
    ),
  );

  process.exit(1);
}

const price = await discoverEthPrice(client);

const ctx = createContext({
  client,
  adminToken,
  tag: makeTag(),
  now: Math.floor(Date.now() / 1000),
  nonceBase: makeNonceBase(),
  ethUsd: price.price,
  ethUsdSource: price.source,
  databasePath:
    (await reportedDatabasePath(baseUrl)) ?? process.env.DATABASE_PATH ?? null,
  quiet: false,
});

banner("ARX — SINGLE ATTACK RUNNER", baseUrl);

// Seeding every capability up front keeps the menu instant: the presenter picks
// an attack and it runs, rather than pausing to provision authority first.
const seeded = await seedCapabilities(client, seedList(ctx.seeds));
const failedSeeds = seeded.filter(
  (outcome) => !outcome.created && !outcome.existed,
);

field("seeded", `${seeded.length - failedSeeds.length}/${seeded.length} capabilities`);

for (const failure of failedSeeds) {
  field(
    "seed fail",
    style.amber(`${failure.capabilityId}: HTTP ${failure.status} ${failure.code ?? ""}`),
  );
}

function menu(): void {
  write();
  rule();
  write(style.bold(" Choose an attack"));
  rule();

  scenarios.forEach((scenario, index) => {
    const kind =
      scenario.kind === "ATTACK"
        ? style.red("ATTACK")
        : style.blue(pad(scenario.kind, 6));

    write(
      `  ${style.bold(String(index + 1).padStart(2, " "))}  ${kind}  ${pad(
        scenario.name,
        24,
      )} ${style.grey(scenario.title)}`,
    );
  });

  write();
  write(style.grey("  q  quit"));
  write();
}

async function runOne(scenario: Scenario): Promise<void> {
  const trace = new Trace(false);

  write();
  rule("━");
  write(style.bold(` ${scenario.title}`));
  rule("━");
  write();

  printStory(scenario);
  printExpectation(scenario);
  write();

  try {
    await scenario.run(ctx, trace);

    const failures = trace.assertions.filter((assertion) => !assertion.ok);

    write();
    field(
      "result",
      `${statusBadge(failures.length === 0 && trace.assertions.length > 0 ? "PASS" : "FAIL")} ${style.grey(
        `${trace.assertions.length - failures.length}/${trace.assertions.length} assertions`,
      )}`,
    );
  } catch (error) {
    write();

    if (error instanceof BlockedError) {
      field("blocked", style.amber(error.blockedReason));
    } else {
      field(
        "error",
        style.red(error instanceof Error ? error.message : String(error)),
      );
    }
  }

  write();
}

async function prompt(question: string): Promise<string> {
  process.stdout.write(question);

  for await (const line of console) {
    return line.trim();
  }

  return "q";
}

if (positional.length > 0) {
  const scenario = findScenario(positional[0]!);

  if (!scenario) {
    write(
      style.red(
        `No scenario named "${positional[0]}". Run without arguments for the menu.`,
      ),
    );

    process.exit(2);
  }

  await runOne(scenario);

  if (!loop) {
    process.exit(0);
  }
}

for (;;) {
  menu();

  const answer = await prompt("  attack> ");

  if (answer === "q" || answer === "quit" || answer === "") {
    write();
    break;
  }

  const byIndex = Number(answer);
  const scenario = Number.isInteger(byIndex)
    ? scenarios[byIndex - 1]
    : findScenario(answer);

  if (!scenario) {
    write(style.red(`  No such attack: ${answer}`));
    continue;
  }

  await runOne(scenario);

  if (!loop) {
    break;
  }
}
