#!/usr/bin/env bun
/**
 * The Arx adversarial demo suite.
 *
 *   bun run scripts/demo.ts                      every scenario, in order
 *   bun run scripts/demo.ts --only prompt-injection
 *   bun run scripts/demo.ts --json               machine-readable output
 *   bun run scripts/demo.ts --list               scenario names
 *
 * Works from a clean clone: no API keys, no hardware, no accounts, no network
 * beyond localhost. It attaches to a server that is already listening and starts
 * one only if nothing answers.
 *
 * The exit code is the contract. Non-zero on any failed or blocked scenario, so
 * CI and the lead can trust it without reading the transcript.
 */

import { ArxClient, isKnownCode } from "./lib/api";
import {
  createContext,
  DEFAULT_ADMIN_TOKEN,
  discoverEthPrice,
  makeNonceBase,
  makeTag,
  type ServerHandle,
} from "./lib/context";
import { seedCapabilities, seedFailures } from "./lib/seeding";
import { seedList } from "./lib/fixtures";
import { attachOrStart } from "./lib/server";
import {
  BlockedError,
  printExpectation,
  printStory,
  Trace,
  type Scenario,
  type ScenarioOutcome,
} from "./lib/scenario";
import { findScenario, scenarioNames, scenarios } from "./scenarios/index";
import {
  banner,
  field,
  formatUsd,
  kv,
  pad,
  rule,
  setColorEnabled,
  statusBadge,
  style,
  WIDTH,
  write,
} from "./lib/term";

type Options = {
  baseUrl: string;
  port: number;
  only: string | null;
  json: boolean;
  list: boolean;
  color: boolean;
  spawn: boolean;
  resetDatabase: boolean;
  databasePath: string;
  allowBlocked: boolean;
  serverLogs: boolean;
  tag: string;
  nonceBase: number;
};

function parseOptions(argv: string[]): Options {
  const port = Number(process.env.PORT ?? 3000);

  const options: Options = {
    baseUrl: process.env.ARX_BASE_URL ?? `http://127.0.0.1:${port}`,
    port,
    only: null,
    json: false,
    list: false,
    color: true,
    spawn: true,
    resetDatabase: true,
    databasePath: process.env.ARX_DEMO_DATABASE_PATH ?? "./data/arx-demo.sqlite",
    allowBlocked: false,
    serverLogs: false,
    tag: makeTag(),
    nonceBase: makeNonceBase(),
  };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]!;
    const next = () => argv[++index];

    switch (argument) {
      case "--only":
        options.only = next() ?? null;
        break;
      case "--json":
        options.json = true;
        options.color = false;
        break;
      case "--list":
        options.list = true;
        break;
      case "--no-color":
        options.color = false;
        break;
      case "--no-spawn":
        options.spawn = false;
        break;
      case "--keep-db":
        options.resetDatabase = false;
        break;
      case "--allow-blocked":
        options.allowBlocked = true;
        break;
      case "--server-logs":
        options.serverLogs = true;
        break;
      case "--base": {
        const value = next();

        if (value) {
          options.baseUrl = value;
        }

        break;
      }
      case "--port": {
        const value = Number(next());

        if (Number.isInteger(value) && value > 0) {
          options.port = value;
          options.baseUrl = `http://127.0.0.1:${value}`;
        }

        break;
      }
      case "--db": {
        const value = next();

        if (value) {
          options.databasePath = value;
        }

        break;
      }
      case "--run-tag": {
        const value = next();

        if (value) {
          options.tag = value;
        }

        break;
      }
      case "--nonce-base": {
        const value = Number(next());

        if (Number.isInteger(value) && value >= 1) {
          options.nonceBase = value;
        }

        break;
      }
      case "--help":
      case "-h":
        printHelp();
        process.exit(0);
      default:
        if (argument.startsWith("-")) {
          write(style.red(`Unknown option: ${argument}`));
          printHelp();
          process.exit(2);
        }
    }
  }

  // The port in the base URL is authoritative when both are given, so
  // `--base http://127.0.0.1:4000` spawns on 4000 rather than on PORT.
  const parsedPort = Number(new URL(options.baseUrl).port || 80);

  if (Number.isInteger(parsedPort) && parsedPort > 0) {
    options.port = parsedPort;
  }

  return options;
}

function printHelp(): void {
  write(`
${style.bold("Arx adversarial demo suite")}

  bun run scripts/demo.ts [options]

  --only <name>      run a single scenario
  --list             list scenario names and exit
  --json             emit a machine-readable report (implies --no-color)
  --base <url>       server base URL (default http://127.0.0.1:$PORT or :3000)
  --port <n>         shorthand for --base http://127.0.0.1:<n>
  --db <path>        database path used when this script starts the server
  --keep-db          do not delete the demo database before starting a server
  --no-spawn         fail instead of starting a server
  --allow-blocked    exit 0 even if scenarios were blocked by missing routes
  --server-logs      print the spawned server's output at the end
  --run-tag <tag>    suffix for seeded capability ids (default: time-based)
  --nonce-base <n>   first intent nonce (default: time-based)
  --no-color         disable ANSI colour
`);
}

function printRunHeader(input: {
  options: Options;
  server: ServerHandle;
  ethUsd: number;
  ethUsdSource: string;
  tag: string;
  signer: unknown;
}): void {
  banner(
    "ARX — ADVERSARIAL DEMO SUITE",
    "AI proposes, Arx authorizes, the device signs",
  );

  const signerRecord =
    typeof input.signer === "object" && input.signer !== null
      ? (input.signer as Record<string, any>)
      : {};

  const signerMode =
    signerRecord.mode ?? signerRecord.adapter ?? signerRecord.signer?.mode ?? "unknown";

  kv(
    [
      ["server", `${input.server.baseUrl} ${input.server.spawned ? style.grey("(started by this run)") : style.grey("(already running)")}`],
      ["database", input.server.databasePath ?? style.amber("unknown")],
      ["signer", String(signerMode)],
      ["capabilities", `tag ${input.tag}`],
      ["eth price", `${formatUsd(input.ethUsd)} ${style.grey(`via ${input.ethUsdSource}`)}`],
    ],
    0,
  );

  if (/mock/i.test(String(signerMode))) {
    write();
    write(
      style.amber(
        style.bold(
          "  MOCK SIGNER — signatures in this run are emulated, not real blockchain signatures.",
        ),
      ),
    );
  }

  write();
}

async function runScenario(
  scenario: Scenario,
  ctx: ReturnType<typeof createContext>,
  index: number,
  total: number,
  quiet: boolean,
): Promise<ScenarioOutcome> {
  const trace = new Trace(quiet);
  const startedAt = performance.now();

  if (!quiet) {
    write();
    rule("━");
    write(
      `${style.bold(
        ` [${String(index + 1).padStart(2, "0")}/${total}] ${scenario.title}`,
      )}`,
    );
    write(
      `${pad(style.grey(`      ${scenario.name}`), WIDTH - 12)}${
        scenario.kind === "ATTACK"
          ? style.red(style.bold("  ATTACK"))
          : style.blue(`  ${scenario.kind}`)
      }`,
    );
    rule("━");
    write();

    printStory(scenario);
    printExpectation(scenario);
    write();
  }

  let status: ScenarioOutcome["status"] = "PASS";
  let blockedReason: string | undefined;

  try {
    await scenario.run(ctx, trace);

    const failed = trace.assertions.filter((assertion) => !assertion.ok);

    status =
      trace.assertions.length === 0
        ? "FAIL"
        : failed.length === 0
          ? "PASS"
          : "FAIL";

    if (trace.assertions.length === 0) {
      trace.notes.push("Scenario made no assertions, which is itself a failure");
    }
  } catch (error) {
    if (error instanceof BlockedError) {
      status = "BLOCKED";
      blockedReason = error.blockedReason;
    } else {
      status = "FAIL";
      trace.assertions.push({
        label: "scenario completed without throwing",
        ok: false,
        expected: "no exception",
        actual: error instanceof Error ? error.message : String(error),
      });
    }
  }

  const durationMs = Math.round(performance.now() - startedAt);

  if (!quiet) {
    write();

    if (status === "BLOCKED") {
      field("blocked", style.amber(blockedReason ?? "unknown reason"));
    }

    field(
      "result",
      `${statusBadge(status)} ${style.grey(
        `${trace.assertions.filter((assertion) => assertion.ok).length}/${trace.assertions.length} assertions, ${durationMs}ms`,
      )}`,
    );
  }

  return {
    name: scenario.name,
    title: scenario.title,
    kind: scenario.kind,
    status,
    expectation: scenario.expectation,
    assertions: trace.assertions,
    steps: trace.steps,
    notes: trace.notes,
    ...(blockedReason === undefined ? {} : { blockedReason }),
    durationMs,
  };
}

function printSummary(outcomes: ScenarioOutcome[]): void {
  write();
  banner("SUMMARY");

  for (const outcome of outcomes) {
    const detail =
      outcome.status === "BLOCKED"
        ? style.amber(outcome.blockedReason ?? "")
        : style.grey(
            outcome.assertions
              .filter((assertion) => !assertion.ok)
              .map((assertion) => `${assertion.label}: got ${assertion.actual}`)
              .join("; "),
          );

    write(
      `  ${statusBadge(outcome.status)}  ${pad(outcome.name, 26)} ${style.grey(
        `${outcome.durationMs}ms`,
      )}`,
    );

    if (detail) {
      write(`        ${detail}`);
    }
  }

  const counts = {
    pass: outcomes.filter((outcome) => outcome.status === "PASS").length,
    fail: outcomes.filter((outcome) => outcome.status === "FAIL").length,
    blocked: outcomes.filter((outcome) => outcome.status === "BLOCKED").length,
  };

  write();
  write(
    `  ${style.green(`${counts.pass} passed`)}   ${
      counts.fail > 0 ? style.red(`${counts.fail} failed`) : `${counts.fail} failed`
    }   ${
      counts.blocked > 0
        ? style.amber(`${counts.blocked} blocked`)
        : `${counts.blocked} blocked`
    }`,
  );
  write();
}

async function main(): Promise<number> {
  const options = parseOptions(process.argv.slice(2));

  setColorEnabled(options.color);

  if (options.list) {
    for (const scenario of scenarios) {
      write(`${pad(scenario.name, 26)} ${scenario.title}`);
    }

    return 0;
  }

  const selected = options.only
    ? (() => {
        const scenario = findScenario(options.only!);

        if (!scenario) {
          write(
            style.red(
              `No scenario named "${options.only}". Known: ${scenarioNames().join(", ")}`,
            ),
          );

          return null;
        }

        return [scenario];
      })()
    : scenarios;

  if (!selected) {
    return 2;
  }

  const adminToken = process.env.ARX_ADMIN_TOKEN ?? DEFAULT_ADMIN_TOKEN;

  let server: ServerHandle;

  try {
    server = await attachOrStart({
      baseUrl: options.baseUrl,
      port: options.port,
      databasePath: options.databasePath,
      adminToken,
      allowSpawn: options.spawn,
      resetDatabase: options.resetDatabase,
    });
  } catch (error) {
    write(style.red(error instanceof Error ? error.message : String(error)));

    return 1;
  }

  const client = new ArxClient({ baseUrl: server.baseUrl, adminToken });

  try {
    const signerInfo = await client.get("/signer");
    const price = await discoverEthPrice(client);

    const ctx = createContext({
      client,
      adminToken,
      tag: options.tag,
      now: Math.floor(Date.now() / 1000),
      nonceBase: options.nonceBase,
      ethUsd: price.price,
      ethUsdSource: price.source,
      databasePath: server.databasePath,
      quiet: options.json,
    });

    if (!options.json) {
      printRunHeader({
        options,
        server,
        ethUsd: price.price,
        ethUsdSource: price.source,
        tag: options.tag,
        signer: signerInfo.body,
      });
    }

    const seedOutcomes = await seedCapabilities(client, seedList(ctx.seeds));
    const failedSeeds = seedFailures(seedOutcomes);

    if (!options.json) {
      field(
        "seeded",
        `${seedOutcomes.length - failedSeeds.length}/${seedOutcomes.length} capabilities`,
      );

      for (const failure of failedSeeds) {
        field(
          "seed fail",
          style.amber(
            `${failure.capabilityId}: HTTP ${failure.status} ${failure.code ?? ""} ${failure.reason ?? ""}`.trim(),
          ),
        );
      }
    }

    const outcomes: ScenarioOutcome[] = [];

    for (const [index, scenario] of selected.entries()) {
      outcomes.push(
        await runScenario(scenario, ctx, index, selected.length, options.json),
      );
    }

    const unknownCodes = new Set<string>();

    for (const outcome of outcomes) {
      for (const step of outcome.steps) {
        if (step.code !== null && !isKnownCode(step.code)) {
          unknownCodes.add(step.code);
        }
      }
    }

    const failed = outcomes.filter((outcome) => outcome.status === "FAIL");
    const blocked = outcomes.filter((outcome) => outcome.status === "BLOCKED");

    if (options.json) {
      const report = {
        suite: "arx-adversarial-demo",
        startedAt: new Date().toISOString(),
        server: {
          baseUrl: server.baseUrl,
          spawnedByDemo: server.spawned,
          databasePath: server.databasePath,
        },
        signer: signerInfo.body,
        ethUsd: { value: price.price, source: price.source },
        runTag: options.tag,
        seeds: seedOutcomes,
        scenarios: outcomes,
        codesOutsideRegistry: [...unknownCodes],
        summary: {
          total: outcomes.length,
          passed: outcomes.length - failed.length - blocked.length,
          failed: failed.length,
          blocked: blocked.length,
        },
      };

      write(JSON.stringify(report, null, 2));
    } else {
      printSummary(outcomes);

      if (unknownCodes.size > 0) {
        write(
          style.amber(
            `  Codes returned that are not in src/core/codes.ts: ${[...unknownCodes].join(", ")}`,
          ),
        );
        write();
      }

      if (options.serverLogs && server.spawned) {
        write(style.grey("--- server output ---"));
        write(server.logs());
      }
    }

    if (failed.length > 0) {
      return 1;
    }

    if (blocked.length > 0 && !options.allowBlocked) {
      return 1;
    }

    return 0;
  } finally {
    await server.stop();
  }
}

process.exitCode = await main();
