#!/usr/bin/env bun
/**
 * Seeds the demo agent and capabilities against a running Arx server.
 *
 *   bun run scripts/seed.ts
 *   bun run scripts/seed.ts --tag demo --base http://127.0.0.1:3000
 *
 * Use this before opening the dashboard: it gives the cockpit a real agent with
 * real, differently-shaped grants to display — a $1k autonomous payment budget
 * here, a token-only grant that may not move native value there — so the
 * least-privilege story is visible without running the full attack suite.
 *
 * Unlike `demo.ts` this never starts a server. Seeding is a control-plane action
 * and it should be obvious which server received it.
 */

import { ArxClient, codeOf, reasonOf } from "./lib/api";
import { DEFAULT_ADMIN_TOKEN } from "./lib/context";
import { AGENT_ID, buildSeedSet, seedList } from "./lib/fixtures";
import { seedCapabilities } from "./lib/seeding";
import { banner, field, kv, setColorEnabled, style, write } from "./lib/term";

type Options = { baseUrl: string; tag: string; color: boolean };

function parseOptions(argv: string[]): Options {
  const options: Options = {
    baseUrl:
      process.env.ARX_BASE_URL ?? `http://127.0.0.1:${process.env.PORT ?? 3000}`,
    tag: "demo",
    color: true,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]!;

    if (argument === "--base") {
      options.baseUrl = argv[++index] ?? options.baseUrl;
    } else if (argument === "--tag") {
      options.tag = argv[++index] ?? options.tag;
    } else if (argument === "--no-color") {
      options.color = false;
    } else if (argument === "--help" || argument === "-h") {
      write(
        "bun run scripts/seed.ts [--base <url>] [--tag <suffix>] [--no-color]",
      );
      process.exit(0);
    }
  }

  return options;
}

const options = parseOptions(process.argv.slice(2));

setColorEnabled(options.color);

const adminToken = process.env.ARX_ADMIN_TOKEN ?? DEFAULT_ADMIN_TOKEN;
const client = new ArxClient({ baseUrl: options.baseUrl, adminToken });

banner("ARX — SEED DEMO CAPABILITIES", options.baseUrl);

const health = await client.get("/health");

if (health.transportError) {
  write(
    style.red(
      `No server is listening on ${options.baseUrl}. Start one first: bun run dev`,
    ),
  );

  process.exit(1);
}

/**
 * The agent identity. An agent is registered by an operator and cannot register
 * itself — invariant 11 — so this is an admin call. The route is optional in the
 * current server; when it is absent the capabilities still seed fine, and the
 * demo's agent id simply has no HMAC secret registered against it.
 */
const agentResult = await client.post(
  "/agents",
  {
    agentId: AGENT_ID,
    label: "Treasury operations bot (demo)",
    secret: "arx-demo-agent-secret",
    enabled: true,
  },
  { admin: true },
);

if (agentResult.routeMissing) {
  field(
    "agent",
    style.amber(
      `POST /agents is not implemented; ${AGENT_ID} will be used without a registered secret`,
    ),
  );
} else if (agentResult.status >= 200 && agentResult.status < 300) {
  field("agent", `${AGENT_ID} registered`);
} else if (agentResult.status === 409) {
  field("agent", `${AGENT_ID} already registered`);
} else {
  field(
    "agent",
    style.amber(
      `HTTP ${agentResult.status} ${codeOf(agentResult) ?? ""} ${reasonOf(agentResult) ?? ""}`.trim(),
    ),
  );
}

const now = Math.floor(Date.now() / 1000);
const seeds = seedList(buildSeedSet(options.tag, now));
const outcomes = await seedCapabilities(client, seeds);

write();

kv(
  outcomes.map((outcome) => {
    const state = outcome.created
      ? style.green("created")
      : outcome.existed
        ? style.grey("already present")
        : style.red(
            `failed HTTP ${outcome.status} ${outcome.code ?? ""} ${outcome.reason ?? ""}`.trim(),
          );

    return [outcome.capabilityId, state] as [string, string];
  }),
  0,
);

write();
field("admin token", adminToken);
field(
  "dashboard",
  `${options.baseUrl}/ — paste the admin token into the cockpit header to enable Approve / Reject`,
);
write();

const failures = outcomes.filter(
  (outcome) => !outcome.created && !outcome.existed,
);

process.exitCode = failures.length > 0 ? 1 : 0;
