/**
 * The scenario harness.
 *
 * A demo that prints what happened is a hope; this one asserts. Every scenario
 * declares the decision code it expects before it runs, and the harness compares
 * the server's answer against that declaration. Three outcomes are possible:
 *
 *   PASS     the expected control fired
 *   FAIL     the control did not fire, or fired with the wrong code
 *   BLOCKED  the endpoint the scenario needs does not exist on this server yet
 *
 * BLOCKED is kept distinct from FAIL on purpose. "The server refused for the
 * wrong reason" and "the server has no such route" are different problems, and
 * collapsing them would hide unfinished work behind a red line that looks like a
 * security bug — or, worse, hide a security bug behind one that looks like
 * unfinished work.
 */

import {
  codeOf,
  isKnownCode,
  reasonOf,
  riskOf,
  verdictOf,
  type ApiResult,
  type Verdict,
} from "./api";
import {
  decisionBadge,
  field,
  kv,
  statusBadge,
  style,
  write,
} from "./term";
import type { RunContext } from "./context";

/** Thrown to abandon a scenario because the server cannot host it. */
export class BlockedError extends Error {
  constructor(readonly blockedReason: string) {
    super(blockedReason);
    this.name = "BlockedError";
  }
}

export type Assertion = {
  label: string;
  ok: boolean;
  expected: string;
  actual: string;
  /** Set when the outcome is acceptable but not the primary expectation. */
  alternate?: boolean;
};

export type StepRecord = {
  label: string;
  method: string;
  path: string;
  status: number;
  code: string | null;
  verdict: Verdict;
  reason: string | null;
  ms: number;
  transportError?: string;
};

export type ScenarioOutcome = {
  name: string;
  title: string;
  kind: ScenarioKind;
  status: "PASS" | "FAIL" | "BLOCKED" | "SKIP";
  expectation: string;
  assertions: Assertion[];
  steps: StepRecord[];
  notes: string[];
  blockedReason?: string;
  durationMs: number;
};

export type ScenarioKind = "CONTROL" | "ATTACK" | "LIFECYCLE" | "FORENSICS";

export type ExpectedCode = {
  /** The code this control should produce. */
  code: string;
  /**
   * Other codes that are still a correct refusal, e.g. a fail-closed denial
   * raised by an earlier check. Accepted, but reported as an alternate so the
   * output never implies the primary control was the one that fired.
   */
  alsoAcceptable?: string[];
};

export class Trace {
  readonly assertions: Assertion[] = [];
  readonly steps: StepRecord[] = [];
  readonly notes: string[] = [];

  constructor(private readonly quiet: boolean) {}

  note(text: string): void {
    this.notes.push(text);

    if (!this.quiet) {
      field("note", style.grey(text));
    }
  }

  /** Issues one HTTP call, printing the request and the decision around it. */
  async call(
    label: string,
    detail: Array<[string, string]>,
    send: () => Promise<ApiResult>,
  ): Promise<ApiResult> {
    if (!this.quiet) {
      field("request", style.bold(label));

      if (detail.length > 0) {
        kv(detail);
      }
    }

    const result = await send();
    const code = codeOf(result);
    const verdict = verdictOf(result);
    const reason = reasonOf(result);

    this.steps.push({
      label,
      method: result.method,
      path: result.path,
      status: result.status,
      code,
      verdict,
      reason,
      ms: result.ms,
      ...(result.transportError === undefined
        ? {}
        : { transportError: result.transportError }),
    });

    if (!this.quiet) {
      if (result.transportError) {
        field(
          "decision",
          style.red(`TRANSPORT ERROR  ${result.transportError}`),
        );
      } else {
        const httpNote = style.grey(`(HTTP ${result.status}, ${result.ms}ms)`);
        const codeText = code
          ? isKnownCode(code)
            ? style.bold(code)
            : `${style.bold(code)} ${style.amber("[not in DecisionCode registry]")}`
          : style.grey("no decision code in response");

        field("decision", `${decisionBadge(verdict)} ${codeText} ${httpNote}`);
      }

      if (reason) {
        field("reason", reason);
      }

      const risk = riskOf(result);

      if (risk) {
        const header =
          risk.score === null ? "signals only" : `score ${risk.score}`;

        field(
          "risk",
          risk.signals.length === 0 && (risk.score ?? 0) > 0
            ? `${header} ${style.amber("(no contributing signals returned — a non-zero score without signals is not auditable)")}`
            : risk.signals.length === 0
              ? `${header} ${style.grey("(nothing flagged)")}`
              : header,
        );

        if (risk.signals.length > 0) {
          kv(
            risk.signals.map(
              (signal) =>
                [
                  `+${signal.weight} ${signal.id}`,
                  signal.explanation,
                ] as [string, string],
            ),
          );
        }
      }
    }

    return result;
  }

  assert(label: string, ok: boolean, expected: string, actual: string): boolean {
    this.assertions.push({ label, ok, expected, actual });

    if (!this.quiet) {
      field(
        "assert",
        `${ok ? style.green("ok  ") : style.red("bad ")} ${label} ${style.grey(
          `expected ${expected}, got ${actual}`,
        )}`,
      );
    }

    return ok;
  }

  /**
   * Asserts the response carries the expected decision code.
   *
   * An unknown code never passes: a control that answers with a string outside
   * the registry is not auditable, however plausible the string looks.
   */
  expectCode(label: string, result: ApiResult, expected: ExpectedCode): boolean {
    const code = codeOf(result);
    const alternates = expected.alsoAcceptable ?? [];

    if (code === expected.code) {
      return this.assert(label, true, expected.code, code);
    }

    if (code !== null && alternates.includes(code)) {
      this.assertions.push({
        label,
        ok: true,
        expected: expected.code,
        actual: code,
        alternate: true,
      });

      if (!this.quiet) {
        field(
          "assert",
          `${style.amber("alt ")} ${label} ${style.grey(
            `expected ${expected.code}, got acceptable alternate ${code}`,
          )}`,
        );
      }

      return true;
    }

    return this.assert(
      label,
      false,
      [expected.code, ...alternates].join(" | "),
      code ?? `none (HTTP ${result.status})`,
    );
  }

  expectVerdict(
    label: string,
    result: ApiResult,
    expected: Verdict | Verdict[],
  ): boolean {
    const accepted = Array.isArray(expected) ? expected : [expected];
    const actual = verdictOf(result);

    return this.assert(
      label,
      accepted.includes(actual),
      accepted.join(" | "),
      actual,
    );
  }

  expectHttp(label: string, result: ApiResult, statuses: number[]): boolean {
    return this.assert(
      label,
      statuses.includes(result.status),
      statuses.join(" | "),
      String(result.status),
    );
  }

  /** Abandons the scenario when the route it needs is not implemented. */
  requireRoute(result: ApiResult): ApiResult {
    if (result.transportError) {
      throw new BlockedError(
        `${result.method} ${result.path} could not be reached: ${result.transportError}`,
      );
    }

    if (result.routeMissing) {
      throw new BlockedError(
        `${result.method} ${result.path} is not implemented on this server`,
      );
    }

    return result;
  }

  block(reason: string): never {
    throw new BlockedError(reason);
  }
}

export type Scenario = {
  /** Stable id used by `--only`. */
  name: string;
  title: string;
  kind: ScenarioKind;
  /** The one scenario whose output gets extra emphasis in a live demo. */
  headline?: boolean;
  /** Plain-language framing: what an operator should picture happening. */
  story: string[];
  /** Declared before the run. This is the contract the scenario is testing. */
  expectation: string;
  run(ctx: RunContext, trace: Trace): Promise<void>;
};

export function summariseOutcome(outcome: ScenarioOutcome): string {
  return `${statusBadge(outcome.status)} ${outcome.name}`;
}

export function printExpectation(scenario: Scenario): void {
  field("expect", scenario.expectation);
}

export function printStory(scenario: Scenario): void {
  field("story", scenario.story.map((line) => style.grey(line)));
  write();
}
