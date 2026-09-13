/**
 * A structured record of what the agent read, concluded, proposed, and was told.
 *
 * The transcript is the demo's evidence. It is built as data first and rendered
 * second, so the same run produces the terminal narrative a judge watches and
 * the JSON the dashboard consumes — never two accounts of the same run that
 * could disagree.
 */

export type TranscriptEntryKind =
  | "TASK"
  | "CONTEXT"
  | "INJECTION"
  | "REASONING"
  | "PROPOSAL"
  | "VERDICT"
  | "SIGNATURE"
  | "OUTCOME"
  | "NOTE"
  | "ALERT";

export type TranscriptEntry = {
  seq: number;
  at: number;
  kind: TranscriptEntryKind;
  title: string;
  body?: string;
  data?: Record<string, unknown>;
};

export type TranscriptMeta = {
  scenarioId: string;
  scenarioTitle: string;
  /** "arx" — the protected path. "unprotected" — the control case. */
  path: "arx" | "unprotected";
  agentId: string;
  /** How the agent reached its decision. Labelled so a mock is never implied real. */
  reasoningMode: "scripted" | "live-llm";
  model?: string;
  arxBaseUrl?: string;
  startedAt: number;
};

export type ConformanceStatus =
  /** Arx did what the scenario said it should. */
  | "AS_EXPECTED"
  /** Arx permitted something the scenario says must be refused. */
  | "CONTROL_GAP"
  /** Arx refused something the scenario says is legitimate. */
  | "UNEXPECTED_DENIAL"
  /** The agent never carried out the injection, so Arx was never tested. */
  | "ATTACK_REFUSED_BY_AGENT";

export type TranscriptJson = TranscriptMeta & {
  entries: TranscriptEntry[];
  verdict?: {
    decision: string;
    code: string;
    reason: string;
  };
  /** Did the run behave as the scenario expected? */
  conformance?: {
    expectedDecision: string;
    acceptableCodes: string[];
    observedDecision: string;
    observedCode: string;
    status: ConformanceStatus;
    note: string;
  };
};

const ESC = String.fromCharCode(27);

const ANSI = {
  reset: `${ESC}[0m`,
  bold: `${ESC}[1m`,
  red: `${ESC}[31m`,
  green: `${ESC}[32m`,
  yellow: `${ESC}[33m`,
  blue: `${ESC}[34m`,
  magenta: `${ESC}[35m`,
  cyan: `${ESC}[36m`,
  grey: `${ESC}[90m`,
} as const;

const KIND_STYLE: Record<
  TranscriptEntryKind,
  { label: string; color: string }
> = {
  TASK: { label: "TASK", color: ANSI.cyan },
  CONTEXT: { label: "CONTEXT", color: ANSI.grey },
  INJECTION: { label: "INJECTION", color: ANSI.magenta },
  REASONING: { label: "AGENT", color: ANSI.blue },
  PROPOSAL: { label: "PROPOSAL", color: ANSI.yellow },
  VERDICT: { label: "ARX", color: ANSI.green },
  SIGNATURE: { label: "SIGNER", color: ANSI.yellow },
  OUTCOME: { label: "OUTCOME", color: ANSI.bold },
  NOTE: { label: "NOTE", color: ANSI.grey },
  ALERT: { label: "ALERT", color: ANSI.red },
};

function colorsEnabled(): boolean {
  return !process.env.NO_COLOR;
}

function paint(text: string, color: string): string {
  return colorsEnabled() ? `${color}${text}${ANSI.reset}` : text;
}

function indentBlock(text: string, prefix: string): string {
  return text
    .trimEnd()
    .split("\n")
    .map((line) => `${prefix}${line}`)
    .join("\n");
}

export class Transcript {
  private readonly entries: TranscriptEntry[] = [];
  private verdict: TranscriptJson["verdict"];
  private conformance: TranscriptJson["conformance"];

  constructor(
    private readonly meta: TranscriptMeta,
    private readonly clock: () => number = () => Math.floor(Date.now() / 1000),
  ) {}

  add(
    kind: TranscriptEntryKind,
    title: string,
    body?: string,
    data?: Record<string, unknown>,
  ): TranscriptEntry {
    const entry: TranscriptEntry = {
      seq: this.entries.length + 1,
      at: this.clock(),
      kind,
      title,
      ...(body === undefined ? {} : { body }),
      ...(data === undefined ? {} : { data }),
    };

    this.entries.push(entry);

    return entry;
  }

  setVerdict(verdict: NonNullable<TranscriptJson["verdict"]>): void {
    this.verdict = verdict;
  }

  setConformance(
    conformance: NonNullable<TranscriptJson["conformance"]>,
  ): void {
    this.conformance = conformance;
  }

  getConformanceStatus(): ConformanceStatus | undefined {
    return this.conformance?.status;
  }

  toJSON(): TranscriptJson {
    return {
      ...this.meta,
      entries: [...this.entries],
      ...(this.verdict === undefined ? {} : { verdict: this.verdict }),
      ...(this.conformance === undefined
        ? {}
        : { conformance: this.conformance }),
    };
  }

  render(): string {
    const lines: string[] = [];

    const header =
      this.meta.path === "arx"
        ? `ARX-PROTECTED AGENT  |  ${this.meta.scenarioTitle}`
        : `UNPROTECTED AGENT — INSECURE CONTROL CASE  |  ${this.meta.scenarioTitle}`;

    const headerColor =
      this.meta.path === "arx" ? ANSI.green + ANSI.bold : ANSI.red + ANSI.bold;

    const rule = "-".repeat(78);

    lines.push(paint(rule, ANSI.grey));
    lines.push(paint(header, headerColor));
    lines.push(
      paint(
        `agent=${this.meta.agentId}  reasoning=${this.meta.reasoningMode}${
          this.meta.model ? ` (${this.meta.model})` : ""
        }  ${this.meta.arxBaseUrl ? `arx=${this.meta.arxBaseUrl}` : "arx=NONE"}`,
        ANSI.grey,
      ),
    );
    lines.push(paint(rule, ANSI.grey));
    lines.push("");

    for (const entry of this.entries) {
      const style = KIND_STYLE[entry.kind];
      const tag = paint(style.label.padEnd(9), style.color);

      lines.push(`${tag} ${paint(entry.title, ANSI.bold)}`);

      if (entry.body) {
        lines.push(paint(indentBlock(entry.body, "          "), ANSI.grey));
      }

      if (entry.data) {
        for (const [key, value] of Object.entries(entry.data)) {
          if (value === undefined) {
            continue;
          }

          const rendered =
            typeof value === "string" ? value : JSON.stringify(value);

          lines.push(paint(`          ${key}: ${rendered}`, ANSI.grey));
        }
      }

      lines.push("");
    }

    if (this.conformance) {
      const ok = this.conformance.status === "AS_EXPECTED";

      lines.push(
        paint(
          `[${ok ? "PASS" : "FAIL"}] ${this.conformance.status}: ${
            this.conformance.note
          }`,
          ok ? ANSI.green + ANSI.bold : ANSI.red + ANSI.bold,
        ),
      );
    }

    return lines.join("\n");
  }
}

/** Renders several transcripts plus a one-line-per-run summary table. */
export function renderTranscripts(transcripts: readonly Transcript[]): string {
  return transcripts.map((transcript) => transcript.render()).join("\n\n");
}
