/**
 * HTTP client for the demo suite.
 *
 * Two deliberate properties:
 *
 * 1. **It never throws on a rejection.** A denial is the expected result in most
 *    scenarios, so a 403 is data, not an exception. Only transport failures are
 *    surfaced as errors.
 * 2. **It reads decision codes tolerantly.** The server's envelope has moved
 *    between versions (`code`, `result.code`, `policy.code`), so the code is
 *    extracted from any of the shapes Arx has used and validated against the
 *    registry in `src/core/codes.ts`. A code the registry does not contain is
 *    reported as unknown rather than silently accepted, which is what stops a
 *    scenario from "passing" on a typo'd string.
 */

import { DECISION_CODES, type DecisionCode } from "../../src/core/codes";

const KNOWN_CODES = new Set<string>(DECISION_CODES);

export type ApiResult = {
  method: string;
  path: string;
  url: string;
  status: number;
  ok: boolean;
  body: any;
  rawBody: string;
  ms: number;
  /** The route is absent from the server, as opposed to rejecting the request. */
  routeMissing: boolean;
  /** Set when the request never reached the server at all. */
  transportError?: string;
};

export type ClientOptions = {
  baseUrl: string;
  adminToken?: string;
  timeoutMs?: number;
};

function parseBody(raw: string): unknown {
  if (raw.length === 0) {
    return null;
  }

  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

/**
 * Distinguishes "this endpoint does not exist" from "this endpoint refused me".
 * Fastify's default not-found handler is recognisable, and the distinction
 * matters: a missing route means the demo is blocked on unfinished server work,
 * while a 404 from a real route is a legitimate outcome.
 */
function isRouteMissing(status: number, body: unknown): boolean {
  if (status !== 404) {
    return false;
  }

  if (typeof body !== "object" || body === null) {
    return false;
  }

  const record = body as Record<string, unknown>;

  if (record.code === "FST_ERR_NOT_FOUND") {
    return true;
  }

  return (
    typeof record.message === "string" && /^Route\s+\S+\s+not found/i.test(record.message)
  );
}

export class ArxClient {
  readonly baseUrl: string;

  private readonly adminToken: string;
  private readonly timeoutMs: number;

  constructor(options: ClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.adminToken = options.adminToken ?? "";
    this.timeoutMs = options.timeoutMs ?? 15_000;
  }

  async request(
    method: "GET" | "POST" | "DELETE",
    path: string,
    body?: unknown,
    options?: { admin?: boolean },
  ): Promise<ApiResult> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = { accept: "application/json" };

    if (body !== undefined) {
      headers["content-type"] = "application/json";
    }

    // The header name for the control plane is not yet fixed in the server, so
    // both spellings are sent. Sending an admin credential on a non-admin route
    // is harmless; omitting it on an admin route is a blocked scenario.
    if (options?.admin && this.adminToken) {
      headers.authorization = `Bearer ${this.adminToken}`;
      headers["x-arx-admin-token"] = this.adminToken;
    }

    const startedAt = performance.now();

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeoutMs),
      });

      const rawBody = await response.text();
      const parsed = parseBody(rawBody);

      return {
        method,
        path,
        url,
        status: response.status,
        ok: response.ok,
        body: parsed,
        rawBody,
        ms: Math.round(performance.now() - startedAt),
        routeMissing: isRouteMissing(response.status, parsed),
      };
    } catch (error) {
      return {
        method,
        path,
        url,
        status: 0,
        ok: false,
        body: null,
        rawBody: "",
        ms: Math.round(performance.now() - startedAt),
        routeMissing: false,
        transportError: error instanceof Error ? error.message : String(error),
      };
    }
  }

  get(path: string, options?: { admin?: boolean }): Promise<ApiResult> {
    return this.request("GET", path, undefined, options);
  }

  post(
    path: string,
    body?: unknown,
    options?: { admin?: boolean },
  ): Promise<ApiResult> {
    return this.request("POST", path, body, options);
  }
}

function firstString(...candidates: unknown[]): string | null {
  for (const candidate of candidates) {
    if (typeof candidate === "string" && candidate.length > 0) {
      return candidate;
    }
  }

  return null;
}

/**
 * Decision codes are SCREAMING_SNAKE_CASE. Fastify's own error envelope puts a
 * human phrase in `error` ("Internal Server Error"), and treating that as a code
 * would both pollute the transcript and make the "code outside the registry"
 * warning useless.
 */
const CODE_SHAPE = /^[A-Z][A-Z0-9_]{2,}$/;

function firstCodeLike(...candidates: unknown[]): string | null {
  for (const candidate of candidates) {
    if (typeof candidate === "string" && CODE_SHAPE.test(candidate)) {
      return candidate;
    }
  }

  return null;
}

/** The decision code this response carries, from whichever field holds it. */
export function codeOf(result: ApiResult): string | null {
  const body = result.body;

  if (typeof body !== "object" || body === null) {
    return null;
  }

  return firstCodeLike(
    body.code,
    body.decisionCode,
    body.policyCode,
    body.result?.code,
    body.policy?.code,
    body.decision?.code,
    body.evaluation?.code,
    body.firewall?.code,
    body.approval?.policyCode,
    body.error?.code,
    body.error,
    body.details?.code,
  );
}

/** True when the code is in the registry; an unknown string is a red flag. */
export function isKnownCode(code: string | null): code is DecisionCode {
  return code !== null && KNOWN_CODES.has(code);
}

export type Verdict = "ALLOW" | "DENY" | "ESCALATE" | "UNKNOWN";

/**
 * The decision this response represents.
 *
 * Derived from an explicit `decision` field when present, and otherwise from
 * the code and HTTP status. `allowed: true` alone is not trusted as ALLOW,
 * because an escalation is also a non-failure.
 */
export function verdictOf(result: ApiResult): Verdict {
  const body = result.body;
  const explicit =
    typeof body === "object" && body !== null
      ? firstString(body.decision, body.result?.decision, body.policy?.decision)
      : null;

  if (explicit === "ALLOW" || explicit === "DENY" || explicit === "ESCALATE") {
    return explicit;
  }

  const code = codeOf(result);

  if (code === "HUMAN_APPROVAL_REQUIRED" || code === "APPROVAL_PENDING_HUMAN") {
    return "ESCALATE";
  }

  if (code === "POLICY_APPROVED") {
    return "ALLOW";
  }

  if (code !== null && KNOWN_CODES.has(code)) {
    return "DENY";
  }

  if (result.status === 202) {
    return "ESCALATE";
  }

  if (result.status >= 200 && result.status < 300) {
    return "ALLOW";
  }

  if (result.status >= 400) {
    return "DENY";
  }

  return "UNKNOWN";
}

export function reasonOf(result: ApiResult): string | null {
  const body = result.body;

  if (typeof body !== "object" || body === null) {
    return typeof body === "string" && body.length > 0 ? body : null;
  }

  return firstString(
    body.reason,
    body.result?.reason,
    body.policy?.reason,
    body.message,
    body.error?.message,
    body.approval?.reason,
  );
}

export type ApprovalView = {
  approvalId: string;
  status: string | null;
  policyCode: string | null;
  riskScore: number | null;
  valueUsd: number | null;
  transactionHash: string | null;
  reason: string | null;
  raw: Record<string, unknown>;
};

/** Pulls the approval out of whichever envelope the server used. */
export function approvalOf(result: ApiResult): ApprovalView | null {
  const body = result.body;

  if (typeof body !== "object" || body === null) {
    return null;
  }

  const candidate =
    (typeof body.approval === "object" && body.approval !== null
      ? body.approval
      : undefined) ??
    (typeof body.approvalId === "string" ? body : undefined) ??
    (typeof body.id === "string" && typeof body.status === "string"
      ? body
      : undefined);

  if (!candidate) {
    return null;
  }

  const approvalId = firstString(candidate.approvalId, candidate.id);

  if (!approvalId) {
    return null;
  }

  return {
    approvalId,
    status: firstString(candidate.status),
    policyCode: firstString(candidate.policyCode, candidate.code),
    riskScore:
      typeof candidate.riskScore === "number" ? candidate.riskScore : null,
    valueUsd: typeof candidate.valueUsd === "number" ? candidate.valueUsd : null,
    transactionHash: firstString(candidate.transactionHash),
    reason: firstString(candidate.reason),
    raw: candidate as Record<string, unknown>,
  };
}

export type RiskView = {
  score: number | null;
  signals: Array<{ id: string; weight: number; explanation: string }>;
};

/** Risk score plus signals. A score with no signals is reported as such. */
export function riskOf(result: ApiResult): RiskView | null {
  const body = result.body;

  if (typeof body !== "object" || body === null) {
    return null;
  }

  const container =
    (typeof body.risk === "object" && body.risk !== null ? body.risk : null) ??
    (typeof body.riskAssessment === "object" && body.riskAssessment !== null
      ? body.riskAssessment
      : null);

  const score =
    typeof container?.score === "number"
      ? container.score
      : typeof body.riskScore === "number"
        ? body.riskScore
        : typeof body.approval?.riskScore === "number"
          ? body.approval.riskScore
          : null;

  const rawSignals =
    (Array.isArray(container?.signals) ? container.signals : null) ??
    (Array.isArray(body.riskSignals) ? body.riskSignals : null) ??
    [];

  if (score === null && rawSignals.length === 0) {
    return null;
  }

  return {
    score,
    signals: rawSignals
      .filter(
        (signal: unknown): signal is Record<string, unknown> =>
          typeof signal === "object" && signal !== null,
      )
      .map((signal: Record<string, unknown>) => ({
        id: String(signal.id ?? signal.signal ?? "UNNAMED_SIGNAL"),
        weight: typeof signal.weight === "number" ? signal.weight : 0,
        explanation: String(signal.explanation ?? signal.reason ?? ""),
      })),
  };
}

/** Everything textual in the response, for substring probes. */
export function responseText(result: ApiResult): string {
  return result.rawBody.toLowerCase();
}
