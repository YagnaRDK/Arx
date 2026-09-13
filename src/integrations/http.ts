/**
 * Outbound HTTP for integration adapters.
 *
 * Every adapter talks to a third party Arx does not control, so every call gets
 * an explicit deadline. A hung dependency must surface as `UNAVAILABLE` and be
 * decided on, not sit inside a request until the agent's client gives up: a
 * timeout that never fires turns a slow oracle into a denial-of-service on the
 * authorization path.
 */

import { unavailable, type Availability } from "../core/seams";

export type HttpFailure = {
  kind: "TIMEOUT" | "NETWORK" | "STATUS" | "DECODE";
  status?: number;
  message: string;
};

export type HttpOutcome<T> =
  | { ok: true; value: T; status: number }
  | { ok: false; failure: HttpFailure };

export const DEFAULT_TIMEOUT_MS = 4_000;

export type JsonRequest = {
  url: string;
  method?: "GET" | "POST";
  headers?: Record<string, string>;
  body?: unknown;
  timeoutMs?: number;
  /** Status codes to hand back as a successful outcome instead of a failure. */
  expectStatuses?: readonly number[];
};

/**
 * Fetches JSON under a hard deadline. Never throws: the caller decides what a
 * failure means, and in Arx an unknown never means "permit".
 */
export async function requestJson<T>(
  request: JsonRequest,
): Promise<HttpOutcome<T>> {
  const timeoutMs = request.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(request.url, {
      method: request.method ?? "GET",
      headers: {
        accept: "application/json",
        ...(request.body === undefined
          ? {}
          : { "content-type": "application/json" }),
        ...request.headers,
      },
      ...(request.body === undefined
        ? {}
        : { body: JSON.stringify(request.body) }),
      signal: controller.signal,
    });

    const accepted =
      response.ok || (request.expectStatuses ?? []).includes(response.status);

    if (!accepted) {
      // The body is read but deliberately truncated: a third party's error text
      // ends up in audit records, and an unbounded one is a log-flooding vector.
      const detail = await safeText(response);

      return {
        ok: false,
        failure: {
          kind: "STATUS",
          status: response.status,
          message: `HTTP ${response.status}${detail ? `: ${detail}` : ""}`,
        },
      };
    }

    try {
      const value = (await response.json()) as T;

      return { ok: true, value, status: response.status };
    } catch (error) {
      return {
        ok: false,
        failure: {
          kind: "DECODE",
          status: response.status,
          message: `Response was not valid JSON: ${describe(error)}`,
        },
      };
    }
  } catch (error) {
    const aborted =
      error instanceof Error &&
      (error.name === "AbortError" || error.name === "TimeoutError");

    return {
      ok: false,
      failure: {
        kind: aborted ? "TIMEOUT" : "NETWORK",
        message: aborted
          ? `Request to ${hostOf(request.url)} exceeded ${timeoutMs}ms`
          : describe(error),
      },
    };
  } finally {
    clearTimeout(timer);
  }
}

/** Turns an HTTP failure into the seam's `UNAVAILABLE`, preserving the reason. */
export function failureToUnavailable<T>(
  provider: string,
  failure: HttpFailure,
): Availability<T> {
  // A 4xx other than 429 is a configuration fault, not a blip: retrying it
  // changes nothing, and telling the operator it is retryable hides the bug.
  const retryable =
    failure.kind === "TIMEOUT" ||
    failure.kind === "NETWORK" ||
    failure.status === 429 ||
    (failure.status ?? 500) >= 500;

  return unavailable<T>(`${provider}: ${failure.message}`, retryable);
}

async function safeText(response: Response): Promise<string> {
  try {
    return (await response.text()).slice(0, 300);
  } catch {
    return "";
  }
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
