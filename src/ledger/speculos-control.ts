/**
 * The Speculos emulator's automation and observation surface.
 *
 * Endpoints verified against Speculos' OpenAPI document:
 *   POST /apdu               transmit an APDU
 *   GET  /events             list events produced by the app
 *                            (`?currentscreenonly=true` for the visible screen)
 *   DELETE /events           reset the event list
 *   POST /button/{left|right|both}   `{"action": "press-and-release", "delay": 0.1}`
 *   POST /automation         install automation rules
 *   GET  /screenshot         PNG of the current screen
 * https://github.com/LedgerHQ/speculos/blob/master/speculos/api/static/swagger/swagger.json
 *
 * Automation rule semantics (first matching rule wins; `button` action takes
 * `num=1` for left and `num=2` for right, then a boolean for press/release):
 * https://github.com/LedgerHQ/speculos/blob/master/docs/user/automation.md
 *
 * Why this module exists at all: `readDeviceScreens()` is the evidence that a
 * human was shown the real recipient and the real amount. Arx's own
 * clear-signing render (`clear-signing.ts`) says what a device *should* show;
 * this says what the device *did* show. They are different claims and are kept
 * in different modules on purpose.
 */

import { ArxError } from "../core/errors";

export type SpeculosEvent = {
  text: string;
  x?: number;
  y?: number;
  /** Speculos may include further fields; they are preserved for the audit record. */
  [key: string]: unknown;
};

export type DeviceScreenCapture = {
  /** Which surface produced this, e.g. `speculos:GET /events`. */
  source: string;
  /** Always true here: Speculos is an emulator, never a physical secure element. */
  emulated: boolean;
  /** Every text line the app rendered, in the order it rendered them. */
  lines: string[];
  /**
   * Lines grouped into screens. The grouping is a heuristic (a new screen is
   * assumed whenever the vertical position does not advance), so `lines` is the
   * authoritative record and this is a convenience for display.
   */
  screens: string[][];
  /** Raw events, unmodified. */
  events: SpeculosEvent[];
  capturedAt: number;
};

export type SpeculosControlConfig = {
  apiUrl: string;
  timeoutMs?: number;
};

const DEFAULT_TIMEOUT_MS = 10_000;

export type SpeculosButton = "left" | "right" | "both";

export class SpeculosControl {
  private readonly apiUrl: string;
  private readonly timeoutMs: number;

  constructor(config: SpeculosControlConfig) {
    this.apiUrl = config.apiUrl.replace(/\/+$/, "");
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  /** Whether the emulator answers at all. Used by `getStatus()` on the signer. */
  async isReachable(): Promise<boolean> {
    try {
      await this.request("GET", "/events?currentscreenonly=true");
      return true;
    } catch {
      return false;
    }
  }

  /** GET /events — the full event log, or only the visible screen. */
  async getEvents(currentScreenOnly = false): Promise<SpeculosEvent[]> {
    const body = await this.request(
      "GET",
      currentScreenOnly ? "/events?currentscreenonly=true" : "/events",
    );

    const events = (body as { events?: unknown })?.events;

    if (!Array.isArray(events)) {
      throw new ArxError(
        "SIGNER_UNAVAILABLE",
        "Speculos GET /events did not return an `events` array",
      );
    }

    return events as SpeculosEvent[];
  }

  /** DELETE /events — call before a signing flow so the capture is scoped to it. */
  async resetEvents(): Promise<void> {
    await this.request("DELETE", "/events");
  }

  /**
   * The signing flow's device-screen evidence.
   *
   * Captured *after* the exchange completes, from the event log the app wrote
   * while it was reviewing. Pair it with `resetEvents()` before signing so the
   * capture contains only this transaction's screens.
   */
  async readDeviceScreens(): Promise<DeviceScreenCapture> {
    const events = await this.getEvents(false);

    const lines = events
      .map((event) => (typeof event.text === "string" ? event.text : ""))
      .filter((text) => text.length > 0);

    return {
      source: `speculos:GET ${this.apiUrl}/events`,
      emulated: true,
      lines,
      screens: groupEventsIntoScreens(events),
      events,
      capturedAt: Math.floor(Date.now() / 1000),
    };
  }

  /** GET /screenshot — PNG bytes of the current screen. */
  async getScreenshot(): Promise<Uint8Array> {
    const response = await this.fetchRaw("GET", "/screenshot");

    return new Uint8Array(await response.arrayBuffer());
  }

  /** POST /button/{button}. */
  async pressButton(
    button: SpeculosButton,
    delaySeconds = 0.1,
  ): Promise<void> {
    await this.request("POST", `/button/${button}`, {
      action: "press-and-release",
      delay: delaySeconds,
    });
  }

  /** POST /automation — replaces the installed rule set. */
  async setAutomation(rules: unknown): Promise<void> {
    await this.request("POST", "/automation", rules);
  }

  /**
   * Installs rules that walk the review flow and confirm.
   *
   * Gated by the caller on `env.speculosAutoApprove`, which defaults to false.
   * This is a demo convenience and nothing else: it removes the human from the
   * loop, so a capture taken while it is active proves only what the device
   * *displayed*, never that a person agreed to it. `readDeviceScreens()` still
   * records the real screens, which is why auto-approval does not make the
   * evidence worthless — but it must always be reported alongside it.
   */
  async autoApprove(options: { enabled: boolean }): Promise<boolean> {
    if (!options.enabled) {
      return false;
    }

    await this.setAutomation(AUTO_APPROVE_RULES);

    return true;
  }

  private async request(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<unknown> {
    const response = await this.fetchRaw(method, path, body);

    const text = await response.text();

    if (text.trim().length === 0) {
      return {};
    }

    try {
      return JSON.parse(text) as unknown;
    } catch {
      // `/events` can answer as an event stream; the caller handles a non-object.
      return { raw: text };
    }
  }

  private async fetchRaw(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<Response> {
    let response: Response;

    try {
      response = await fetch(`${this.apiUrl}${path}`, {
        method,
        headers:
          body === undefined
            ? { accept: "application/json" }
            : { "content-type": "application/json", accept: "application/json" },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      throw new ArxError(
        "SIGNER_UNAVAILABLE",
        `Speculos control API ${method} ${path} is unreachable at ${this.apiUrl}`,
        { cause: error },
      );
    }

    if (!response.ok) {
      throw new ArxError(
        "SIGNER_UNAVAILABLE",
        `Speculos control API ${method} ${path} returned HTTP ${response.status}`,
      );
    }

    return response;
  }
}

/**
 * Groups an ordered event list into screens.
 *
 * Heuristic, and labelled as such wherever it surfaces: Speculos emits one
 * event per rendered text element with its pixel position, and the app redraws
 * top-down, so a `y` that does not increase marks the start of a new screen.
 */
export function groupEventsIntoScreens(
  events: readonly SpeculosEvent[],
): string[][] {
  const screens: string[][] = [];
  let current: string[] = [];
  let previousY: number | null = null;

  for (const event of events) {
    if (typeof event.text !== "string" || event.text.length === 0) {
      continue;
    }

    const y = typeof event.y === "number" ? event.y : null;

    const startsNewScreen =
      current.length > 0 && (y === null || previousY === null || y <= previousY);

    if (startsNewScreen) {
      screens.push(current);
      current = [];
    }

    current.push(event.text);
    previousY = y;
  }

  if (current.length > 0) {
    screens.push(current);
  }

  return screens;
}

/**
 * Rule set for unattended demos.
 *
 * First matching rule wins, so the confirm rule is listed first and a
 * catch-all "press right to advance" rule follows. Rejection screens are
 * reached only by advancing *past* the confirm screen, which the first rule
 * prevents.
 */
const AUTO_APPROVE_RULES = {
  version: 1,
  rules: [
    {
      // Covers the Nano wording ("Accept and send", "Sign transaction") and the
      // Stax/Flex wording ("Hold to sign", "Approve").
      regexp: "Accept|Approve|Sign transaction|Hold to sign",
      actions: [
        ["button", 1, true],
        ["button", 2, true],
        ["button", 1, false],
        ["button", 2, false],
      ],
    },
    {
      // Default: advance to the next review screen.
      actions: [
        ["button", 2, true],
        ["button", 2, false],
      ],
    },
  ],
} as const;
