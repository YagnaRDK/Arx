/**
 * Speculos REST transport: POSTs APDUs to the emulator's HTTP API.
 *
 * Endpoint and JSON shape verified against Speculos' own OpenAPI document:
 * `POST /apdu` with body `{"data": "<hex>"}`, responding `{"data": "<hex>"}`
 * where the response hex includes the trailing status word (the document's
 * example is request `e0c0000004`, response `105e441f9000`).
 * https://github.com/LedgerHQ/speculos/blob/master/speculos/api/static/swagger/swagger.json
 */

import { ArxError } from "../core/errors";
import { bytesToHex, hexToBytes, type LedgerTransport } from "./apdu";

export type SpeculosHttpTransportConfig = {
  /** Base URL of the Speculos REST API, e.g. `http://127.0.0.1:5000`. */
  apiUrl: string;
  /** Hard ceiling on one exchange. A device waiting on a human still needs a bound. */
  timeoutMs?: number;
};

const DEFAULT_TIMEOUT_MS = 30_000;

export class SpeculosHttpTransport implements LedgerTransport {
  readonly name = "speculos-http";

  private readonly apiUrl: string;
  private readonly timeoutMs: number;

  constructor(config: SpeculosHttpTransportConfig) {
    this.apiUrl = config.apiUrl.replace(/\/+$/, "");
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  async exchange(apdu: Uint8Array): Promise<Uint8Array> {
    let response: Response;

    try {
      response = await fetch(`${this.apiUrl}/apdu`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ data: bytesToHex(apdu) }),
        // An explicit deadline: without it a stalled emulator hangs a request
        // holding an approval open, which is a liveness hole in the signer path.
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      throw new ArxError(
        "SIGNER_UNAVAILABLE",
        `Speculos REST API at ${this.apiUrl} is unreachable`,
        { cause: error },
      );
    }

    if (!response.ok) {
      throw new ArxError(
        "SIGNER_UNAVAILABLE",
        `Speculos REST API returned HTTP ${response.status} for POST /apdu`,
      );
    }

    const body = (await response.json()) as unknown;

    if (
      typeof body !== "object" ||
      body === null ||
      typeof (body as { data?: unknown }).data !== "string"
    ) {
      throw new ArxError(
        "SIGNING_FAILED",
        "Speculos POST /apdu response did not contain a hexadecimal `data` field",
      );
    }

    return hexToBytes((body as { data: string }).data);
  }
}
