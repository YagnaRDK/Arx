import { type DecisionCode, httpStatusForCode } from "./codes";

/**
 * An authorization or transport failure with a machine-readable code.
 *
 * `details` is for operator-facing context (which limit was hit, which field
 * failed). It must never carry secrets: it is returned over HTTP and written to
 * the audit log.
 */
export class ArxError extends Error {
  readonly code: DecisionCode;
  readonly status: number;
  readonly details?: unknown;

  constructor(
    code: DecisionCode,
    message: string,
    options?: { details?: unknown; status?: number; cause?: unknown },
  ) {
    super(message, { cause: options?.cause });

    this.name = "ArxError";
    this.code = code;
    this.status = options?.status ?? httpStatusForCode(code);
    this.details = options?.details;
  }

  toJSON() {
    return {
      allowed: false,
      code: this.code,
      reason: this.message,
      ...(this.details === undefined ? {} : { details: this.details }),
    };
  }
}

export function isArxError(error: unknown): error is ArxError {
  return error instanceof ArxError;
}
