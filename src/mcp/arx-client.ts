import { type Availability, ok, unavailable } from "../core/seams";
import type { DecisionCode } from "../core/codes";
import type { EvmTransaction } from "../types/transaction";
import type { ArxMcpConfig } from "./config";

/**
 * The HTTP client the MCP tools speak through.
 *
 * The MCP server deliberately does not import the policy engine. If it did, a
 * compromised agent process would be running the authorization code in its own
 * address space, and the trust boundary would be a naming convention rather
 * than a boundary. Everything here goes over the wire to an Arx the agent
 * cannot modify.
 *
 * Every method returns `Availability<T>`: "Arx answered, here is the answer" is
 * a different fact from "Arx could not be asked". The tool layer turns the
 * second into a refusal, never into a pass.
 */

export type ArxDecision = "ALLOW" | "DENY" | "ESCALATE" | "ABORT";

/** Which stage of the Arx pipeline actually produced the answer. */
export type PipelineStage = "APPROVALS" | "FIREWALL" | "POLICY";

export type ProposalOutcome = {
  decision: ArxDecision;
  code: DecisionCode | string;
  reason: string;
  requestId?: string;
  /** Present only when a real approval artifact was minted. */
  approvalId?: string;
  transactionId?: string;
  transactionHash?: string;
  approvalExpiresAt?: number;
  /**
   * True only when Arx returned an approval that binds these exact transaction
   * bytes. A decision from a weaker pipeline stage is informative but confers
   * no signing authority, and says so.
   */
  signable: boolean;
  stage: PipelineStage;
  httpStatus: number;
  details?: unknown;
  /** Operator-facing notes about degraded behaviour. Never hidden. */
  warnings: string[];
};

export type ApprovalView = {
  approvalId: string;
  status: string;
  agentId?: string;
  capabilityId?: string;
  transactionId?: string;
  transactionHash?: string;
  expiresAt?: number;
  createdAt?: number;
  riskScore?: number;
  reason?: string;
  policyCode?: string;
  raw: unknown;
};

export type SignatureOutcome = {
  status: string;
  approvalId?: string;
  transactionId?: string;
  signedTransaction?: string;
  signerAdapter?: string;
  signerAddress?: string;
  /**
   * True when the signature did not come from a real signing device. The mock
   * adapter emits `0xmock_<digest>`, which is not a valid Ethereum signature
   * and must never be presented as one (invariant 8).
   */
  simulated: boolean;
  simulationNote?: string;
  raw: unknown;
};

export type AuditTrailView = {
  requestId: string;
  entries: unknown[];
  raw: unknown;
};

export type ChainVerificationView = {
  valid: boolean;
  entries?: number;
  headHash?: string;
  brokenAtSeq?: number;
  problem?: string;
  raw: unknown;
};

type RawResponse = { status: number; body: unknown; text: string };

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object"
    ? (value as Record<string, unknown>)
    : {};
}

function str(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function num(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value)
    ? value
    : undefined;
}

/**
 * Fastify answers an unregistered route with a 404 carrying `"Route ... not
 * found"`. That is different from a 404 produced by a handler (an approval that
 * does not exist), and only the first justifies trying another spelling.
 */
function isMissingRoute(response: RawResponse): boolean {
  if (response.status !== 404) {
    return false;
  }

  const body = asRecord(response.body);
  const message = str(body.message) ?? response.text;

  return /route .* not found/i.test(message ?? "");
}

function looksLikeMockSignature(signed: string | undefined): boolean {
  return signed !== undefined && signed.toLowerCase().startsWith("0xmock");
}

export class ArxClient {
  constructor(private readonly config: ArxMcpConfig) {}

  get baseUrl(): string {
    return this.config.baseUrl;
  }

  private headers(): Record<string, string> {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      accept: "application/json",
    };

    if (this.config.agentId) {
      headers["x-arx-agent-id"] = this.config.agentId;
    }

    if (this.config.agentToken) {
      headers.authorization = `Bearer ${this.config.agentToken}`;
    }

    return headers;
  }

  private async request(
    method: "GET" | "POST",
    path: string,
    body?: unknown,
  ): Promise<Availability<RawResponse>> {
    const url = `${this.config.baseUrl}${path}`;

    try {
      const response = await fetch(url, {
        method,
        headers: this.headers(),
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(this.config.requestTimeoutMs),
      });

      const text = await response.text();

      let parsed: unknown = undefined;

      try {
        parsed = text.length > 0 ? JSON.parse(text) : undefined;
      } catch {
        parsed = undefined;
      }

      return ok({ status: response.status, body: parsed, text });
    } catch (error) {
      return unavailable(
        `Arx at ${this.config.baseUrl} is unreachable: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }

  /** Tries each candidate spelling, stopping at the first route that exists. */
  private async requestFirstAvailable(
    method: "GET" | "POST",
    paths: readonly string[],
    body?: unknown,
  ): Promise<Availability<RawResponse>> {
    let lastUnavailable: Availability<RawResponse> | undefined;

    for (const path of paths) {
      const result = await this.request(method, path, body);

      if (result.status === "UNAVAILABLE") {
        lastUnavailable = result;
        continue;
      }

      if (isMissingRoute(result.value)) {
        continue;
      }

      return result;
    }

    return (
      lastUnavailable ??
      unavailable(
        `None of these Arx routes exist on this build: ${paths.join(", ")}`,
        false,
      )
    );
  }

  /**
   * Submits an intent plus the transaction bytes it claims to represent.
   *
   * `POST /approvals` is the only stage that can mint an approval, so it is
   * tried first. If that route is absent or erroring, the weaker stages still
   * yield a real decision — and because they cannot produce an approval, the
   * fallback can never turn a failure into signing authority. It degrades the
   * agent's reach, which is the correct direction.
   */
  async propose(intent: unknown): Promise<Availability<ProposalOutcome>> {
    const warnings: string[] = [];

    const attempts: Array<{ stage: PipelineStage; path: string }> = [
      { stage: "APPROVALS", path: this.config.routes.propose },
      { stage: "FIREWALL", path: this.config.routes.proposeFirewallFallback },
      { stage: "POLICY", path: this.config.routes.proposePolicyFallback },
    ];

    let lastUnavailable: Availability<ProposalOutcome> | undefined;

    for (const attempt of attempts) {
      const result = await this.request("POST", attempt.path, intent);

      if (result.status === "UNAVAILABLE") {
        lastUnavailable = unavailable(result.reason, result.retryable);
        break;
      }

      const response = result.value;

      if (isMissingRoute(response)) {
        warnings.push(
          `Arx has no ${attempt.path} route; fell back to a weaker pipeline stage.`,
        );
        continue;
      }

      // A 5xx is Arx failing, not Arx deciding. Retrying a lesser stage gives
      // the agent an honest decision without giving it an approval.
      if (response.status >= 500) {
        const body = asRecord(response.body);
        warnings.push(
          `Arx returned ${response.status} from ${attempt.path} (${
            str(body.message) ?? "no message"
          }); fell back to a weaker pipeline stage that cannot authorize signing.`,
        );
        continue;
      }

      return ok(this.interpretProposal(response, attempt.stage, warnings));
    }

    return (
      lastUnavailable ??
      unavailable(
        `No Arx endpoint could decide this proposal. Attempted: ${attempts
          .map((attempt) => attempt.path)
          .join(", ")}. ${warnings.join(" ")}`,
        true,
      )
    );
  }

  private interpretProposal(
    response: RawResponse,
    stage: PipelineStage,
    warnings: string[],
  ): ProposalOutcome {
    const body = asRecord(response.body);
    const approval = asRecord(body.approval);

    const code = str(body.code) ?? (response.status < 300 ? "POLICY_APPROVED" : "FORBIDDEN");
    const approvalStatus = str(approval.status);

    let decision: ArxDecision;

    if (str(body.decision) === "ALLOW") {
      decision = "ALLOW";
    } else if (str(body.decision) === "DENY") {
      decision = "DENY";
    } else if (str(body.decision) === "ESCALATE") {
      decision = "ESCALATE";
    } else if (str(body.decision) === "ABORT") {
      decision = "ABORT";
    } else if (response.status < 300) {
      decision = "ALLOW";
    } else {
      decision = "DENY";
    }

    // The code is authoritative over the HTTP status: a 202 or a 403 that names
    // HUMAN_APPROVAL_REQUIRED is an escalation, not a refusal.
    if (code === "HUMAN_APPROVAL_REQUIRED" || approvalStatus === "PENDING_HUMAN") {
      decision = "ESCALATE";
    }

    const approvalId = str(approval.approvalId);
    const signable =
      stage === "APPROVALS" &&
      decision === "ALLOW" &&
      approvalId !== undefined &&
      approvalStatus === "APPROVED";

    if (decision === "ALLOW" && !signable) {
      warnings.push(
        stage === "APPROVALS"
          ? "Arx allowed the proposal but returned no usable approval artifact, so nothing can be signed."
          : `Decision came from the ${stage} stage, which does not mint approvals. No signature can be obtained with it.`,
      );
    }

    return {
      decision,
      code,
      reason:
        str(body.reason) ??
        str(asRecord(body.policy).reason) ??
        str(approval.reason) ??
        str(body.status) ??
        (decision === "ALLOW" ? "Within granted authority" : "Refused by Arx"),
      requestId: str(body.requestId),
      approvalId,
      transactionId: str(approval.transactionId) ?? str(body.transactionId),
      transactionHash: str(approval.transactionHash),
      approvalExpiresAt: num(approval.expiresAt),
      signable,
      stage,
      httpStatus: response.status,
      details: body.details,
      warnings,
    };
  }

  async getApproval(
    approvalId: string,
  ): Promise<Availability<ApprovalView | null>> {
    const path = this.config.routes.approvalById.replace(
      "{approvalId}",
      encodeURIComponent(approvalId),
    );

    const result = await this.request("GET", path);

    if (result.status === "UNAVAILABLE") {
      return result;
    }

    if (result.value.status === 404) {
      return ok(null);
    }

    const body = asRecord(result.value.body);
    const approval = asRecord(body.approval ?? body);

    return ok({
      approvalId: str(approval.approvalId) ?? approvalId,
      status: str(approval.status) ?? "UNKNOWN",
      agentId: str(approval.agentId),
      capabilityId: str(approval.capabilityId),
      transactionId: str(approval.transactionId),
      transactionHash: str(approval.transactionHash),
      expiresAt: num(approval.expiresAt),
      createdAt: num(approval.createdAt),
      riskScore: num(approval.riskScore),
      reason: str(approval.reason),
      policyCode: str(approval.policyCode),
      raw: result.value.body,
    });
  }

  async requestSignature(input: {
    approvalId: string;
    transaction: EvmTransaction;
  }): Promise<Availability<SignatureOutcome>> {
    const result = await this.request("POST", this.config.routes.sign, {
      approvalId: input.approvalId,
      transaction: input.transaction,
    });

    if (result.status === "UNAVAILABLE") {
      return result;
    }

    const body = asRecord(result.value.body);
    const signer = asRecord(body.signer);
    const signed = str(body.signedTransaction);
    const adapter = str(signer.adapter) ?? str(body.signerAdapter);

    const simulated =
      looksLikeMockSignature(signed) ||
      (adapter !== undefined && /mock|emulat|speculos/i.test(adapter));

    if (result.value.status >= 300) {
      return ok({
        status: str(body.code) ?? `HTTP_${result.value.status}`,
        approvalId: input.approvalId,
        simulated: false,
        raw: result.value.body,
      });
    }

    return ok({
      status: str(body.status) ?? "SIGNED",
      approvalId: str(body.approvalId) ?? input.approvalId,
      transactionId: str(body.transactionId),
      signedTransaction: signed,
      signerAdapter: adapter,
      signerAddress: str(signer.address),
      simulated,
      simulationNote: simulated
        ? "SIMULATED SIGNATURE. This came from an emulated or mock signer and is not a valid Ethereum signature. Do not broadcast it and do not describe it as signed by a hardware device."
        : undefined,
      raw: result.value.body,
    });
  }

  async listCapabilities(input: {
    agentId?: string;
    capabilityId?: string;
  }): Promise<Availability<unknown[]>> {
    if (input.capabilityId) {
      const path = this.config.routes.capabilityById.replace(
        "{capabilityId}",
        encodeURIComponent(input.capabilityId),
      );

      const result = await this.request("GET", path);

      if (result.status === "UNAVAILABLE") {
        return result;
      }

      if (result.value.status === 404) {
        return ok([]);
      }

      const body = asRecord(result.value.body);

      return ok([body.capability ?? result.value.body]);
    }

    const agentId = input.agentId ?? this.config.agentId;

    if (!agentId) {
      return unavailable(
        "No agentId was supplied and none is configured, so the set of held capabilities cannot be determined.",
        false,
      );
    }

    const paths = this.config.routes.capabilitiesByAgent.map((path) =>
      path.replace("{agentId}", encodeURIComponent(agentId)),
    );

    const result = await this.requestFirstAvailable("GET", paths);

    if (result.status === "UNAVAILABLE") {
      return result;
    }

    const body = asRecord(result.value.body);
    const list = body.capabilities ?? result.value.body;

    return ok(Array.isArray(list) ? list : []);
  }

  async getAuditTrail(
    requestId: string,
  ): Promise<Availability<AuditTrailView>> {
    const paths = this.config.routes.auditTrail.map((path) =>
      path.replace("{requestId}", encodeURIComponent(requestId)),
    );

    const result = await this.requestFirstAvailable("GET", paths);

    if (result.status === "UNAVAILABLE") {
      return result;
    }

    const body = asRecord(result.value.body);
    const entries = body.entries ?? body.trail ?? result.value.body;

    return ok({
      requestId,
      entries: Array.isArray(entries) ? entries : [],
      raw: result.value.body,
    });
  }

  async verifyAuditChain(): Promise<Availability<ChainVerificationView>> {
    const result = await this.requestFirstAvailable(
      "GET",
      this.config.routes.auditVerify,
    );

    if (result.status === "UNAVAILABLE") {
      return result;
    }

    const body = asRecord(result.value.body);
    const verification = asRecord(body.verification ?? body);

    return ok({
      valid: verification.valid === true,
      entries: num(verification.entries),
      headHash: str(verification.headHash),
      brokenAtSeq: num(verification.brokenAtSeq),
      problem: str(verification.problem),
      raw: result.value.body,
    });
  }
}
