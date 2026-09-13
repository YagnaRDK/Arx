import { beforeEach, describe, expect, it } from "bun:test";

/*
 * The approval lifecycle.
 *
 * An approval is the only thing that authorizes a signature, so its state
 * machine is a security boundary rather than bookkeeping. Three properties are
 * under test here:
 *
 *   - the transition table is closed (nothing outside it is reachable),
 *   - claiming an approval is atomic, so one approval yields one signature,
 *   - an approval's authority is bounded by the capability behind it and by
 *     Arx's own signature over it.
 */
process.env.NODE_ENV = "test";
process.env.DATABASE_PATH ??= "./.test-data/arx-suite.sqlite";

const { db, resetDatabaseForTests } = await import("../src/db/database");
const { ApprovalService } = await import("../src/approval/approval-service");
const { HumanApprovalQueue, controlPlaneOperator } = await import(
  "../src/approval/human-approval"
);
const { hashNormalizedTransaction } = await import(
  "../src/approval/transaction-hash"
);
const { ApprovalStore } = await import("../src/storage/approval-store");
const { SpendStore } = await import("../src/storage/spend-store");
const { AuthorizationKey } = await import("../src/crypto/authorization-key");
const { isArxError } = await import("../src/core/errors");
const { ApprovalStatusSchema, canTransition, isTerminal } = await import(
  "../src/types/approval"
);
const { allow, escalate } = await import("../src/types/evaluation");

const ALL_STATUSES = ApprovalStatusSchema.options;
const { AGENT_ID, CAPABILITY_ID, NOW, PAYEE, buildTransaction } = await import(
  "./helpers/fixtures"
);

const approvalStore = new ApprovalStore();
const spendStore = new SpendStore();

/**
 * A key this test controls, rather than the process-wide singleton. Verification
 * is key-bound, so a suite that borrowed the singleton would pass for the wrong
 * reason after a key rotation.
 */
const key = new AuthorizationKey();
const service = new ApprovalService(approvalStore, key);
const queue = new HumanApprovalQueue({ approvalStore, spendStore });

const transaction = buildTransaction();

function createAuto(overrides: { capabilityExpiresAt?: number; now?: number } = {}) {
  return service.createApproval({
    requestId: `req-${crypto.randomUUID()}`,
    capabilityId: CAPABILITY_ID,
    agentId: AGENT_ID,
    transaction,
    decision: allow("within the granted authority"),
    capabilityExpiresAt: overrides.capabilityExpiresAt ?? NOW + 3_600,
    now: overrides.now ?? NOW,
    valueUsd: 32,
    riskScore: 0,
  });
}

function createEscalated(
  overrides: { capabilityExpiresAt?: number; now?: number } = {},
) {
  return service.createApproval({
    requestId: `req-${crypto.randomUUID()}`,
    capabilityId: CAPABILITY_ID,
    agentId: AGENT_ID,
    transaction,
    decision: escalate("risk score is above the autonomous ceiling"),
    capabilityExpiresAt: overrides.capabilityExpiresAt ?? NOW + 3_600,
    now: overrides.now ?? NOW,
    valueUsd: 32,
    riskScore: 72,
  });
}

/** Forces a status without going through the service, to set up a state. */
function forceStatus(approvalId: string, status: string): void {
  db.run("UPDATE approvals SET status = ? WHERE approval_id = ?", [
    status,
    approvalId,
  ]);
}

beforeEach(() => {
  resetDatabaseForTests();
});

describe("approval state machine: the transition table", () => {
  it("permits exactly the documented transitions and nothing else", () => {
    // Written out in full rather than derived from the table under test, so a
    // change to the table has to be a deliberate change to this list too.
    const legal: Record<string, string[]> = {
      PENDING_HUMAN: ["APPROVED", "REJECTED", "EXPIRED", "REVOKED"],
      APPROVED: ["SIGNING", "EXPIRED", "REVOKED"],
      SIGNING: ["CONSUMED", "SIGNING_FAILED"],
      CONSUMED: [],
      SIGNING_FAILED: [],
      REJECTED: [],
      REVOKED: [],
      EXPIRED: [],
    };

    for (const from of ALL_STATUSES) {
      for (const to of ALL_STATUSES) {
        expect({ from, to, allowed: canTransition(from, to) }).toEqual({
          from,
          to,
          allowed: legal[from]!.includes(to),
        });
      }
    }
  });

  it("treats every end state as terminal", () => {
    for (const status of [
      "CONSUMED",
      "SIGNING_FAILED",
      "REJECTED",
      "REVOKED",
      "EXPIRED",
    ] as const) {
      expect(isTerminal(status)).toBe(true);
    }

    for (const status of ["PENDING_HUMAN", "APPROVED", "SIGNING"] as const) {
      expect(isTerminal(status)).toBe(false);
    }
  });

  it("refuses a revival of a terminal approval, which is the transition that matters", () => {
    // CONSUMED -> APPROVED would make one authorization reusable forever.
    expect(canTransition("CONSUMED", "APPROVED")).toBe(false);
    expect(canTransition("SIGNING_FAILED", "APPROVED")).toBe(false);
    expect(canTransition("REJECTED", "APPROVED")).toBe(false);
    expect(canTransition("EXPIRED", "APPROVED")).toBe(false);
    // And the shortcut that would skip the atomic claim entirely.
    expect(canTransition("APPROVED", "CONSUMED")).toBe(false);
    expect(canTransition("PENDING_HUMAN", "SIGNING")).toBe(false);
  });

  it("throws rather than performing an illegal transition through the service", () => {
    const approval = createAuto();

    forceStatus(approval.approvalId, "CONSUMED");

    // `markSigned` is SIGNING -> CONSUMED; there is no service method that can
    // express CONSUMED -> SIGNING, and the guard is checked before the write.
    expect(service.markSigned(approval.approvalId)).toBe(false);
    expect(service.get(approval.approvalId)?.status).toBe("CONSUMED");
  });
});

describe("approval state machine: legal walks", () => {
  it("walks the autonomous path APPROVED -> SIGNING -> CONSUMED", () => {
    const approval = createAuto();

    expect(approval.status).toBe("APPROVED");
    expect(approval.approvalType).toBe("AUTO");
    expect(approval.policyCode).toBe("POLICY_APPROVED");

    expect(service.claimForSigning(approval.approvalId)).toBe(true);
    expect(service.get(approval.approvalId)?.status).toBe("SIGNING");

    expect(service.markSigned(approval.approvalId)).toBe(true);
    expect(service.get(approval.approvalId)?.status).toBe("CONSUMED");
  });

  it("walks the escalated path PENDING_HUMAN -> APPROVED -> SIGNING -> CONSUMED", () => {
    const approval = createEscalated();

    expect(approval.status).toBe("PENDING_HUMAN");
    expect(approval.approvalType).toBe("HUMAN");
    expect(approval.policyCode).toBe("HUMAN_APPROVAL_REQUIRED");

    const granted = queue.approve(
      approval.approvalId,
      controlPlaneOperator("operator-1"),
      { now: NOW },
    );

    expect(granted.status).toBe("APPROVED");
    expect(granted.decidedBy).toBe("operator-1");
    expect(granted.decidedAt).toBe(NOW);

    expect(service.claimForSigning(approval.approvalId)).toBe(true);
    expect(service.markSigned(approval.approvalId)).toBe(true);
    expect(service.get(approval.approvalId)?.status).toBe("CONSUMED");
  });

  it("walks PENDING_HUMAN -> REJECTED and stays there", () => {
    const approval = createEscalated();

    const rejected = queue.reject(
      approval.approvalId,
      controlPlaneOperator("operator-1"),
      "recipient is not a known supplier",
      { now: NOW },
    );

    expect(rejected.status).toBe("REJECTED");

    // Terminal: a denied proposal can never be revived.
    expect(() =>
      queue.approve(approval.approvalId, controlPlaneOperator("operator-2"), {
        now: NOW,
      }),
    ).toThrow();
    expect(service.get(approval.approvalId)?.status).toBe("REJECTED");
  });

  it("walks APPROVED -> SIGNING -> SIGNING_FAILED", () => {
    const approval = createAuto();

    expect(service.claimForSigning(approval.approvalId)).toBe(true);
    expect(service.markSigningFailed(approval.approvalId)).toBe(true);
    expect(service.get(approval.approvalId)?.status).toBe("SIGNING_FAILED");
  });

  it("expires both APPROVED and PENDING_HUMAN through the sweep", () => {
    const auto = createAuto({ capabilityExpiresAt: NOW + 60 });
    const escalated = createEscalated({ capabilityExpiresAt: NOW + 60 });

    expect(approvalStore.expireOverdue(NOW + 61)).toBe(2);
    expect(service.get(auto.approvalId)?.status).toBe("EXPIRED");
    expect(service.get(escalated.approvalId)?.status).toBe("EXPIRED");
  });

  it("leaves a claimed approval alone when the sweep runs", () => {
    // An approval that a request has already claimed may be moments from a
    // device signature. Expiring it out from under that request would be a
    // different bug from the one the sweeper exists to fix.
    const approval = createAuto({ capabilityExpiresAt: NOW + 60 });

    expect(service.claimForSigning(approval.approvalId)).toBe(true);
    expect(approvalStore.expireOverdue(NOW + 61)).toBe(0);
    expect(service.get(approval.approvalId)?.status).toBe("SIGNING");
  });
});

describe("approval state machine: representative illegal moves from each state", () => {
  it("PENDING_HUMAN cannot be claimed for signing", () => {
    const approval = createEscalated();

    expect(service.claimForSigning(approval.approvalId)).toBe(false);
    expect(service.get(approval.approvalId)?.status).toBe("PENDING_HUMAN");
  });

  it("APPROVED cannot be marked signed without first being claimed", () => {
    // The claim is what makes the approval exclusive. Skipping it is the
    // double-sign race.
    const approval = createAuto();

    expect(service.markSigned(approval.approvalId)).toBe(false);
    expect(service.get(approval.approvalId)?.status).toBe("APPROVED");
  });

  it("SIGNING cannot be claimed a second time", () => {
    const approval = createAuto();

    expect(service.claimForSigning(approval.approvalId)).toBe(true);
    expect(service.claimForSigning(approval.approvalId)).toBe(false);
  });

  it("CONSUMED cannot be claimed again", () => {
    const approval = createAuto();

    service.claimForSigning(approval.approvalId);
    service.markSigned(approval.approvalId);

    expect(service.claimForSigning(approval.approvalId)).toBe(false);
  });

  it("SIGNING_FAILED is terminal and is not retryable", () => {
    // Deliberately not returned to APPROVED: a failed attempt may already have
    // reached the device. A new authorization request is the recovery path.
    const approval = createAuto();

    service.claimForSigning(approval.approvalId);
    service.markSigningFailed(approval.approvalId);

    expect(service.claimForSigning(approval.approvalId)).toBe(false);
    expect(service.markSigned(approval.approvalId)).toBe(false);
    expect(service.get(approval.approvalId)?.status).toBe("SIGNING_FAILED");

    const verification = service.verifyApproval({
      approval: service.get(approval.approvalId)!,
      transaction,
      currentTime: NOW,
    });

    expect(verification.valid).toBe(false);
    expect(verification.code).toBe("APPROVAL_STATE_CONFLICT");
    expect(verification.reason).toContain("not retryable");
  });

  it("REJECTED cannot be claimed for signing", () => {
    const approval = createEscalated();

    queue.reject(approval.approvalId, controlPlaneOperator("op"), "no", {
      now: NOW,
    });

    expect(service.claimForSigning(approval.approvalId)).toBe(false);
  });

  it("EXPIRED cannot be claimed for signing", () => {
    const approval = createAuto({ capabilityExpiresAt: NOW + 60 });

    approvalStore.expireOverdue(NOW + 61);

    expect(service.claimForSigning(approval.approvalId)).toBe(false);
  });

  it("REVOKED cannot be claimed for signing", () => {
    const approval = createAuto();

    forceStatus(approval.approvalId, "REVOKED");

    expect(service.claimForSigning(approval.approvalId)).toBe(false);
  });
});

describe("claimForSigning is atomic", () => {
  it("yields exactly one winner from eight concurrent claims", async () => {
    /*
     * bun:sqlite is synchronous, so `Promise.all` does not truly interleave the
     * UPDATE statements — what this proves is the exactly-once semantics of the
     * compare-and-swap, which is the property the HTTP layer depends on. The
     * genuinely concurrent version of this test is the eight-parallel
     * `POST /sign` in `tests/end-to-end.test.ts`.
     */
    const approval = createAuto();

    const results = await Promise.all(
      Array.from({ length: 8 }, async () =>
        service.claimForSigning(approval.approvalId),
      ),
    );

    expect(results.filter(Boolean)).toHaveLength(1);
    expect(service.get(approval.approvalId)?.status).toBe("SIGNING");
  });

  it("yields exactly one winner when two operators race to decide", () => {
    const approval = createEscalated();

    const first = approvalStore.decide(
      approval.approvalId,
      "PENDING_HUMAN",
      "APPROVED",
      "operator-1",
      NOW,
    );
    const second = approvalStore.decide(
      approval.approvalId,
      "PENDING_HUMAN",
      "REJECTED",
      "operator-2",
      NOW,
    );

    expect(first).toBe(true);
    expect(second).toBe(false);
    expect(service.get(approval.approvalId)?.decidedBy).toBe("operator-1");
  });

  it("reports a lost decision race as a conflict rather than a success", () => {
    const approval = createEscalated();

    queue.approve(approval.approvalId, controlPlaneOperator("op-1"), {
      now: NOW,
    });

    try {
      queue.reject(approval.approvalId, controlPlaneOperator("op-2"), "no", {
        now: NOW,
      });
      throw new Error("expected the second decision to be refused");
    } catch (error) {
      expect(isArxError(error)).toBe(true);
      if (isArxError(error)) {
        expect(error.code).toBe("APPROVAL_STATE_CONFLICT");
      }
    }
  });
});

describe("approval verification", () => {
  it("accepts an APPROVED approval bound to this exact transaction", () => {
    const approval = createAuto();

    const verification = service.verifyApproval({
      approval,
      transaction,
      currentTime: NOW,
    });

    expect(verification).toMatchObject({
      valid: true,
      code: "POLICY_APPROVED",
    });
  });

  it("refuses a PENDING_HUMAN approval and accepts it once a human grants it", () => {
    const approval = createEscalated();

    const before = service.verifyApproval({
      approval,
      transaction,
      currentTime: NOW,
    });

    expect(before.valid).toBe(false);
    expect(before.code).toBe("APPROVAL_PENDING_HUMAN");

    const granted = queue.approve(
      approval.approvalId,
      controlPlaneOperator("operator-1"),
      { now: NOW },
    );

    const after = service.verifyApproval({
      approval: granted,
      transaction,
      currentTime: NOW,
    });

    expect(after.valid).toBe(true);
    // The signature was made before the human decided, and still verifies: the
    // binding payload deliberately excludes the mutable lifecycle fields.
    expect(granted.authorizationSignature).toBe(
      approval.authorizationSignature,
    );
  });

  it("refuses an approval at the exact second it expires", () => {
    const approval = createAuto({ capabilityExpiresAt: NOW + 60 });

    expect(
      service.verifyApproval({
        approval,
        transaction,
        currentTime: approval.expiresAt - 1,
      }).valid,
    ).toBe(true);

    expect(
      service.verifyApproval({
        approval,
        transaction,
        currentTime: approval.expiresAt,
      }),
    ).toMatchObject({ valid: false, code: "APPROVAL_EXPIRED" });
  });

  it("refuses a transaction whose bytes differ from the approved ones", () => {
    const approval = createAuto();
    const mutated = buildTransaction({ value: "10000000000000001" });

    expect(
      service.verifyApproval({
        approval,
        transaction: mutated,
        currentTime: NOW,
      }),
    ).toMatchObject({ valid: false, code: "TRANSACTION_HASH_MISMATCH" });
  });

  it("refuses an approval issued to a different agent", () => {
    const approval = createAuto();
    const other = buildTransaction({}, { agentId: "other-agent" });

    expect(
      service.verifyApproval({
        approval,
        transaction: other,
        currentTime: NOW,
      }).valid,
    ).toBe(false);
  });

  it("refuses an approval carrying no authorization signature", () => {
    const approval = createAuto();

    db.run(
      "UPDATE approvals SET authorization_signature = NULL, authorization_key_id = NULL WHERE approval_id = ?",
      [approval.approvalId],
    );

    expect(
      service.verifyApproval({
        approval: service.get(approval.approvalId)!,
        transaction,
        currentTime: NOW,
      }),
    ).toMatchObject({
      valid: false,
      code: "APPROVAL_SIGNATURE_INVALID",
    });
  });

  it("refuses an approval whose signature was tampered with in the database", () => {
    // Database write access must not be sufficient to obtain a signature.
    const approval = createAuto();
    const forged = Buffer.alloc(64, 7).toString("base64");

    db.run(
      "UPDATE approvals SET authorization_signature = ? WHERE approval_id = ?",
      [forged, approval.approvalId],
    );

    expect(
      service.verifyApproval({
        approval: service.get(approval.approvalId)!,
        transaction,
        currentTime: NOW,
      }),
    ).toMatchObject({
      valid: false,
      code: "APPROVAL_SIGNATURE_INVALID",
    });
  });

  it("refuses an approval whose bound fields were edited under a valid signature", () => {
    // The attack this closes: raise `valueUsd` (or extend `expiresAt`) on a
    // genuine row and leave Arx's signature in place.
    const approval = createAuto();

    db.run(
      "UPDATE approvals SET value_usd = 9999999, expires_at = ? WHERE approval_id = ?",
      [NOW + 86_400, approval.approvalId],
    );

    const reread = service.get(approval.approvalId)!;

    expect(reread.valueUsd).toBe(9999999);
    expect(
      service.verifyApproval({
        approval: reread,
        transaction,
        currentTime: NOW,
      }),
    ).toMatchObject({
      valid: false,
      code: "APPROVAL_SIGNATURE_INVALID",
    });
  });

  it("refuses an approval signed by a key that is not the active one", () => {
    // A rotated (or ephemeral, post-restart) key leaves approvals that cannot
    // be verified, and an unverifiable approval is not a valid one.
    const approval = createAuto();
    const otherService = new ApprovalService(
      approvalStore,
      new AuthorizationKey(),
    );

    expect(
      otherService.verifyApproval({
        approval,
        transaction,
        currentTime: NOW,
      }),
    ).toMatchObject({
      valid: false,
      code: "APPROVAL_SIGNATURE_INVALID",
    });
  });

  it("binds the signature to the transaction hash, not to the summary", () => {
    // The summary is display evidence for a human reviewer. Editing it must not
    // be able to make an unapproved transaction signable, and it must not
    // silently invalidate a genuine approval either.
    const approval = createAuto();

    db.run("UPDATE approvals SET summary = ? WHERE approval_id = ?", [
      JSON.stringify({
        to: PAYEE,
        valueWei: "1",
        chainId: 11_155_111,
        selector: null,
        method: null,
        calldataRecipients: [],
      }),
      approval.approvalId,
    ]);

    const reread = service.get(approval.approvalId)!;

    expect(reread.summary?.valueWei).toBe("1");
    expect(reread.transactionHash).toBe(hashNormalizedTransaction(transaction));
    expect(
      service.verifyApproval({
        approval: reread,
        transaction,
        currentTime: NOW,
      }).valid,
    ).toBe(true);
  });
});

describe("an approval never outlives its capability", () => {
  it("caps an autonomous approval's TTL at the capability's expiry", () => {
    const approval = createAuto({ capabilityExpiresAt: NOW + 10 });

    expect(approval.expiresAt).toBe(NOW + 10);
  });

  it("caps an escalation's longer TTL at the capability's expiry", () => {
    // The human TTL is 15 minutes by default; a capability with 30 seconds left
    // must not grant a 15-minute signing window.
    const approval = createEscalated({ capabilityExpiresAt: NOW + 30 });

    expect(approval.expiresAt).toBe(NOW + 30);
  });

  it("gives an escalation the longer TTL when the capability allows it", () => {
    const auto = createAuto();
    const escalated = createEscalated();

    expect(escalated.expiresAt - NOW).toBeGreaterThan(auto.expiresAt - NOW);
  });

  it("refuses to issue an approval under an already-expired capability", () => {
    expect(() => createAuto({ capabilityExpiresAt: NOW })).toThrow();

    try {
      createAuto({ capabilityExpiresAt: NOW - 1 });
    } catch (error) {
      expect(isArxError(error)).toBe(true);
      if (isArxError(error)) {
        expect(error.code).toBe("CAPABILITY_EXPIRED");
      }
    }
  });

  it("refuses to mint an approval from a denied decision", () => {
    // Fail closed: reaching here means a caller ignored the decision, which is
    // a defect rather than a request outcome.
    try {
      service.createApproval({
        requestId: "req-denied",
        capabilityId: CAPABILITY_ID,
        agentId: AGENT_ID,
        transaction,
        decision: {
          allowed: false,
          code: "RECIPIENT_NOT_ALLOWED",
          reason: "denied",
          decision: "DENY",
        },
        capabilityExpiresAt: NOW + 3_600,
        now: NOW,
      });
      throw new Error("expected approval creation to be refused");
    } catch (error) {
      expect(isArxError(error)).toBe(true);
      if (isArxError(error)) {
        expect(error.code).toBe("INTERNAL_ERROR");
      }
    }
  });

  it("expires an escalation that timed out rather than approving it late", () => {
    // A late grant would be a decision made against stale prices, stale risk
    // and stale capability state.
    const approval = createEscalated({ capabilityExpiresAt: NOW + 30 });

    try {
      queue.approve(approval.approvalId, controlPlaneOperator("op"), {
        now: approval.expiresAt,
      });
      throw new Error("expected the late grant to be refused");
    } catch (error) {
      expect(isArxError(error)).toBe(true);
      if (isArxError(error)) {
        expect(error.code).toBe("APPROVAL_EXPIRED");
      }
    }

    expect(service.get(approval.approvalId)?.status).toBe("EXPIRED");
  });
});

describe("an agent cannot resolve its own escalation", () => {
  it("refuses a decision whose actor is the proposing agent", () => {
    // The runtime backstop behind the admin-credential control. If an agent
    // could approve itself, escalation would be decoration.
    const approval = createEscalated();

    try {
      queue.approve(approval.approvalId, AGENT_ID, { now: NOW });
      throw new Error("expected self-approval to be refused");
    } catch (error) {
      expect(isArxError(error)).toBe(true);
      if (isArxError(error)) {
        expect(error.code).toBe("FORBIDDEN");
      }
    }

    expect(service.get(approval.approvalId)?.status).toBe("PENDING_HUMAN");
  });

  it("refuses a self-rejection too, so the agent cannot clear its own queue", () => {
    const approval = createEscalated();

    expect(() =>
      queue.reject(approval.approvalId, AGENT_ID, "never mind", { now: NOW }),
    ).toThrow();
    expect(service.get(approval.approvalId)?.status).toBe("PENDING_HUMAN");
  });

  it("refuses an anonymous decision", () => {
    const approval = createEscalated();

    expect(() =>
      queue.approve(approval.approvalId, "   ", { now: NOW }),
    ).toThrow();
  });
});
