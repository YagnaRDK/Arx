# Arx architecture

## The problem

An autonomous agent that can move money needs authority. The usual way to give
it authority is a private key or an API credential, which grants everything that
credential can do, for as long as it exists.

That is a poor fit for a system whose behaviour is steered by text it did not
write. Prompt injection, a poisoned tool result, or a compromised model turns
"the agent can pay suppliers" into "the attacker can pay themselves". The agent
is not malfunctioning when this happens — it is doing what it was convinced to
do. Better reasoning does not fix it, because the problem is not intelligence.

**The problem is authority.**

## The boundary

```
  untrusted input ──┐
  (email, web, tool │
   output, RAG)     │
                    ▼
            ┌───────────────┐
            │   AI agent    │   may be hijacked; holds no key
            └───────┬───────┘
                    │ proposes an intent + transaction
════════════════════▼════════════════════════════════════════
        THE AGENT CANNOT REACH PAST THIS LINE
════════════════════╪════════════════════════════════════════
                    ▼
     ┌──────────────────────────────┐
     │          ARX KERNEL          │  no model, no prompt,
     │                              │  deterministic
     │  normalize   canonical form  │
     │  capability  is it granted?  │
     │  policy      is it in scope? │
     │  firewall    what do the     │
     │              bytes do?       │
     │  risk        explainable     │
     │  approval    bound artifact  │
     └──────────────┬───────────────┘
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
   ALLOW / DENY            ESCALATE
   / ABORT                      │
        │                       ▼
        │              ┌─────────────────┐
        │              │ human at device │
        │              └────────┬────────┘
        ▼                       ▼
     ┌──────────────────────────────┐
     │       SIGNER BOUNDARY        │
     │  DMK → Speculos / hardware   │
     │  Trusted Display shows the   │
     │  transaction; the Secure     │
     │  Element holds the key       │
     └──────────────┬───────────────┘
                    ▼
          signature + audit entry
```

The kernel is the point. It contains no model, issues no prompts, and makes no
network calls on the decision path — so there is nothing in it to inject into.
It is a pure function of the capability, the intent, the transaction bytes and
the clock.

## Pipeline

| Stage | Question | Module |
|---|---|---|
| Normalize | What exactly is this transaction, canonically? | `src/normalization/` |
| Capability | What authority was this agent granted? | `src/storage/capability-store.ts` |
| Policy | Is the declared intent inside that authority? | `src/policy/` |
| Firewall | Do the transaction bytes match the declaration? | `src/firewall/` |
| Risk | What is unusual here, and why? | `src/risk/` |
| Approval | Bind the decision to these exact bytes | `src/approval/` |
| Signer | Obtain a signature from a boundary Arx does not control | `src/signer/`, `src/ledger/` |
| Audit | Record it so the decision can be re-derived | `src/storage/audit-store.ts` |

## Four outcomes

Arx uses Ledger's own vocabulary.

- **ALLOW** — within granted authority. Proceed autonomously.
- **DENY** — evaluated and refused. A final answer, not a retry hint.
- **ESCALATE** — within authority only if a person confirms at the device.
- **ABORT** — the premise could not be established: an oracle was unreachable, a
  name would not resolve, the device displayed something other than what was
  approved. Distinct from DENY because *not knowing is not permission*.

**Silence is never approval.**

## Design decisions, and why

### Deterministic transaction identity

A transaction's identity is `SHA-256` over its canonical form, never a random
UUID. The same logical request therefore always resolves to the same identity,
which is what lets an approval be bound to it and a retry be recognised.

### Canonical serialization, not `JSON.stringify`

Every hash flows through `src/crypto/canonical.ts` (RFC 8785 style: sorted keys,
normalised numbers, rejected non-representable values).

With plain `JSON.stringify`, a digest depends on key insertion order. Two
structurally identical transactions could hash differently — and worse, a
reordered or re-spelled payload could be shaped to match an approval bound to
different bytes. Integer strings are minimised (`"0100"` → `"100"`) and address
casing is normalised, so a value cannot pass a limit check under one spelling
and be bound under another.

### The agent's numbers are claims, not facts

An intent carries `amountUsd`, `action` and `inputToken`. All three are
assertions by a process that may be compromised. The transaction bytes are the
fact.

`src/firewall/checks/value-binding.ts` prices the actual value through an oracle
and compares it to the declaration. A claim of `$1` against a transfer of 1000
ETH is `VALUE_DECLARATION_MISMATCH`. The USD ceiling is enforced against the
oracle figure, never the claim.

### The recipient is often inside the calldata

An allowlisted token contract is not a safe transaction. In an ERC-20
`transfer`, the recipient is an argument, not the `to` field. A firewall that
only checks `to` leaves an allowlisted contract as an open payment channel, so
calldata is decoded and the embedded recipient checked against the same policy.
Multicall and batch wrappers are recursed into, so a wrapper cannot launder a
denied method.

### Replay: a floor and a counter, not one value

The original design used `capabilityId + agentId + nonce` as a single replay key
and rejected any nonce below the capability's. That made a reusable capability
single-use in practice: after one action every nonce was either already
processed or too low.

The two concerns are now separate:

- `capability.nonce` is a **floor** — the lowest nonce the grant will accept.
  Raising it retires every outstanding lower nonce at once.
- `intent.nonce` is a **per-action counter** — strictly above the highest already
  accepted, and never reusable.

Requiring strict increase, rather than merely "not seen before", means an intent
captured off the wire cannot be held and replayed once the counter has moved
past it. `intentId` is separate again, providing idempotency: the same id with
the same body replays the original decision; with a different body it is
`INTENT_ID_CONFLICT`.

### Claiming an approval is atomic

Signing transitions `APPROVED → SIGNING` through a compare-and-swap
(`UPDATE ... WHERE status = 'APPROVED'`) *before* any bytes reach the device. Of
two concurrent requests exactly one sees a row change; the other is refused.

A read-then-write would leave a window in which both callers believed they had
won, and both would obtain a signature. A failure moves the approval to the
terminal `SIGNING_FAILED`, so a rejected attempt is never retryable with the
same approval.

### Spend windows consume authority at approval, not at signing

An outstanding approval is a promise already made. Counting only signed
transactions would let an agent hold ten unspent approvals against a
one-transaction budget and redeem them all. Rows are `RESERVED` when an approval
is issued, `SETTLED` on signature, and `RELEASED` if it expires or signing fails
— so a device rejection does not silently burn the day's budget.

### Arx signs its own approvals

Without this, the only evidence an approval is genuine is a row in Arx's
database, and anyone who can write that database can mint authority. Arx holds
an Ed25519 key — not a blockchain key; it never holds one of those — and signs
each approval's binding fields. The signer verifies that signature before
touching the device, so database write access alone is not enough to obtain a
signature.

### Failure is never permission

Every external dependency returns `Availability<T>` (`src/core/seams.ts`), which
distinguishes *"checked, and here is the answer"* from *"could not check"*. An
adapter that returned "no risk found" when its data source was unreachable would
convert a dependency outage into a silent authorization bypass. Unknown resolves
to DENY or ABORT, never ALLOW.

### The audit log is evidence, not a convenience

Each entry commits to its predecessor's hash, so editing or deleting any
historical decision invalidates every hash after it. `GET /audit/verify`
recomputes the chain and names the first break. An operator can confirm that no
decision was altered after the fact without trusting the process that wrote it.

### The broker hands out capabilities, never the key

An agent holding an API credential holds it for as long as the credential lives,
inside a process that can be talked into disclosing it. `src/broker/` instead
seals the upstream secret with the Ledger Key Ring, issues the agent a
short-lived token bound to a hash of the policy in force, and unseals
just-in-time to perform an authorized action. The agent cannot leak what it
never holds, and tokens die when the policy is narrowed, so authority cannot
outlive its justification.

## Extension seams

Third-party integrations plug into narrow interfaces rather than reaching into
the pipeline (`src/core/seams.ts`).

| Seam | Interface | Provides |
|---|---|---|
| Price truth | `PriceOracle` | asset → USD, with a source and an age |
| Identity | `NameResolver` | name ⇄ address, and the resolver used |
| Reputation | `RiskSignalProvider` | explainable signals about an address |
| Signing | `SignerAdapter` | a signature from a boundary Arx does not control |
| Human factor | `HumanVerifier` | evidence a specific person approved |
| Execution | `ExecutionVenue` | a quote and calldata for an action |

## Trust assumptions

Stated plainly, because a security boundary is only as good as its honest
description.

1. **The agent process is untrusted.** It may be fully compromised. It holds no
   key and no credential.
2. **The Arx kernel is trusted** to evaluate correctly. It is deterministic and
   dependency-free on the decision path so that it can be audited and tested,
   not because correctness is assumed.
3. **The device is the signing boundary.** Software policy is bypassable if the
   signer is not protected; the Secure Element holds the key and the Trusted
   Display is the only display that cannot be rewritten by a compromised host.
4. **Speculos is an emulator, not a Secure Element.** It reproduces the app and
   the protocol faithfully. It does not reproduce hardware isolation, and a
   signature produced by it is not evidence of hardware-backed signing.
5. **A signature alone does not prove a human was present.** It proves the
   device signed. Device confirmation plus the Trusted Display readback is what
   supports the stronger claim.
