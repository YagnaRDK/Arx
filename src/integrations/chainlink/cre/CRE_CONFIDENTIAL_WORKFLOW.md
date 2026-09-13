# Arx × Chainlink CRE — Confidential Policy Evaluation

**Status: design sketch plus a runnable core. The CRE workflow has never been
executed, on CRE or in the CRE simulator.** The policy evaluation it would host
is real, deterministic code in this repository
(`src/integrations/chainlink/cre/confidential-policy.ts`) and is covered by its
own checks. The enclave that would run it is not wired up. Nothing in Arx's
request path depends on this, and `GET /integrations` reports it as
`DESIGN_SKETCH`.

## The problem

A capability's ceilings are themselves sensitive. Publishing

> this agent may move up to $50,000 per day, to these four addresses

tells an attacker exactly how much to try to take and exactly where it is
permitted to go. But the ceilings must be enforced somewhere, and if the only
place they are enforced is inside Arx, then Arx's operator is a single point of
trust for the whole authority model.

## What a Confidential Workflow changes

Chainlink CRE Confidential Workflows execute inside a TEE, and secrets are
requested and decrypted *inside the enclave at the moment the code needs them*
([docs](https://docs.chain.link/cre/concepts/confidential-workflows)). So:

| | Sees the secret policy | Sees the request | Sees the verdict |
|---|---|---|---|
| Arx operator | no (holds ciphertext) | yes | yes |
| CRE node operators | no | yes | yes |
| The enclave | yes, transiently | yes | yes |
| Policy owner | yes | yes | yes |

The enclave returns only `{ allowed, code, reason, policyCommitment,
requestCommitment, evaluatedAt, executionMode }`. The ceilings and the
allowlist never leave it.

## Two design choices that make it auditable

**A commitment, not the policy.** Every verdict carries `policyCommitment` —
the canonical SHA-256 of the secret policy document, via Arx's `hashCanonical`
rather than `JSON.stringify`, so key order cannot produce two commitments for
one policy. Anyone holding the policy can confirm the enclave used *that*
version; the commitment alone reveals nothing. `verifyVerdictBinding()`
performs that check.

**Time is an input.** `evaluatedAt` is passed into the evaluation, never read
from a clock inside it. The enclave's output is therefore reproducible: an
auditor with the policy, the request and the timestamp gets the same verdict
byte for byte.

## Sponsor-track mapping

| Requirement | How this meets it |
|---|---|
| CRE Confidential Workflow | `workflow.sketch.ts` — sketch, not running |
| A secret processed in a TEE | the capability's ceilings and allowlist, decrypted in-enclave |
| A real use for confidentiality | withholding limits from node operators *and* from Arx's own operator |

## What remains to be done

1. `bun add @chainlink/cre-sdk` (package name verified from the
   [project configuration reference](https://docs.chain.link/cre/reference/project-configuration-ts)),
   then confirm `bunx tsc --noEmit` stays clean.
2. Replace the pseudocode handler in `workflow.sketch.ts` with the real
   handler-registration and in-enclave secret fetch. The guide that carries
   those symbols renders its samples client-side and could not be read
   programmatically, so they were **not** guessed.
3. Declare `ARX_CONFIDENTIAL_POLICY` in `secrets.yaml`, put the value in
   `.env`, and run `cre workflow simulate`.
4. Only once a simulator run produces a verdict, change the registry entry from
   `DESIGN_SKETCH`. Not before.

## Sources

- https://docs.chain.link/cre/concepts/confidential-workflows
- https://docs.chain.link/cre/guides/workflow/using-confidential-workflows/making-workflow-confidential
- https://docs.chain.link/cre/guides/workflow/secrets/using-secrets-simulation-go
- https://docs.chain.link/cre/reference/cli/secrets
- https://docs.chain.link/cre/reference/project-configuration-ts
- https://docs.chain.link/cre/release-notes
