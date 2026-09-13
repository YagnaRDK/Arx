/**
 * DESIGN SKETCH — NOT A RUNNING WORKFLOW.
 *
 * This file is named `.sketch.ts` and exports nothing executable on purpose.
 * It shows how `evaluateConfidentialPolicy` would be hosted inside a Chainlink
 * CRE Confidential Workflow, and it has never been run on CRE, in the CRE
 * simulator, or anywhere else. Arx does not depend on it, the server does not
 * import it, and `IntegrationRegistry` reports the Chainlink CRE entry as a
 * design sketch rather than a live integration.
 *
 * Why it is a sketch and not an implementation:
 *
 *   - The CRE TypeScript SDK is published as `@chainlink/cre-sdk`
 *     (verified: https://docs.chain.link/cre/reference/project-configuration-ts).
 *     It is **not** installed in this repository, because adding an unexercised
 *     dependency to a security product's build for a sketch is a bad trade.
 *   - The exact SDK symbols for registering a TEE handler and fetching a secret
 *     inside the enclave could not be retrieved: the guide that carries them
 *     (https://docs.chain.link/cre/guides/workflow/using-confidential-workflows/making-workflow-confidential)
 *     renders its code samples client-side and returned only its table of
 *     contents. Rather than invent plausible-looking function names, the calls
 *     below are written as clearly-marked pseudocode.
 *
 * What *is* verified, and where from:
 *   - Confidential Workflows run sensitive logic inside a TEE, and secrets are
 *     "requested and decrypted inside the enclave at the moment your code needs
 *     them": https://docs.chain.link/cre/concepts/confidential-workflows
 *   - A local simulator exists, and it supports the Confidential HTTP
 *     capability with secret injection: `cre workflow simulate`, with secrets
 *     provided from a `.env` file or environment variables and declared in a
 *     `secrets.yaml`:
 *     https://docs.chain.link/cre/guides/workflow/secrets/using-secrets-simulation-go
 *     https://docs.chain.link/cre/release-notes
 *   - Deployed workflows read secrets from the Vault DON via
 *     `cre secrets create`: https://docs.chain.link/cre/reference/cli/secrets
 *
 * The configuration shape below is the documented one:
 *
 * ```yaml
 * # workflow.yaml
 * staging-settings:
 *   user-workflow:
 *     workflow-name: "arx-confidential-policy"
 *     deployment-registry: "private"
 *   workflow-artifacts:
 *     workflow-path: "./main.ts"
 *     config-path: "./config.staging.json"
 *     secrets-path: "./secrets.yaml"
 * ```
 *
 * ```yaml
 * # secrets.yaml — logical names only; values come from .env or the Vault DON
 * secretsNames:
 *   ARX_CONFIDENTIAL_POLICY: ["ARX_CONFIDENTIAL_POLICY"]
 * ```
 *
 * And the handler, in pseudocode:
 *
 * ```ts
 * // import { ... } from "@chainlink/cre-sdk";   // NOT installed here
 *
 * // PSEUDOCODE: exact SDK symbols unverified, see the note above.
 * export const arxConfidentialPolicyWorkflow = defineWorkflow((cre) => {
 *   cre.onConfidentialRequest(async (enclave, payload) => {
 *     // The secret is decrypted inside the TEE, at the moment it is needed.
 *     // Node operators running this workflow never observe it.
 *     const policy: ConfidentialPolicy = JSON.parse(
 *       await enclave.getSecret("ARX_CONFIDENTIAL_POLICY"),
 *     );
 *
 *     const request: ConfidentialRequest = parseRequest(payload);
 *
 *     // The one line that is real code in this repository. Deterministic, and
 *     // it takes `evaluatedAt` as an input so the enclave's output is
 *     // reproducible by an auditor holding the same policy.
 *     return evaluateConfidentialPolicy(
 *       policy,
 *       request,
 *       "CRE_CONFIDENTIAL_TEE",
 *     );
 *   });
 * });
 * ```
 *
 * Only the verdict leaves the enclave: `allowed`, a `DecisionCode`, a reason,
 * and the two commitment hashes. The ceilings and the allowlist do not. Arx
 * stores the verdict in the audit chain, and `verifyVerdictBinding` lets
 * whoever holds the policy confirm which version produced it.
 *
 * To make this real, in order:
 *   1. `bun add @chainlink/cre-sdk` and confirm `bunx tsc --noEmit` stays clean.
 *   2. Read the making-a-workflow-confidential guide in a browser and replace
 *      the pseudocode above with the actual handler-registration and
 *      secret-fetch calls.
 *   3. `cre workflow simulate` with `ARX_CONFIDENTIAL_POLICY` in `.env`.
 *   4. Only after a simulator run produces a verdict, change the registry entry
 *      from `DESIGN_SKETCH` to something stronger — and never before.
 */

export {};
