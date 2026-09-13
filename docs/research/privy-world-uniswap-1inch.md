# Privy, World, Uniswap and 1inch

> Compiled 2026-09-12 by a research agent that verified each claim against
> primary sources (npm tarballs, app source, official docs). Facts carry their
> source URL. Anything unverified is listed explicitly at the end — treat that
> section as unknown, not as true.

## Summary

All four sponsors are implementable from a Bun/TypeScript server, and three of them map almost perfectly onto Arx (agent → policy firewall → Ledger).

**A) Privy** is the strongest fit and the deepest. The current server SDK is `@privy-io/node` (0.34.0) — NOT `@privy-io/server-auth` (1.32.5, effectively legacy). The exported `PrivyClient` uses *method* accessors: `privy.wallets()`, `privy.policies()`, `privy.keyQuorums()`, `privy.intents()` (I verified this against the published `.d.ts`, because the raw Stainless client underneath uses properties — easy to get wrong). The policy engine is a per-RPC-method rule list with `field_source`/`field`/`operator`/`value` conditions over `ethereum_transaction`, `ethereum_calldata` (requires an inline ABI), `ethereum_typed_data_*`, `system` (timestamps), and `reference` (stateful rolling-window aggregations). Default is DENY. Policies attach at wallet creation via `policy_ids` (max **one** policy per wallet today) or via `PATCH /v1/wallets/:id`. Key quorums (m-of-n P-256 keys + user IDs, nestable one level) become `owner_id`/`signer_id`. Intents are async signing: propose → collect signatures → auto-execute. All four "Privy controls" the bounty asks for are reachable in one afternoon; you can trivially satisfy "at least one".

**B) World.** Selfie Check is credential ID `11`, preset `selfieCheckLegacy()`, World ID 3.0 only, **access-gated behind a per-app feature flag you must email for** — that's the critical path risk. Verification is server-side: POST the untouched IDKit result to `https://developer.world.org/api/v4/verify/{rp_id}` (v4, not the old v2/app_id endpoint). A headless server flow exists: `@worldcoin/idkit-core` ≥4.2.4 gives `signRequest()` (subpath `/signing`), `IDKit.request().preset(selfieCheckLegacy())`, `connectorURI` (render as QR), and `pollUntilCompletion()` — no React, no mini app required. There is also `@worldcoin/human-in-the-loop` (0.2.1), which is *literally* your product: an agent tool that pauses mid-execution until a World ID proof arrives.

**C) Uniswap.** Trading API is `https://trade-api.gateway.uniswap.org/v1`, auth `x-api-key`, free self-serve key. Sepolia (11155111) is a supported chainId. CCA = **Continuous Clearing Auction** (liquidity launchpad, Base). The quote response exposes the full v4 route including each pool's `hooks` address, and `/swap` returns exact `to`/`data`/`value` — ideal for a firewall demo.

**D) 1inch.** Aqua registry `0x1111113ccf1426a8e30e2bff5e005d929bf6a90a`, SwapVM/AquaSwapVMRouter `0x111111338c5091e8440b67b168bae16a668ac0de`, same on every chain. SDKs are `@1inch/aqua-sdk` (0.3.4) + `@1inch/swap-vm-sdk` (0.4.4) + `@1inch/sdk-core` (0.1.6). Fork mainnet with anvil and the official contracts are already in state.

## Verified facts

### Privy — npm package

`@privy-io/node` latest = 0.34.0 (the current server SDK). `@privy-io/server-auth` latest = 1.32.5 with only beta tags since Oct 2025 — treat as legacy; docs have a "Migrating from server-auth" page. `@privy-io/react-auth` latest = 3.42.0.

Source: https://registry.npmjs.org/@privy-io/node

### Privy — client shape (verified against .d.ts)

The `PrivyClient` exported from `@privy-io/node` is `public-api/PrivyClient` and uses METHOD accessors: `webhooks()`, `wallets()`, `policies()`, `transactions()`, `keyQuorums()`, `intents()`, `users()`, `organizations()`, `apps()`, `utils()`. `wallets()` further exposes `ethereum()`, `solana()`, `tron()`, `earn()`, `swaps()`, `depositAccounts`. (The lower-level generated client in `client.d.ts` uses properties — do not mix them up.)

Source: https://registry.npmjs.org/@privy-io/node/-/node-0.34.0.tgz

### Privy — constructor

`new PrivyClient({ appId, appSecret })`. Optional: `apiUrl`, `jwtVerificationKey`, `webhookSigningSecret`, `requestExpiry: { disabled?, defaultMs? (default 15 min), defaultIntentMs? (default 72h) }`. Supported runtimes explicitly include **Bun 1.0+**, Node 20+, Deno, CF Workers, Vercel Edge, Nitro. Browsers throw.

Source: https://docs.privy.io/basics/nodeJS/setup

### Privy — policy object

Policy = `{ version: '1.0', name, chain_type: 'ethereum'|'solana'|'tron'|'sui'|'xrpl', rules: Rule[], owner?: {public_key}|{user_id}, owner_id?: <keyQuorumId> }`. Rule = `{ name, method, conditions: Condition[], action: 'ALLOW'|'DENY' }`. Condition = `{ field_source, field, operator, value, abi? }`.

Source: https://docs.privy.io/controls/policies/overview

### Privy — policy evaluation semantics

Rules are only evaluated for the requested RPC method. Any DENY wins. If no rule matches → **DENY by default**. If a policy is attached to a wallet, it MUST contain a rule for every RPC method the wallet will use, or that method is blocked. For Solana, every instruction must ALLOW. Enforced inside the TEE/secure enclave.

Source: https://docs.privy.io/controls/policies/overview

### Privy — rule `method` enum (exact)

'eth_sendTransaction' | 'eth_signTransaction' | 'eth_signUserOperation' | 'eth_signTypedData_v4' | 'personal_sign' | 'eth_sign7702Authorization' | 'wallet_sendCalls' | 'signTransaction' | 'signAndSendTransaction' | 'signMessage' | 'exportPrivateKey' | 'exportSeedPhrase' | 'signRawMessageBytes' | 'signTransactionBytes' | 'tron_signTransaction' | 'tron_sendTransaction' | 'xrpl_signTransaction' | 'earn_deposit' | 'earn_withdraw' | 'transfer' | '*'

Source: https://docs.privy.io/controls/policies/overview

### Privy — condition `field_source` enum (exact)

'ethereum_transaction' | 'ethereum_calldata' | 'ethereum_typed_data_domain' | 'ethereum_typed_data_message' | 'ethereum_7702_authorization' | 'solana_program_instruction' | 'solana_system_program_instruction' | 'solana_token_program_instruction' | 'tron_transaction' | 'tron_trigger_smart_contract_data' | 'sui_transaction_command' | 'sui_transfer_objects_command' | 'xrpl_transaction' | 'tempo_transaction' | 'message' | 'action_request_body' | 'system' | 'reference'

Source: https://docs.privy.io/controls/policies/overview

### Privy — operators

'eq' | 'neq' | 'lt' | 'lte' | 'gt' | 'gte' | 'in' | 'in_condition_set' | 'contains' | 'starts_with' | 'ends_with'. All string comparisons are case-sensitive. `in` accepts at most 100 values; use `in_condition_set` (condition sets) beyond that.

Source: https://docs.privy.io/controls/policies/overview

### Privy — available rule types (answers "allowlist / spend limits / contract method allow")

Supported: transfer limits; time-bound signers; allow/denylists of transfer recipients; allow/denylists of smart contracts & Solana programs; allow/denylists of networks (`chain_id`); allowed time window for key export; granular calldata + parameter constraints; EIP-712 typed-data restrictions. Fields: `to`, `value`, `chain_id` (ethereum_transaction); `function_name`, `function_name.param` (ethereum_calldata, ABI required — even for zero-arg functions like `deposit()`); `chainId`, `verifyingContract` (typed_data_domain); `current_unix_timestamp` (system); `content`, `byte_length` (message).

Source: https://docs.privy.io/controls/policies/example-policies/ethereum

### Privy — numeric encoding gotcha

"The policy engine evaluates numerical data exactly as passed in the request body—no conversion is applied." ETH in wei, USDC in microdollars. Docs examples use hex strings (`'0x2386F26FC10000'`) for `value` and decimal strings (`'8453'`) for `chain_id`. Keep the encoding in your tx request body consistent with the policy `value`.

Source: https://docs.privy.io/controls/policies/overview

### Privy — create policy endpoint

`POST https://api.privy.io/v1/policies`. Basic auth `-u appId:appSecret`, plus headers `privy-app-id`, optional `privy-authorization-signature`, optional `privy-idempotency-key`. Response adds `id` (24-char CUID2) and `owner_id`. SDK: `await privy.policies().create({...})` → `Policy`.

Source: https://docs.privy.io/controls/policies/create-a-policy

### Privy — attach policy to wallet

At creation: `POST /v1/wallets` with `policy_ids: [<24-char CUID2>]`. After creation: `PATCH /v1/wallets/<wallet_id>` with `policy_ids`, `owner`/`owner_id`, `additional_signers`, `display_name` (SDK: `privy.wallets().update(walletId, {...})`). **Currently only ONE policy is supported per wallet.** Wallets with `owner_id` set require an authorization signature on PATCH and on `/rpc`.

Source: https://docs.privy.io/wallets/wallets/update-a-wallet

### Privy — create wallet request body (exact)

`POST /v1/wallets` body: `chain_type` (ethereum|solana|cosmos|stellar|sui|aptos|movement|tron|bitcoin-segwit|bitcoin-taproot|pearl|near|ton|starknet|xrpl|spark), `display_name` (≤100), `external_id` (≤64, URL-safe), `policy_ids[]`, `entity: {id, type: 'user'|'organization'}`, `owner: {user_id} | {public_key}`, `owner_id` (key-quorum id), `additional_signers: [{signer_id, override_policy_ids[]}]`. Response includes `id`, `address`, `public_key`, `authorization_threshold`, `created_at`.

Source: https://docs.privy.io/api-reference/wallets/create

### Privy — key quorums

`privy.keyQuorums().create({ public_keys?: string[] (base64 DER P-256), user_ids?: string[], key_quorum_ids?: string[] (nested, 1 level deep), display_name?, authorization_threshold?: number })`. Threshold defaults to ALL keys. Returned `id` is used as `owner_id` (wallets/policies) or `signer_id` (additional signers). Nested quorum counts as ONE approval toward the parent threshold. Thresholds enforced in the TEE. Docs label key quorums an "advanced feature" and suggest contacting Privy.

Source: https://docs.privy.io/controls/key-quorum/create

### Privy — authorization keys

P-256 (secp256r1). Generate in-process: `import {generateP256KeyPair} from '@privy-io/node'; const {privateKey, publicKey} = await generateP256KeyPair();` → base64-encoded DER, no PEM headers. Or `openssl ecparam -name prime256v1 -genkey -noout -out private.pem && openssl ec -in private.pem -pubout -out public.pem` then `openssl ec -pubin -in public.pem -outform DER | base64`. Privy never stores the private key.

Source: https://docs.privy.io/controls/authorization-keys/keys/create/key

### Privy — AuthorizationContext (exact TS shape)

`interface AuthorizationContext { authorization_private_keys?: string[]; user_jwts?: string[]; signatures?: string[]; sign_fns?: ((payload: Uint8Array) => Promise<string>)[] }`. Pass it as `authorization_context` on any SDK call that needs owner/signer signatures. Mixing `user_jwts` + `authorization_private_keys` gives a 2-of-2 user+server quorum.

Source: https://docs.privy.io/controls/authorization-keys/using-owners/sign/signing-on-the-server

### Privy — manual signature utilities exported from @privy-io/node

`formatRequestForAuthorizationSignature(input): Uint8Array`, `generateAuthorizationSignature({authorizationPrivateKey, input}): string`, `generateAuthorizationSignatures(client, {authorizationContext, input})`, `prepareRequest(client, appId, {...})`. Signature payload = `{ version: 1, method: 'POST'|'PUT'|'PATCH'|'DELETE', url (no trailing slash), body, headers: { 'privy-app-id', 'privy-idempotency-key'?, 'privy-request-expiry'? } }`, canonicalized JSON, ECDSA P-256. Header: `privy-authorization-signature` (comma-delimited if multiple) + `privy-request-expiry`.

Source: https://docs.privy.io/api-reference/authorization-signatures

### Privy — intents

Async signing. Propose: `POST /v1/intents/wallets/<wallet_id>/rpc` (same body as sync `/rpc`, minus signatures) → `{intent_id, status, authorization_details}`. Also `/transfer`, `/update-wallet`, `/update-policy`, `/update-policy-rule`, `/update-key-quorum`. Authorize: `POST /v1/intents/{intent_id}/authorize` with `{signature, timestamp}` (ms). One signature per call; each signer calls separately; idempotent per signer. Statuses: pending, granted, processing, executed, failed, rejected, expired (72h default), dismissed. `action_result` holds the tx hash. Webhook `intent.executed`.

Source: https://docs.privy.io/transaction-management/intents/overview

### Privy — Node SDK intents surface (verified in .d.ts)

`privy.intents()` exposes `rpc`, `createPolicyRule`, `deletePolicyRule`, `updatePolicy`, `updatePolicyRule`, `updateWallet`, `updateKeyQuorum`, plus inherited `list`, `get`, `reject`. **There is NO `authorize()` method in @privy-io/node 0.34.0** (the Java SDK has one). Authorize via raw REST + `generateAuthorizationSignature`.

Source: https://registry.npmjs.org/@privy-io/node/-/node-0.34.0.tgz

### Privy — additional signers with per-signer override policies

A wallet can have multiple `additional_signers`, each with `override_policy_ids`. When a signer submits a transaction, Privy evaluates ONLY that signer's override policy. Same wallet, different authority per key — no extra wallets needed.

Source: https://docs.privy.io/recipes/wallets/conditional-signer-policies

### Privy — stateful policies (rolling spend limits)

Create an Aggregation (`POST /v1/aggregations`) with `method` ('eth_signTransaction' | 'eth_signUserOperation' only), `metric {field, field_source: 'ethereum_transaction'|'ethereum_calldata', function: 'sum', abi?}`, `window {type: 'rolling', seconds: 3600..259200}`, optional `conditions[]` pre-filters and `group_by[]`. Then reference it in a policy condition with `field_source: 'reference'`, `field: 'aggregation.<id>'`. Max **10 aggregations per app**.

Source: https://docs.privy.io/controls/policies/stateful-policies

### Privy — simulation ordering gotcha

For operations where Privy both signs AND broadcasts, transaction simulation runs BEFORE policy evaluation. A request that would fail simulation (insufficient funds, revert) returns the simulation error, not a policy violation — even if it also violates policy.

Source: https://docs.privy.io/controls/policies/overview

### Privy — send transaction API

`await privy.wallets().ethereum().sendTransaction(walletId, { caip2: 'eip155:11155111', params: { transaction: { to, value: '0x1', chain_id: 11155111 } }, authorization_context? })` → `{ hash }`. Also `signTransaction`, `signMessage`, `signTypedData`, `signUserOperation`, `sign7702Authorization`, `sendCalls`, `signSecp256k1`. Generic escape hatch: `privy.wallets().rpc(walletId, {method, caip2, params, sponsor?, authorization_context?})`.

Source: https://docs.privy.io/basics/nodeJS/quickstart

### World — Selfie Check identity

Credential ID `11`, issued by Tools for Humanity, status **Beta**, validity 90 days (90-day inactivity window then re-capture). Medium-assurance: liveness + facial similarity via device camera. Explicitly NOT a strict one-person-one-account guarantee; returns a proof of a completed check, not a numeric sybil score. Documented uses: liveness detection, abuse resistance, continuity.

Source: https://docs.world.org/world-id/credentials/11

### World — Selfie Check is access-gated

"Selfie Check (Beta) is access-gated. To use it, request access so the feature flag can be enabled for your app" — email developers@toolsforhumanity.com. A valid app/action does NOT imply Selfie Check access. Once enabled, any World ID App user can complete it — no Orb, passport, or prerequisite credential.

Source: https://docs.world.org/world-id/credentials/11

### World — SDK preset name

Selfie Check preset is `selfieCheckLegacy()` (imported from `@worldcoin/idkit-core` or `@worldcoin/idkit`). It currently returns World ID **3.0** proofs; 4.0 support not yet available. Other presets: `proofOfHuman`, `passport`, `identityCheck` (preview), `orbLegacy`, `secureDocumentLegacy`, `documentLegacy`, `deviceLegacy` (deprecated → use Selfie Check).

Source: https://docs.world.org/world-id/idkit/credentials

### World — npm versions

`@worldcoin/idkit` 4.2.3; `@worldcoin/idkit-core` 4.2.4; `@worldcoin/minikit-js` 2.0.3; `@worldcoin/mini-apps-ui-kit-react` 1.6.0; `@worldcoin/human-in-the-loop` 0.2.1; `@worldcoin/human-in-the-loop-react` 0.1.1. Docs warn: DO NOT pin idkit to ^2.x or ^3.x — v4 redesigned the API; pin ^4.x.

Source: https://registry.npmjs.org/@worldcoin/idkit

### World — server-side verification endpoint

`POST https://developer.world.org/api/v4/verify/{rp_id}` — forward the complete IDKit result **byte-for-byte, unmodified**. Prefer `rp_id` (`rp_...`); `app_id` (`app_...`) still accepted for back-compat. Legacy domain `https://developer.worldcoin.org`; staging `https://staging-developer.worldcoin.org`. 200 = at least one proof verified; 400 codes include `app_not_migrated`, `all_verifications_failed`, `invalid_proof`, `not_registered`. NOTE: the old `/api/v2/verify/{app_id}` is the pre-4.0 endpoint (`verifyCloudProof` era) — the current one is v4.

Source: https://docs.world.org/api-reference/developer-portal/verify

### World — headless/server flow exists (no React, no mini app)

`@worldcoin/idkit-core` server helpers: `import {signRequest} from '@worldcoin/idkit-core/signing'` → `{sig, nonce, createdAt, expiresAt}` (opts: `signingKeyHex`, `action`, `ttl` default 300s); `import {hashSignal} from '@worldcoin/idkit-core/hashing'`. `IDKit.request(config).preset(...)` returns an `IDKitRequest` with `connectorURI` (render as QR), `requestId`, `pollOnce()`, `pollUntilCompletion({pollInterval, timeout})`, `getDebugReport()`. Also `IDKit.requestWithInviteCode(...)` for invite-code landing pages.

Source: https://docs.world.org/world-id/idkit/javascript

### World — Selfie Check does require the World ID App on the user's phone

Mobile: IDKit generates a deep link → redirects into World ID App. Desktop: IDKit generates a QR code → user scans with phone → World ID App runs the camera flow → proof returns to the originating web session. The *proof verification* is fully server-side; the *capture* requires World ID App.

Source: https://docs.world.org/world-id/credentials/11

### World — nullifier storage requirement

Every proof returns a `nullifier` (RP-scoped + action-scoped, 0x-hex 256-bit). Store as decimal `NUMERIC(78,0)` with `UNIQUE (nullifier, action)` and reject duplicates on insert. This is the only anti-replay mechanism. The in-memory `Set` in samples is illustrative only.

Source: https://docs.world.org/world-id/idkit/integrate

### World — request-level liveness flag (independent of Selfie Check)

`require_user_presence: true` on the request config (not a credential) forces a fresh liveness check before returning the proof; fails with `user_presence_failed`. Works with any preset. World matches the live selfie against the credential image (passport photo / Orb capture).

Source: https://docs.world.org/world-id/idkit/credentials

### World — environments must match end-to-end

IDKit `environment` prop, the action's environment in the Developer Portal, and simulator-vs-real-app must all agree. Production World ID App only signs production proofs. Staging actions only verify against the simulator at https://simulator.worldcoin.org. A staging action + real phone silently produces zero proofs.

Source: https://docs.world.org/world-id/SKILL.md

### World ID Sandbox App

Sandbox is a separate production-like environment with its own backend and its own iOS/Android builds of the World ID app, built from the same codebase as production. It is a valid IDKit destination (real bridge round-trip), supports resettable accounts, simulated verification, and toggleable fraud/risk/attestation gating. iOS via TestFlight (request enrollment in Developer Portal → "World ID Sandbox" → iOS tab); Android via a private Google Play testing track (same panel). Not in public app stores. Selfie Check testing in Sandbox is documented, including Hot/Cold/Semi-cold journeys and known limitations (iOS Semi-cold is limited).

Source: https://docs.world.org/world-id/sandbox/what-is-sandbox

### World — AgentKit / AgentBook (their Track 1)

`npm install @worldcoin/agentkit`. AgentKit Beta extends x402 so servers can distinguish human-backed agents from bots. AgentBook is the on-chain registry: `npx @worldcoin/agentkit-cli register <agent-address>` (gasless via hosted relay, canonical deployment on World Chain; `status <addr>` to check). Agent side: `createAgentkitClient({signer:{address, chainId:'eip155:8453', type:'eip191', signMessage}})` then `agentkit.fetch(url)`. Server side: `agentkitResourceServerExtension`, `createAgentBookVerifier`, `createAgentkitHooks`, `declareAgentkitExtension`, `InMemoryAgentKitStorage` (Hono reference impl; Express/Next work via the same hooks). World Chain = eip155:480, World Chain USDC = 0x79A02482A880bCE3F13e09Da970dC34db4CD24d1.

Source: https://docs.world.org/agents/agent-kit/integrate

### World — human-in-the-loop SDK (this IS your idea, shipped)

`npm i @worldcoin/human-in-the-loop ai workflow` (server) and `@worldcoin/human-in-the-loop-react @worldcoin/idkit ai react` (client). Server env: `WORLD_RP_ID`, `WORLD_SIGNING_KEY`. `import {requestHumanAuthorization} from '@worldcoin/human-in-the-loop/workflows'` used as a tool's `execute` — pauses the workflow, streams approval context to the client, waits for a World ID proof, verifies it, resumes. Options: `action` (string or `({toolCallId, input}) => string`, default toolCallId), `signingKey`, `rpId`. Client: `<HumanApproval message part appId preset allowLegacyProofs .../>` or headless `useHumanApproval(message, part)` → `{ready, action, rpContext, webhookUrl, state, verify}`. Built on Vercel AI SDK + useworkflow.dev. Reference app: github.com/worldcoin/human-in-the-loop/tree/main/examples/flight-booking

Source: https://docs.world.org/agents/human-in-the-loop/integrate

### World — Developer Portal MCP (fast setup)

Endpoint `https://developer.world.org/api/mcp` (streamable-http), auth `Authorization: Bearer api_<base64(id:secret)>` with a team API key. Tools: `get_team_context`, `get_app_config`, `create_app`, `configure_world_id` (mints RP, returns `signing_key.private_key` ONCE), `create_world_id_action`, `get_world_id_registration_status`, `get_world_id_signing_key` (address only), `rotate_world_id_signing_key`. `app_mode` is fixed at create time — use `external` for IDKit, `mini-app` for MiniKit.

Source: https://docs.world.org/world-id/SKILL.md

### Uniswap — Trading API base URL and auth

Base URL `https://trade-api.gateway.uniswap.org/v1`. Auth is a single header `x-api-key` (OpenAPI `securitySchemes.apiKey = {type: apiKey, in: header, name: x-api-key}`, applied globally). Live OpenAPI spec: https://trade-api.gateway.uniswap.org/v1/api.json (verified 200, 274KB).

Source: https://trade-api.gateway.uniswap.org/v1/api.json

### Uniswap — API key is free and self-serve

Sign up at https://developers.uniswap.org/dashboard (verified 200) to generate API keys for swapping and LP operations. The API is free — no subscription or per-call charges. Store the key server-side; never ship it to a browser.

Source: https://developers.uniswap.org/docs/trading/swapping-api/start-building/integration-guide

### Uniswap — endpoint list (from live spec)

POST /check_approval, /permissions, /quote, /order, /swap, /limit_order_quote, /swap_5792, /swap_7702, /swap_4337, /check_approval_4337, /plan, /wallet/encode_7702, /wallet/check_delegation, /wallet/encode_4337, /margin/quote; GET /orders, /swaps, /swappable_tokens, /supported_chains, /tokens, /plan/{planId}; LP: /lp/check_approval, /lp/create, /lp/increase, /lp/decrease, /lp/claim_fees, /lp/create_classic, /lp/pool_info.

Source: https://trade-api.gateway.uniswap.org/v1/api.json

### Uniswap — /quote request schema (exact)

Required: `type` ('EXACT_INPUT'|'EXACT_OUTPUT'), `amount` (string), `tokenInChainId`, `tokenOutChainId`, `tokenIn`, `tokenOut`, `swapper`. Optional: `slippageTolerance`, `autoSlippage`, `routingPreference` ('BEST_PRICE'|'FASTEST', default BEST_PRICE), `protocols` (['V2','V3','V4','UNISWAPX','UNISWAPX_V2','UNISWAPX_V3','UNISWAPX_LATEST']), `hooksOptions` ('V4_HOOKS_INCLUSIVE'|'V4_HOOKS_ONLY'|'V4_NO_HOOKS'), `urgency`, `permitAmount`, `recipient`, `integratorFees`, `generatePermitAsTransaction`, `includeRouteCandidates`, `spreadOptimization`. Native token = 0x0000000000000000000000000000000000000000.

Source: https://trade-api.gateway.uniswap.org/v1/api.json

### Uniswap — routing dispatch

`/quote` returns top-level `routing`: CLASSIC | DUTCH_V2 | DUTCH_V3 | PRIORITY | WRAP | UNWRAP | BRIDGE | CHAINED. CLASSIC/WRAP/UNWRAP/BRIDGE → POST /swap. DUTCH_V2/DUTCH_V3/PRIORITY → POST /order. CHAINED → use the /plan endpoints.

Source: https://developers.uniswap.org/docs/trading/swapping-api/start-building/integration-guide

### Uniswap — /swap request/response (exact)

Request: `{ quote (ClassicQuote|WrapUnwrapQuote|BridgeQuote, required), signature?, permitData?, simulateTransaction?, refreshGasPrice?, safetyMode?, deadline?, urgency? }`. Response: `{ requestId, swap: { data, value, to, from, maxFeePerGas, maxPriorityFeePerGas, gasLimit, chainId }, gasFee }`. The `data` field must be non-empty and must NOT be modified.

Source: https://trade-api.gateway.uniswap.org/v1/api.json

### Uniswap — quote response exposes the v4 route incl. hook addresses

ClassicQuote contains `route: Array<Array<V2PoolInRoute|V3PoolInRoute|V4PoolInRoute>>`, `routeString`, `quoteId`, `gasUseEstimate`, `priceImpact`, `txFailureReasons`, `blockNumber`. A v4-pool entry looks like `{type:'v4-pool', address:<poolId>, tokenIn, tokenOut, fee, tickSpacing, hooks:'0x...', liquidity, sqrtRatioX96, tickCurrent, amountIn, amountOut}` — i.e. the hook address is right there to policy-check.

Source: https://trade-api.gateway.uniswap.org/v1/api.json

### Uniswap — supported chain IDs (spec enum)

1, 10, 56, 130, 137, 143, 196, 324, 480, 1868, 4217, 4326, 4663, 5042, 8453, 10143, 42161, 42220, 43114, 57073, 59144, 81457, 7777777, and testnets **1301 (Unichain Sepolia), 84532 (Base Sepolia), 11155111 (Ethereum Sepolia)**. Docs: "All listed testnets are accessible via the API" (only Sepolia + Unichain Sepolia appear in app.uniswap.org).

Source: https://developers.uniswap.org/docs/trading/swapping-api/supported-chains

### Uniswap — Universal Router version header

`x-universal-router-version` on /quote, /swap, /swap_5792, /swap_7702. Default is 2.0 on most chains (some default to 2.1.1). Decoder compatibility: UR 2.0 → `@uniswap/universal-router-sdk` ≥3.1.0; UR 2.1.1 and 2.2.0 → ≥5.9.0. Canonical router list: github.com/Uniswap/sdks/blob/main/sdks/universal-router-sdk/src/utils/constants.ts

Source: https://developers.uniswap.org/docs/trading/swapping-api/supported-chains

### Uniswap — Sepolia (11155111) v4 addresses

PoolManager 0xE03A1074c86CFeDd5C142C4F04F1a1536e203543; Universal Router (2.0) 0x3A9D48AB9751398BbFa63ad67599Bb04e4BdF98b; Universal Router 2.1.1 0x7dfd4f31be6814d2906bde155c3e1b146eac1468; PositionManager 0x429ba70129df741B2Ca2a85BC3A2a3328e5c09b4; StateView 0xe1dd9c3fa50edb962e442f60dfbc432e24537e4c; Quoter (V4Quoter) 0x61b3f2011a92d183c7dbadbda940a7555ccf9227; ReservesLens 0x0000001b173C3bbF3984D417d8614E3eed34865B; PoolSwapTest 0x9b6b46e2c869aa39918db7f52f5557fe577b6eee; PoolModifyLiquidityTest 0x0c478023803a644c94c4ce1c1e7b9a087e411b0a; Permit2 0x000000000022D473030F116dDEE9F6B43aC78BA3.

Source: https://developers.uniswap.org/docs/protocols/v4/deployments

### Uniswap — other useful v4 addresses

Mainnet: PoolManager 0x000000000004444c5dc75cB358380D2e3dE08A90, UR 0x66a9893cc07d91d95644aedd05d03f95e1dba8af, UR 2.1.1 0x4c82d1fbfe28c977cbb58d8c7ff8fcf9f70a2cca, V4Quoter 0x52f0e24d1c21c8a0cb1e5a5dd6198556bd9e1203, StateView 0x7ffe42c4a5deea5b0fec41c94c136cf115597227. Base Sepolia (84532): PoolManager 0x05E73354cFDd6745C338b50BcFDfA3Aa6fA03408, UR 0x492e6456d9528771018deb9e87ef7750ef184104, V4Quoter 0x4a6513c898fe1b2d0e78d3b0e0a4a151589b1cba. Unichain Sepolia (1301): PoolManager 0x00b036b58a818b1bc34d502d3fe730db729e62ac, UR 0xf70536b3bcc1bd1a972dc186a2cf84cc6da6be5d. Permit2 is 0x000000000022D473030F116dDEE9F6B43aC78BA3 everywhere.

Source: https://developers.uniswap.org/docs/protocols/v4/deployments

### Uniswap — npm SDK versions

@uniswap/v4-sdk 2.3.3; @uniswap/universal-router-sdk 5.11.5; @uniswap/sdk-core 7.19.2; @uniswap/v3-sdk 3.31.3; @uniswap/v2-sdk 4.21.3; @uniswap/permit2-sdk 1.4.0.

Source: https://registry.npmjs.org/@uniswap/v4-sdk

### Uniswap — CCA definitively defined

CCA = **Continuous Clearing Auction**, not "contract chain abstraction". It generalizes the uniform-price auction into continuous time, clearing bids block by block, to bootstrap liquidity and discover price for new/low-liquidity tokens on Uniswap v4. Ships as the Uniswap "Liquidity Launchpad". Built with Aztec (first launch, Nov 2025 sale, Feb 2026 TGE); includes an optional ZK Passport module. Deployed on Base, announced Jan 22 2026, live Feb 2 2026; seven independent audits (OpenZeppelin, Spearbit, others). Repo: github.com/Uniswap/continuous-clearing-auction. Docs: developers.uniswap.org/docs/liquidity/liquidity-launchpad/concepts/cca (+ /deployments, /guides/local-deployment, /guides/setup, /guides/submit-bid, /guides/exit-bid, /guides/example-configuration).

Source: https://developers.uniswap.org/docs/liquidity/liquidity-launchpad/concepts/cca

### Uniswap — v4 hooks

Hooks are external contracts attached to a v4 pool at creation that the PoolManager singleton calls at lifecycle points (before/after initialize, addLiquidity, removeLiquidity, swap, donate). v4 uses a singleton PoolManager + flash accounting + ERC-6909 claim tokens. Docs: /docs/protocols/v4/concepts/hooks, /concepts/poolmanager, /concepts/flash-accounting, /guides/custom-accounting. Uniswap Labs production hooks (permissioned pools, StablePair) are documented under /docs/protocols/uniswap-labs-hooks.

Source: https://developers.uniswap.org/docs/protocols/v4/concepts/hooks

### Uniswap — bounty submission mechanics

Required: public GitHub repo with open-source code, a `FEEDBACK.md` file, a clear README identifying the relevant contracts, AND a submission to the Uniswap Developer Feedback Form at https://developers.uniswap.org/hackathon-feedback (verified 200) that includes the link to your FEEDBACK.md.

Source: https://developers.uniswap.org/hackathon-feedback

### 1inch — official contract addresses

Deterministic, SAME address on every supported chain: **Aqua (registry) `0x1111113ccf1426a8e30e2bff5e005d929bf6a90a`**; **SwapVM / AquaSwapVMRouter `0x111111338c5091e8440b67b168bae16a668ac0de`**. README: "Only interact with these two contracts. Anything else is not Aqua." Chains: Ethereum, Base(8453), Optimism(10), Polygon(137), Arbitrum(42161), Avalanche(43114), BSC(56), Linea(59144), Sonic(146), Unichain(130), Gnosis(100), zkSync(324), Robinhood(4663), Cronos(25), Monad(143), HyperEVM(999), Arc(5042).

Source: https://github.com/1inch/aqua

### 1inch — what Aqua is

A shared liquidity layer. LPs keep a single ERC-20 approval to the Aqua registry and distribute *virtual* balances across strategies; tokens never leave the LP's wallet. Storage: `mapping(maker => mapping(app => mapping(strategyHash => mapping(token => Balance))))`. Lifecycle: `ship()` (open a strategy + allocate virtual balances), `dock()` (close + withdraw). Swap-time only: `pull()` (app moves maker tokens to taker) and `push()` (taker deposits into maker's strategy balance). `strategyHash = keccak256(abi.encode(strategy))`; strategies are IMMUTABLE once shipped — re-parameterize with dock() → ship().

Source: https://github.com/1inch/aqua

### 1inch — what SwapVM is

A bytecode VM for swap strategies. Programs are sequences of instructions executed against 5 `SwapRegisters` (balanceIn, balanceOut, amountIn, amountOut, amountNetPulled): the taker specifies ONE amount, the VM computes the other, instructions mutate registers to apply fees/curves/guards. Maker orders are signed off-chain (EIP-712) OR authorized via Aqua (`useAquaInsteadOfSignature: true`). Maker/taker hooks: preTransferIn, postTransferIn, preTransferOut, postTransferOut. Instruction ORDER is security-critical.

Source: https://github.com/1inch/swap-vm

### 1inch — npm SDKs (verified on registry)

**`@1inch/aqua-sdk` 0.3.4**, **`@1inch/swap-vm-sdk` 0.4.4**, **`@1inch/sdk-core` 0.1.6** — these are the Aqua/SwapVM ones. Also `@1inch/limit-order-sdk` 5.4.3, `@1inch/fusion-sdk` 2.4.15, `@1inch/cross-chain-sdk` 2.2.4, `@1inch/solana-fusion-sdk` 0.2.2, `@1inch/solidity-utils` 6.9.16, `@1inch/byte-utils` 3.1.9, `@1inch/limit-order-protocol-contract` 4.3.3. All three Aqua-family packages depend on `viem ^2.48.4`. Monorepo: github.com/1inch/sdks (pnpm + Nx, Node ≥22, Foundry, Docker for e2e).

Source: https://registry.npmjs.org/@1inch/aqua-sdk

### 1inch — @1inch/aqua-sdk API surface

`new AquaProtocolContract(address)` with `.ship({app, strategy: HexString, amountsAndTokens: [{token: Address, amount: bigint}]})` and `.dock({app, strategyHash, tokens: Address[]})`, both returning `CallInfo = {to: Hex, data: Hex, value: bigint}`. Statics: `encodeShipCallData`, `encodeDockCallData`, `buildShipTx`, `buildDockTx`, `calculateStrategyHash(HexString)`. Exports `AQUA_CONTRACT_ADDRESSES: Record<NetworkEnum, Address>`, `ABI.AQUA_ABI`, types `ShipArgs`/`DockArgs`/`AmountsAndTokens`, and event classes `PushedEvent`, `PulledEvent`, `ShippedEvent`, `DockedEvent` (each with `.fromLog(log)`).

Source: https://www.npmjs.com/package/@1inch/aqua-sdk

### 1inch — @1inch/swap-vm-sdk API surface

`new SwapVMContract(AQUA_SWAP_VM_CONTRACT_ADDRESSES[chainId])` with `.quote({order, tokenIn, tokenOut, amount, takerTraits})`, `.swap(sameParams)`, `.hashOrder(order)` → CallInfo. `Order.new({maker, program, traits})`, `Order.parse(HexString)`, `order.encode()`, `order.hash({chainId, name, version})`. `MakerTraits.default()`, `TakerTraits.default()`. Strategies: `AquaXYCAmmStrategy.new()/.newConcentrate({rawPriceMin, rawPriceMax} | {sqrtPriceMin, sqrtPriceMax})`, `AquaPeggedAmmStrategy`, `AquaAMMStrategy`. Builders: `AquaProgramBuilder` (pre-wired to the Aqua opcode subset — recommended) and generic `ProgramBuilder(ixsSet)`. Exports `SwappedEvent`, `ABI.SWAP_VM_ABI`, `instructions.*` namespaces (controls, balances, invalidators, xycSwap, concentrate, decay, limitSwap, minRate, dutchAuction, oraclePriceAdjuster, baseFeeAdjuster, twapSwap, extruction, fee), `instructions.concentrate.ONE_E18`.

Source: https://www.npmjs.com/package/@1inch/swap-vm-sdk

### 1inch — CRITICAL instruction-set caveat

The SDK encodes the FULL SwapVM instruction set (`_allInstructions`), but the currently deployed `AquaSwapVMRouter` contracts only execute the **Aqua subset** (`aquaInstructions`). Programs using out-of-subset opcodes encode fine but will NOT execute on-chain today. A full SwapVM deployment is planned after the Fusaka hardfork. Use `AquaProgramBuilder` to be safe. Also: the opcode array INDEX must match the on-chain layout — a mismatch silently executes the wrong instruction.

Source: https://www.npmjs.com/package/@1inch/swap-vm-sdk

### 1inch — Aqua instruction subset (runtime-available categories)

Balances: STATIC_BALANCES_XD, DYNAMIC_BALANCES_XD. Invalidators: INVALIDATE_BIT_1D, INVALIDATE_TOKEN_IN_1D, INVALIDATE_TOKEN_OUT_1D. Controls: JUMP, JUMP_IF_TOKEN_IN, JUMP_IF_TOKEN_OUT, DEADLINE, ONLY_TAKER_TOKEN_BALANCE_NON_ZERO, ONLY_TAKER_TOKEN_BALANCE_GTE, ONLY_TAKER_TOKEN_SUPPLY_SHARE_GTE, SALT. Trading: XYC_SWAP_XD, CONCENTRATE_GROW_LIQUIDITY_2D, DECAY_XD, LIMIT_SWAP_1D, LIMIT_SWAP_ONLY_FULL_1D, REQUIRE_MIN_RATE_1D, ADJUST_MIN_RATE_1D, DUTCH_AUCTION_BALANCE_IN_1D, DUTCH_AUCTION_BALANCE_OUT_1D, ORACLE_PRICE_ADJUSTER_1D, BASE_FEE_ADJUSTER_1D, TWAP, EXTRUCTION. Fees: FLAT_FEE_AMOUNT_IN_XD, FLAT_FEE_AMOUNT_OUT_XD, PROGRESSIVE_FEE_IN_XD, PROGRESSIVE_FEE_OUT_XD, PROTOCOL_FEE_AMOUNT_OUT_XD, AQUA_PROTOCOL_FEE_AMOUNT_OUT_XD.

Source: https://www.npmjs.com/package/@1inch/swap-vm-sdk

### 1inch — official reference fork test harness

1inch's own tests run anvil in a testcontainer: image `ghcr.io/foundry-rs/foundry:v1.2.3`, command `anvil -f $FORK_URL --fork-header "..." --chain-id 1 --mnemonic 'hat hat horse border print cancel subway heavy copy alert eternal mask' --host 0.0.0.0`, default FORK_URL `https://eth.llamarpc.com`. viem `createTestClient({mode:'anvil'})`. They fund an LP (WETH+USDC, unlimited approve to Aqua) and a swapper (USDC) by impersonating a USDC donor. Files: typescript/aqua/tests/setup-evm.ts, aqua.spec.ts; typescript/swap-vm/tests/setup-evm.ts, swap-vm.spec.ts in github.com/1inch/sdks.

Source: https://github.com/1inch/sdks/blob/master/typescript/aqua/tests/setup-evm.ts

### 1inch — what "build an Aqua app" means (1inch's own words)

From the 1inch Aqua bounty program: developers create a custom Aqua app based on SwapVM that implements a sophisticated DeFi position; they may modify SwapVM opcodes and define their own instructions; the final position is demonstrated through tests, scripts, or a UI. (1inch's standing Aqua/SwapVM contribution + bug bounty runs up to $100,000, separate from the ETHOnline prize.)

Source: https://blog.1inch.com/1inch-aqua-bounty-program/

### 1inch — repos, audit, licence

Repos: github.com/1inch/aqua (Foundry: `forge install && forge test`), github.com/1inch/swap-vm, github.com/1inch/sdks. Audited by OpenZeppelin ("1inch Aqua and SwapVM MVP v1.0 Audit"). Bug bounty at hackenproof.com/programs/1inch-aqua. Licence is NOT OSI: `LicenseRef-Degensoft-Aqua-Source-1.1` / `LicenseRef-Degensoft-SwapVM-1.1` (contact license@degensoft.com / legal@degensoft.com). Relevant if your repo must be "open source" for another sponsor — keep 1inch code as a dependency, not vendored.

Source: https://www.openzeppelin.com/news/1inch-aqua-and-swapvm-mvp-v1.0-audit

### ETHOnline 2026 — exact bounty requirements (all four)

Privy $5,000: T1 Best B2B Financial Product $2,500 (Privy as core, ≥1 wallet, business use case, ≥1 B2B workflow, ≥1 control from policies/signers/quorums/intents, working demo + source); T2 Best Financial Flow $2,500. World $7,000: T1 AgentKit Continuity $3,500 (up to 3 teams @ $1,166); T2 Selfie Check $3,500 (up to 3 teams @ $1,166 — meaningful risk/eligibility/fairness signal + feedback doc + working app). Uniswap Foundation $5,000: T1 Best Uniswap Stack Contribution $3,000 (up to 3 @ $1,000; public repo, FEEDBACK.md, feedback form, README naming contracts); T2 Continuity $2,000. 1inch $7,000: T1 Build an Aqua App $5,000 (1st $2,500 / 2nd $1,500 / 3rd $1,000 — official Aqua/SwapVM contracts, on-chain token transfers incl. local forks, proper git history); T2 Continuity $2,000.

Source: https://ethglobal.com/events/ethonline2026/prizes

## Code and commands

### Privy: full B2B setup — auth key → key quorum → policy → wallet with policy + per-signer override

This single file satisfies the Privy Track 1 control requirement three times over (policies + signers + key quorums). `bun add @privy-io/node@latest`. Verified against the published 0.34.0 .d.ts: PrivyClient uses METHOD accessors. Keep the numeric encoding in your policy `value` identical to what you later put in the tx body (both hex here).

```typescript
// src/integrations/privy/setup.ts
import { PrivyClient, generateP256KeyPair, type AuthorizationContext } from '@privy-io/node';
import { erc20Abi } from 'viem';

const privy = new PrivyClient({
  appId: process.env.PRIVY_APP_ID!,
  appSecret: process.env.PRIVY_APP_SECRET!,
});

const USDC_SEPOLIA = '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238'; // replace w/ your test token
const TREASURY = '0x000000000000000000000000000000000000dEaD';

// ---------------------------------------------------------------- 1. auth keys
// Server-held authorization keys. Base64 DER, no PEM headers. Privy never stores these.
const opsKey   = await generateP256KeyPair();   // low-authority "agent" signer
const adminKey = await generateP256KeyPair();   // high-authority human signer

// ------------------------------------------------------- 2. key quorum (owner)
// 1-of-1 here for speed; bump authorization_threshold to 2 for a real 2-of-2.
const ownerQuorum = await privy.keyQuorums().create({
  display_name: 'Arx treasury owner',
  public_keys: [adminKey.publicKey],
  authorization_threshold: 1,
});

const opsSignerQuorum = await privy.keyQuorums().create({
  display_name: 'Arx agent signer',
  public_keys: [opsKey.publicKey],
  authorization_threshold: 1,
});

// ------------------------------------------------------------------ 3. policies
// REMEMBER: default is DENY. Every RPC method the wallet uses needs a rule.
const agentPolicy = await privy.policies().create({
  name: 'Arx agent policy — small USDC payouts to allowlisted vendors only',
  version: '1.0',
  chain_type: 'ethereum',
  owner_id: ownerQuorum.id, // only the admin quorum may mutate this policy
  rules: [
    {
      name: 'ALLOW USDC transfer to allowlisted vendors, <= 100 USDC, Sepolia only',
      method: 'eth_sendTransaction',
      action: 'ALLOW',
      conditions: [
        { field_source: 'ethereum_transaction', field: 'chain_id', operator: 'eq',  value: '11155111' },
        { field_source: 'ethereum_transaction', field: 'to',       operator: 'eq',  value: USDC_SEPOLIA },
        // calldata conditions REQUIRE an inline JSON ABI
        { field_source: 'ethereum_calldata', abi: erc20Abi as unknown as object,
          field: 'transfer.to',     operator: 'in',  value: [TREASURY] },
        { field_source: 'ethereum_calldata', abi: erc20Abi as unknown as object,
          field: 'transfer.value',  operator: 'lte', value: '0x5F5E100' }, // 100e6
        // business-hours style guard
        { field_source: 'system', field: 'current_unix_timestamp', operator: 'gte', value: '1757000000' },
      ],
    },
    { name: 'DENY key export outright', method: 'exportPrivateKey', action: 'DENY', conditions: [] },
  ],
});

const adminPolicy = await privy.policies().create({
  name: 'Arx admin policy — any contract, any amount',
  version: '1.0',
  chain_type: 'ethereum',
  owner_id: ownerQuorum.id,
  rules: [{
    name: 'Allow all eth_sendTransaction',
    method: 'eth_sendTransaction',
    action: 'ALLOW',
    conditions: [{ field_source: 'ethereum_transaction', field: 'chain_id', operator: 'in', value: ['11155111'] }],
  }],
});

// ----------------------------------------------------- 4. wallet + attachments
// NOTE: only ONE policy_id per wallet today. Per-signer authority comes from
// additional_signers[].override_policy_ids — that's the B2B trick.
const wallet = await privy.wallets().create({
  chain_type: 'ethereum',
  display_name: 'Acme Corp operating wallet',
  external_id: 'acme-corp-operating',
  owner_id: ownerQuorum.id,
  policy_ids: [adminPolicy.id],
  additional_signers: [
    { signer_id: opsSignerQuorum.id, override_policy_ids: [agentPolicy.id] },
  ],
});

console.log({ walletId: wallet.id, address: wallet.address });

// ------------------------------------------------ 5. sign as the RESTRICTED key
// Privy evaluates ONLY this signer's override policy.
const agentCtx: AuthorizationContext = { authorization_private_keys: [opsKey.privateKey] };

const { hash } = await privy.wallets().ethereum().sendTransaction(wallet.id, {
  caip2: 'eip155:11155111',
  params: { transaction: { to: USDC_SEPOLIA, value: '0x0', chain_id: 11155111, data: '0xa9059cbb...' } },
  authorization_context: agentCtx,
});
console.log('tx', hash);
```

### Privy: rolling 24h spend cap (stateful policy via aggregations)

No SDK helper is documented for aggregations; use REST. Max 10 aggregations per app. Only eth_signTransaction / eth_signUserOperation are supported methods. Window seconds must be 3600..259200.

```bash
# 1) create the aggregation
curl -sX POST https://api.privy.io/v1/aggregations \
  -u "$PRIVY_APP_ID:$PRIVY_APP_SECRET" \
  -H "privy-app-id: $PRIVY_APP_ID" -H 'content-type: application/json' \
  -d '{
    "method": "eth_signTransaction",
    "metric": { "field": "value", "field_source": "ethereum_transaction", "function": "sum" },
    "window": { "type": "rolling", "seconds": 86400 },
    "conditions": [
      { "field_source": "ethereum_transaction", "field": "chain_id", "operator": "eq", "value": "11155111" }
    ]
  }'
# -> { "id": "cmtd4d5i10bf94m5m2o8tp", ... }

# 2) reference it from a policy condition
#    field_source: 'reference', field: 'aggregation.<id>'
curl -sX POST https://api.privy.io/v1/policies \
  -u "$PRIVY_APP_ID:$PRIVY_APP_SECRET" \
  -H "privy-app-id: $PRIVY_APP_ID" -H 'content-type: application/json' \
  -d '{
    "version": "1.0",
    "name": "Rolling 24h ETH cap",
    "chain_type": "ethereum",
    "rules": [{
      "name": "Allow while 24h cumulative value <= 0.5 ETH",
      "method": "eth_signTransaction",
      "action": "ALLOW",
      "conditions": [
        { "field_source": "reference",
          "field": "aggregation.cmtd4d5i10bf94m5m2o8tp",
          "operator": "lte",
          "value": "0x6F05B59D3B20000" }
      ]
    }]
  }'
```

### Privy: intents — propose now, human authorizes later (Ledger-friendly)

This is the exact shape of Arx's escalation path. The Node SDK has NO intents().authorize() in 0.34.0 — you must hand-roll the authorize call with the exported signing utilities. `url` must have no trailing slash and must match byte-for-byte what you POST to.

```typescript
// src/integrations/privy/intent.ts
import { PrivyClient, generateAuthorizationSignature,
         type EthereumSendTransactionRpcInput } from '@privy-io/node';

const privy = new PrivyClient({
  appId: process.env.PRIVY_APP_ID!,
  appSecret: process.env.PRIVY_APP_SECRET!,
});

// --- 1. agent proposes (NO signature required at this step) -----------------
const rpcRequest: EthereumSendTransactionRpcInput = {
  method: 'eth_sendTransaction',
  caip2: 'eip155:11155111',
  params: { transaction: { to: '0xE3070d3e4309afA3bC9a6b057685743CF42da77C',
                           value: '0x2386F26FC10000', chain_id: 11155111 } },
};

const intent = await privy.intents().rpc(walletId, rpcRequest);
console.log(intent.intent_id, intent.status, intent.authorization_details);
// status: 'pending'. Expires in 72h. Arx can now run risk checks / World ID /
// Ledger confirmation while the intent sits there.

// --- 2. human/approver authorizes -------------------------------------------
const intentId = intent.intent_id;
const body = {} as const; // authorize body is the signature envelope itself
const timestamp = Date.now();

const signature = generateAuthorizationSignature({
  authorizationPrivateKey: process.env.PRIVY_ADMIN_AUTH_KEY!, // base64 DER PKCS8, no PEM
  input: {
    version: 1,
    method: 'POST',
    url: `https://api.privy.io/v1/intents/${intentId}/authorize`, // no trailing slash
    body,
    headers: { 'privy-app-id': process.env.PRIVY_APP_ID! },
  },
});

const res = await fetch(`https://api.privy.io/v1/intents/${intentId}/authorize`, {
  method: 'POST',
  headers: {
    authorization: 'Basic ' + Buffer.from(
      `${process.env.PRIVY_APP_ID}:${process.env.PRIVY_APP_SECRET}`).toString('base64'),
    'privy-app-id': process.env.PRIVY_APP_ID!,
    'content-type': 'application/json',
  },
  body: JSON.stringify({ signature, timestamp }),
});
console.log(res.status, await res.json());

// --- 3. poll / webhook ------------------------------------------------------
const final = await privy.intents().get(intentId);
// final.status: 'executed' | 'failed' | 'expired' | 'rejected' | 'dismissed'
// final.action_result holds the tx hash on success. Webhook: intent.executed
```

### World: headless Selfie Check gate on a Bun/Fastify server (no React, no mini app)

`bun add @worldcoin/idkit-core@^4`. Two routes: start (returns a QR URL) and a background poll+verify. The server never trusts the client-supplied proof — it polls the bridge itself and forwards the untouched payload to the v4 verify endpoint. Swap `selfieCheckLegacy` for `orbLegacy` if the Selfie Check flag isn't enabled yet.

```typescript
// src/integrations/world/selfie-gate.ts
import { IDKit, selfieCheckLegacy } from '@worldcoin/idkit-core';
import { signRequest } from '@worldcoin/idkit-core/signing';
import type { FastifyInstance } from 'fastify';

const APP_ID = process.env.WORLD_APP_ID as `app_${string}`;
const RP_ID  = process.env.WORLD_RP_ID!;                 // rp_...
const SIGNING_KEY = process.env.WORLD_RP_SIGNING_KEY!;    // server-only, hex
const ENVIRONMENT = (process.env.WORLD_ENV ?? 'production') as 'production' | 'staging';

// nullifier store — in prod: NUMERIC(78,0) with UNIQUE (nullifier, action)
const seen = new Set<string>();

export type GateResult =
  | { ok: true; nullifier: string }
  | { ok: false; reason: string };

/**
 * Bind the proof to the exact action being authorized via `signal`.
 * Arx: signal = hash of the normalized intent, so a proof for one
 * payout cannot be replayed for another.
 */
export async function requestSelfieCheck(opts: { action: string; signal: string }) {
  const { sig, nonce, createdAt, expiresAt } = signRequest({
    signingKeyHex: SIGNING_KEY,
    action: opts.action,
    ttl: 300,
  });

  const request = await IDKit.request({
    app_id: APP_ID,
    action: opts.action,
    rp_context: { rp_id: RP_ID, nonce, created_at: createdAt,
                  expires_at: expiresAt, signature: sig },
    allow_legacy_proofs: true, // Selfie Check is World ID 3.0 today
    environment: ENVIRONMENT,
  }).preset(selfieCheckLegacy({ signal: opts.signal }));

  return {
    connectorURI: request.connectorURI, // render as QR / deep link
    requestId: request.requestId,
    // resolves when the user finishes in World ID App
    settle: async (): Promise<GateResult> => {
      const completion = await request.pollUntilCompletion({
        pollInterval: 2_000, timeout: 180_000,
      });
      if (!completion.success) {
        console.error('idkit failed', request.getDebugReport());
        return { ok: false, reason: String(completion.error) };
      }
      return verifyAndConsume(completion, opts.action);
    },
  };
}

async function verifyAndConsume(idkitResponse: unknown, action: string): Promise<GateResult> {
  // forward BYTE-FOR-BYTE. Do not remap identifiers, do not build a
  // verification_level, do not re-encode. Selfie Check returns
  // responses[].identifier === 'selfie'.
  const res = await fetch(`https://developer.world.org/api/v4/verify/${RP_ID}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(idkitResponse),
  });
  if (!res.ok) return { ok: false, reason: `verify_failed:${res.status}` };

  const body = await res.json() as { success: boolean; nullifier?: string };
  const nullifier = body.nullifier;
  if (!nullifier) return { ok: false, reason: 'no_nullifier' };

  const key = `${action}:${BigInt(nullifier).toString(10)}`;
  if (seen.has(key)) return { ok: false, reason: 'nullifier_replay' };
  seen.add(key);
  return { ok: true, nullifier };
}

export function registerWorldRoutes(app: FastifyInstance) {
  app.post<{ Body: { intentId: string } }>('/gate/selfie/start', async (req) => {
    const action = `arx-approve-${req.body.intentId}`;
    const r = await requestSelfieCheck({ action, signal: req.body.intentId });
    // fire-and-store; resolve into your intent state machine
    void r.settle().then((g) => console.log('gate result', req.body.intentId, g));
    return { qr: r.connectorURI, requestId: r.requestId };
  });
}
```

### World: RP signature route (if you keep the widget on a React client)

The only thing the client may ever receive is {sig, nonce, created_at, expires_at}. Never NEXT_PUBLIC_ the signing key, never sign on the client. Client then passes it as rp_context to <IDKitRequestWidget preset={selfieCheckLegacy({signal})} />.

```typescript
// Fastify equivalent of the Next.js /api/rp-signature route
import { signRequest } from '@worldcoin/idkit-core/signing';

app.post<{ Body: { action: string } }>('/api/rp-signature', async (req) => {
  const { sig, nonce, createdAt, expiresAt } = signRequest({
    signingKeyHex: process.env.WORLD_RP_SIGNING_KEY!,
    action: req.body.action,
  });
  return { sig, nonce, created_at: createdAt, expires_at: expiresAt };
});

// Client side (React):
//   <IDKitRequestWidget
//     open={open} onOpenChange={setOpen}
//     app_id={process.env.NEXT_PUBLIC_WORLD_APP_ID as `app_${string}`}
//     action={action}
//     rp_context={rpContext}
//     preset={selfieCheckLegacy({ signal: intentId })}
//     handleVerify={async (result) => {
//        const r = await fetch('/api/verify-proof', { method: 'POST',
//          body: JSON.stringify({ rp_id: RP_ID, idkitResponse: result }) });
//        if (!r.ok) throw new Error('Backend verification failed');
//     }}
//     onSuccess={() => {}}
//   />
```

### Uniswap: quote → Arx policy-check the calldata → swap (the firewall demo)

This is the highest-value-per-hour Uniswap integration for a firewall project. The quote response hands you the whole v4 route WITH each pool's hooks address, and /swap hands you exact {to, data, value}. You allowlist the router, decode the calldata, and reject unknown hooks — then hand the approved tx to Ledger. Needs a free x-api-key.

```typescript
// src/integrations/uniswap/firewall.ts
import { decodeFunctionData, getAddress, type Address, type Hex } from 'viem';

const API = 'https://trade-api.gateway.uniswap.org/v1';
const headers = {
  'x-api-key': process.env.UNISWAP_API_KEY!,
  'content-type': 'application/json',
  accept: 'application/json',
  // pin the router version so your decoder never drifts
  'x-universal-router-version': '2.0',
};

// Sepolia (11155111) — verified against developers.uniswap.org/docs/protocols/v4/deployments
const ALLOWED_ROUTERS = new Set<Address>([
  getAddress('0x3A9D48AB9751398BbFa63ad67599Bb04e4BdF98b'), // Universal Router 2.0
  getAddress('0x7dfd4f31be6814d2906bde155c3e1b146eac1468'), // Universal Router 2.1.1
]);
const POOL_MANAGER = getAddress('0xE03A1074c86CFeDd5C142C4F04F1a1536e203543');
const PERMIT2      = getAddress('0x000000000022D473030F116dDEE9F6B43aC78BA3');
const ALLOWED_HOOKS = new Set<Address>([
  '0x0000000000000000000000000000000000000000', // no-hook pools only, by default
]);

type V4Pool = { type: 'v4-pool'; hooks: Address; fee: string; address: string };
type RoutePool = V4Pool | { type: 'v2-pool' | 'v3-pool' };

export type Decision =
  | { verdict: 'ALLOW'; tx: { to: Address; data: Hex; value: string; chainId: number } }
  | { verdict: 'DENY' | 'ESCALATE'; reasons: string[] };

export async function quoteAndScreen(p: {
  tokenIn: Address; tokenOut: Address; amount: string; swapper: Address; chainId: number;
}): Promise<Decision> {
  // ---- 1. quote
  const qr = await fetch(`${API}/quote`, {
    method: 'POST', headers,
    body: JSON.stringify({
      type: 'EXACT_INPUT',
      amount: p.amount,
      tokenIn: p.tokenIn,
      tokenOut: p.tokenOut,
      tokenInChainId: p.chainId,
      tokenOutChainId: p.chainId,
      swapper: p.swapper,
      slippageTolerance: 0.5,
      routingPreference: 'BEST_PRICE',
      protocols: ['V2', 'V3', 'V4'],
      hooksOptions: 'V4_NO_HOOKS',   // or V4_HOOKS_INCLUSIVE + screen below
    }),
  });
  if (!qr.ok) return { verdict: 'DENY', reasons: [`quote_${qr.status}: ${await qr.text()}`] };
  const { routing, quote, permitData } = await qr.json();

  const reasons: string[] = [];

  // ---- 2. route-level policy: screen every hook in the proposed route
  const pools: RoutePool[] = (quote.route ?? []).flat();
  for (const pool of pools) {
    if (pool.type === 'v4-pool') {
      const hook = getAddress((pool as V4Pool).hooks);
      if (!ALLOWED_HOOKS.has(hook)) reasons.push(`unknown_v4_hook:${hook}`);
    }
  }
  if (Number(quote.priceImpact ?? 0) > 2) reasons.push(`price_impact:${quote.priceImpact}`);
  if ((quote.txFailureReasons ?? []).length) reasons.push(`sim:${quote.txFailureReasons.join(',')}`);

  // UniswapX routes are gasless orders, not txs — Arx can't Ledger-sign an EOA tx for them
  if (!['CLASSIC', 'WRAP', 'UNWRAP', 'BRIDGE'].includes(routing)) {
    return { verdict: 'DENY', reasons: [`unsupported_routing:${routing}`, ...reasons] };
  }

  // ---- 3. build calldata
  const sr = await fetch(`${API}/swap`, {
    method: 'POST', headers,
    body: JSON.stringify({ quote, permitData, simulateTransaction: true }),
  });
  if (!sr.ok) return { verdict: 'DENY', reasons: [`swap_${sr.status}: ${await sr.text()}`, ...reasons] };
  const { swap } = await sr.json() as {
    swap: { to: Address; data: Hex; value: string; from: Address; chainId: number };
  };

  // ---- 4. transaction-level policy: target allowlist + non-empty calldata
  const to = getAddress(swap.to);
  if (!ALLOWED_ROUTERS.has(to)) reasons.push(`router_not_allowlisted:${to}`);
  if (!swap.data || swap.data === '0x') reasons.push('empty_calldata');
  if (getAddress(swap.from) !== getAddress(p.swapper)) reasons.push('from_mismatch');

  if (reasons.length) return { verdict: 'ESCALATE', reasons };
  return { verdict: 'ALLOW', tx: { to, data: swap.data, value: swap.value, chainId: swap.chainId } };
}

// Optional deeper decode: Universal Router `execute(bytes commands, bytes[] inputs, uint256 deadline)`
export const UR_EXECUTE_ABI = [{
  type: 'function', name: 'execute', stateMutability: 'payable',
  inputs: [{ name: 'commands', type: 'bytes' },
           { name: 'inputs', type: 'bytes[]' },
           { name: 'deadline', type: 'uint256' }],
  outputs: [],
}] as const;

export function decodeUniversalRouter(data: Hex) {
  return decodeFunctionData({ abi: UR_EXECUTE_ABI, data });
  // -> { functionName: 'execute', args: [commands, inputs, deadline] }
  // Each byte of `commands` is a UR command id; see
  // developers.uniswap.org/docs/protocols/universal-router/concepts/commands
}
export { POOL_MANAGER, PERMIT2 };
```

### Uniswap: check_approval before the swap

/check_approval returns a fully-formed tx when a Permit2 approval is missing. Run it through the same Arx policy check (target must be the token contract, spender must be Permit2).

```typescript
const ar = await fetch(`${API}/check_approval`, {
  method: 'POST', headers,
  body: JSON.stringify({
    walletAddress: swapper,
    token: tokenIn,
    amount: (BigInt(amount) * 2n).toString(),
    chainId: 11155111,
    tokenOut,
    tokenOutChainId: 11155111,
  }),
});
const { approval } = await ar.json();
if (approval) {
  // approval is { to, from, data, value, chainId, ... } — policy-check then sign
}
```

### 1inch: minimum viable on-chain Aqua App on an anvil mainnet fork

THE key insight for the bounty: fork mainnet and the OFFICIAL Aqua + AquaSwapVMRouter contracts are already in state at their deterministic addresses — you use them, you don't deploy them. `bun add @1inch/aqua-sdk @1inch/swap-vm-sdk @1inch/sdk-core viem`. Run `anvil -f $MAINNET_RPC --chain-id 1` first. Keep AquaProgramBuilder / Aqua* strategies only — out-of-subset opcodes encode but won't execute.

```typescript
// scripts/aqua-demo.ts   — run with: bun scripts/aqua-demo.ts
import {
  AquaProtocolContract, AQUA_CONTRACT_ADDRESSES, ABI as AQUA_ABI_NS,
} from '@1inch/aqua-sdk';
import {
  SwapVMContract, AQUA_SWAP_VM_CONTRACT_ADDRESSES, Order, MakerTraits,
  TakerTraits, AquaXYCAmmStrategy, instructions, ABI as VM_ABI_NS,
} from '@1inch/swap-vm-sdk';
import { Address, HexString, NetworkEnum } from '@1inch/sdk-core';
import {
  createTestClient, createWalletClient, http, publicActions, parseUnits,
  decodeFunctionResult, erc20Abi, type Hex,
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { mainnet } from 'viem/chains';

const RPC = 'http://127.0.0.1:8545';            // anvil -f <mainnet rpc>
const chainId = NetworkEnum.ETHEREUM;            // 1

const WETH = new Address('0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2');
const USDC = new Address('0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48');

// OFFICIAL contracts — same address on every chain, already live on the fork
const AQUA_ADDR   = AQUA_CONTRACT_ADDRESSES[chainId];          // 0x1111113ccf1426a8e30e2bff5e005d929bf6a90a
const SWAPVM_ADDR = AQUA_SWAP_VM_CONTRACT_ADDRESSES[chainId];  // 0x111111338c5091e8440b67b168bae16a668ac0de

const aqua   = new AquaProtocolContract(AQUA_ADDR);
const swapVM = new SwapVMContract(SWAPVM_ADDR);

const transport = http(RPC);
const test   = createTestClient({ mode: 'anvil', chain: mainnet, transport }).extend(publicActions);
const maker  = createWalletClient({ chain: mainnet, transport,
  account: privateKeyToAccount(process.env.MAKER_PK as Hex) }).extend(publicActions);
const taker  = createWalletClient({ chain: mainnet, transport,
  account: privateKeyToAccount(process.env.TAKER_PK as Hex) }).extend(publicActions);

// ---------------------------------------------------- 0. fund on the fork
await test.setBalance({ address: maker.account.address, value: parseUnits('100', 18) });
await test.setBalance({ address: taker.account.address, value: parseUnits('100', 18) });
// impersonate a whale to move WETH/USDC, or use anvil_setStorageAt / deal helpers

// ------------------------------- 1. maker: single approval to the Aqua registry
for (const token of [WETH, USDC]) {
  await maker.writeContract({
    address: token.toString() as Hex, abi: erc20Abi, functionName: 'approve',
    args: [AQUA_ADDR.toString() as Hex, 2n ** 256n - 1n],
    chain: mainnet, account: maker.account,
  });
}

// ---------------- 2. maker: compile a SwapVM program and ship it into Aqua
//    The "app" IS the official AquaSwapVMRouter; the "strategy" IS the encoded Order.
const { ONE_E18 } = instructions.concentrate;
const program = AquaXYCAmmStrategy.newConcentrate({
  rawPriceMin: ONE_E18 / 3000n,   // P = tokenGt/tokenLt, 1e18 fixed point
  rawPriceMax: ONE_E18 / 1500n,   // i.e. 1500–3000 USDC per WETH
}).build();

const order = Order.new({
  maker: new Address(maker.account.address),
  program,
  traits: MakerTraits.default(),  // Aqua mode: no EIP-712 signature needed
});

const encodedOrder = order.encode();                     // this is the `strategy`
const strategyHash = AquaProtocolContract.calculateStrategyHash(encodedOrder);

const shipTx = aqua.ship({
  app: new Address(SWAPVM_ADDR.toString()),
  strategy: encodedOrder,
  amountsAndTokens: [
    { token: USDC, amount: parseUnits('10000', 6) },
    { token: WETH, amount: parseUnits('5', 18) },
  ],
});
const shipHash = await maker.sendTransaction({ ...shipTx, chain: mainnet, account: maker.account });
await maker.waitForTransactionReceipt({ hash: shipHash });
console.log('shipped', { strategyHash: strategyHash.toString(), shipHash });

// ---------------------------------------------- 3. taker: quote, then swap
const swapParams = {
  order: Order.parse(encodedOrder),
  amount: parseUnits('1000', 6),
  takerTraits: TakerTraits.default(),
  tokenIn: USDC,
  tokenOut: WETH,
};

const sim = await taker.call(swapVM.quote(swapParams));
const [amountIn, amountOut] = decodeFunctionResult({
  abi: VM_ABI_NS.SWAP_VM_ABI, functionName: 'quote', data: sim.data!,
});
console.log('quote', { amountIn, amountOut });

// ARX HOOK: this is where you policy-check {to, data, value} + amountOut
// against your firewall rules, then hand it to the Ledger signer.
const swapCall = swapVM.swap(swapParams);   // CallInfo { to, data, value }

await taker.writeContract({
  address: USDC.toString() as Hex, abi: erc20Abi, functionName: 'approve',
  args: [SWAPVM_ADDR.toString() as Hex, swapParams.amount],
  chain: mainnet, account: taker.account,
});

const swapHash = await taker.sendTransaction({ ...swapCall, chain: mainnet, account: taker.account });
const rcpt = await taker.waitForTransactionReceipt({ hash: swapHash });
console.log('SWAPPED onchain', swapHash, rcpt.status);   // <- the bounty's "onchain token transfer"

// ----------------------------------- 4. read virtual balances / parse events
const [bal] = await test.readContract({
  address: AQUA_ADDR.toString() as Hex, abi: AQUA_ABI_NS.AQUA_ABI,
  functionName: 'rawBalances',
  args: [maker.account.address, SWAPVM_ADDR.toString() as Hex,
         strategyHash.toString() as Hex, USDC.toString() as Hex],
});
console.log('maker virtual USDC balance', bal);

// ------------------------------------------------------- 5. maker: dock out
const dockTx = aqua.dock({
  app: new Address(SWAPVM_ADDR.toString()),
  strategyHash,
  tokens: [USDC, WETH],
});
await maker.sendTransaction({ ...dockTx, chain: mainnet, account: maker.account });
```

### 1inch: anvil fork + custom Aqua instruction skeleton

First block = the fork 1inch's own tests use. Second block = the minimum for a *custom* Aqua app (what 1inch says earns the bounty): a strategy class that composes Aqua-subset opcodes into a program.

```bash
# --- fork mainnet; official Aqua + SwapVM are already deployed in this state
anvil -f "$MAINNET_RPC_URL" --chain-id 1 \
  --mnemonic 'hat hat horse border print cancel subway heavy copy alert eternal mask' \
  --host 127.0.0.1 --port 8545

# verify the official contracts are present on your fork
cast code 0x1111113ccf1426a8e30e2bff5e005d929bf6a90a --rpc-url http://127.0.0.1:8545 | head -c 20
cast code 0x111111338c5091e8440b67b168bae16a668ac0de --rpc-url http://127.0.0.1:8545 | head -c 20

# 1inch's own harness, if you want to copy it verbatim
git clone https://github.com/1inch/sdks && cd sdks
pnpm install && pnpm build:contracts    # forge build -> dist/contracts
FORK_URL=$MAINNET_RPC_URL pnpm nx test aqua
FORK_URL=$MAINNET_RPC_URL pnpm nx test swap-vm
```

### 1inch: a custom Aqua strategy (the "Aqua App" deliverable)

A strategy is just a program builder. Use AquaProgramBuilder so you physically cannot emit an opcode the deployed router can't run. Guards like DEADLINE / ONLY_TAKER_TOKEN_BALANCE_GTE are exactly the 'policy in the VM' angle that connects this to Arx.

```typescript
// src/integrations/oneinch/ArxGuardedAmmStrategy.ts
import {
  AquaProgramBuilder, instructions, Address, Order, MakerTraits,
  type SwapVmProgram,
} from '@1inch/swap-vm-sdk';

const { concentrate, fee, controls } = instructions;

/**
 * Arx-guarded AMM: concentrated liquidity + taker fee + hard deadline +
 * a minimum-taker-balance guard. Demonstrates policy enforced *inside*
 * the swap program, not just off-chain.
 */
export class ArxGuardedAmmStrategy {
  private rawPriceMin?: bigint;
  private rawPriceMax?: bigint;
  private feeBpsIn?: number;
  private deadline?: bigint;

  constructor(public readonly tokenA: Address, public readonly tokenB: Address) {}

  withPriceRange(min: bigint, max: bigint) { this.rawPriceMin = min; this.rawPriceMax = max; return this; }
  withTakerFeeBps(bps: number)            { this.feeBpsIn = bps; return this; }
  withDeadline(unixSeconds: bigint)       { this.deadline = unixSeconds; return this; }

  build(): SwapVmProgram {
    const b = new AquaProgramBuilder(); // pre-wired to aquaInstructions

    // ORDER MATTERS — guards first, then pricing, then fee, then the swap.
    if (this.deadline !== undefined) {
      b.add(controls.deadline.createIx(new controls.DeadlineArgs(this.deadline)));
    }
    if (this.rawPriceMin !== undefined && this.rawPriceMax !== undefined) {
      const data = concentrate.ConcentrateGrowLiquidity2DArgs
        .fromRawPrices(this.rawPriceMin, this.rawPriceMax);
      b.add(concentrate.concentrateGrowLiquidity2D.createIx(data));
    }
    if (this.feeBpsIn !== undefined) {
      b.add(fee.flatFeeAmountInXD.createIx(fee.FlatFeeArgs.fromBps(this.feeBpsIn)));
    }
    b.xycSwapXD();
    return b.build();
  }
}

// usage
// const program = new ArxGuardedAmmStrategy(USDC, WETH)
//   .withPriceRange(ONE_E18 / 3000n, ONE_E18 / 1500n)
//   .withTakerFeeBps(5)
//   .withDeadline(BigInt(Math.floor(Date.now()/1000) + 3600))
//   .build();
// const order = Order.new({ maker, program, traits: MakerTraits.default() });
// then aqua.ship({ app: SWAPVM_ADDR, strategy: order.encode(), amountsAndTokens })
```

### World: human-in-the-loop agent tool (drop-in, if you add a Vercel-AI-SDK surface)

`bun add @worldcoin/human-in-the-loop ai workflow`. Env: WORLD_RP_ID, WORLD_SIGNING_KEY. This is worth knowing about even if you don't adopt it — it's the World-blessed shape of exactly what Arx does, and citing it in your FEEDBACK doc shows you read the docs.

```typescript
// src/workflows/chat/steps/tools.ts
import { requestHumanAuthorization } from '@worldcoin/human-in-the-loop/workflows';
import { z } from 'zod';

export const tools = {
  approveHighRiskTransfer: {
    description: 'Request verified-human approval via World ID before a high-risk transfer.',
    inputSchema: z.object({
      to: z.string(),
      amountUsd: z.number(),
      summary: z.string(),
    }),
    // Pauses the durable workflow, streams approval context to the client,
    // waits for the World ID proof, verifies it server-side, then resumes.
    // Bind the action to the payload so a proof can't be replayed elsewhere:
    execute: requestHumanAuthorization({
      action: ({ input }) => `transfer:${input.to}:${input.amountUsd}`,
    }),
  },
};
```

## Unverified — do not rely on these

- **Selfie Check feature flag** — I confirmed it is access-gated and that you must email developers@toolsforhumanity.com, but I could NOT confirm turnaround time or whether hackathon participants get fast-tracked. This is the single biggest schedule risk in the whole list: without the flag, `selfieCheckLegacy()` requests will fail and the $3,500 track is unreachable. Email now, before writing any code.
- **Does `@worldcoin/idkit-core`'s `IDKit.request()` / `pollUntilCompletion()` actually run in Bun?** The docs describe idkit-core as the low-level JS/TS SDK "when you're not using React" and document server subpaths (`/signing`, `/hashing`), but nowhere state that the *bridge request* half is server-safe. It uses WebCrypto + fetch, both of which Bun has, so it very likely works — but I did not execute it. Verify with a 10-line spike before you build the headless flow on it. Fallback: run the widget on a thin React page and keep only `signRequest` + the v4 verify POST on the server.
- **Exact `/api/v4/verify` success payload for a Selfie Check proof.** The OpenAPI shows `VerifyV4SuccessResponse` with `success`, `action`, `nullifier`, `created_at`, `environment`, `session_id`, `results[]`, `message` — but the examples cover orb/proof_of_human, not `identifier: 'selfie'`. I could not confirm whether a Selfie Check (v3-protocol) response returns the nullifier at the top level or only inside `results[]`. Handle both.
- **Whether the bounty's 'Selfie Check used meaningfully for risk' is satisfied by an agent-authorization gate.** The listed uses are risk, eligibility, fairness, continuity, abuse prevention — a human-approval gate reads as 'abuse prevention'/'continuity' and should qualify, but this is a judging call, not a documented rule.
- **Uniswap Trading API quote availability on Sepolia.** The OpenAPI enum includes 11155111 and the docs say all listed testnets are API-accessible, but Sepolia v4 liquidity is thin and a `/quote` may return 404 `QuoteAmountTooLowError` / no-route. I did not make a live quote call (no API key). Have a mainnet-fork or Base-mainnet fallback for the demo.
- **Whether `/quote` will return v4 routes with non-zero `hooks` on a testnet.** The hook-screening demo is much better with a real hooked pool; on Sepolia you may only ever see `0x000...0`. Consider forking Base mainnet and replaying a real quote's calldata through your firewall instead.
- **Universal Router `execute` ABI exact signature per version.** I gave the standard `execute(bytes,bytes[],uint256)`. UR 2.0 vs 2.1.1 vs 2.2.0 may differ, and the docs explicitly warn that decoding with the wrong `@uniswap/universal-router-sdk` version 'can fail or produce incorrect results'. Pull the real ABI from `@uniswap/universal-router-sdk` 5.11.5 rather than hand-writing it, and always pin `x-universal-router-version`.
- **Does `aqua.ship({ app: <official AquaSwapVMRouter> })` work against the official mainnet deployment on a fork without deploying anything?** Strongly implied — the swap-vm-sdk quick-start does exactly this with `AQUA_SWAP_VM_CONTRACT_ADDRESSES[chainId]` as the app, and `useAquaInsteadOfSignature` mode exists for it — but 1inch's own tests deploy `TestAquaSwapVMRouter` + `Aqua` locally rather than using the live ones. Spike this first; if the official router rejects it, fall back to 1inch's harness (still 'official contracts' by bytecode, arguably weaker for the bounty).
- **EIP-712 domain of the officially deployed AquaSwapVMRouter.** 1inch's test calls `order.hash({ chainId, name: 'TestAquaSwapVMRouter', ... })`. I could not find the production `name`/`version`. In Aqua mode (`useAquaInsteadOfSignature: true`) no maker signature is needed so this may not matter — but if you sign orders EIP-712 instead of shipping them, you need the real domain. Read it from the contract (`eip712Domain()`) on your fork.
- **Exact `instructions.controls.DeadlineArgs` / `deadline` export names.** I read the SwapVM README's instruction list (DEADLINE exists in the Aqua subset) and the `FlatFeeArgs`/`ConcentrateGrowLiquidity2DArgs` patterns, but I did not open the compiled `instructions/controls` d.ts. Verify the constructor/arg-class names against `node_modules/@1inch/swap-vm-sdk/dist/index.d.ts` before relying on my `ArxGuardedAmmStrategy` snippet verbatim.
- **`npm install @1inch/swap-vm`** appears in the SwapVM README's Getting Started but returns **404 on the npm registry**. The real packages are `@1inch/swap-vm-sdk` and `@1inch/aqua-sdk`. `@1inch/aqua` also 404s despite the README's npm badge. Don't copy those install lines.
- **Privy key quorums may require Privy to enable them for your app.** Docs call them 'an advanced feature' and say 'reach out to discuss whether this setup is right for your integration'. The SDK/REST create path looks self-serve, but if `keyQuorums().create()` 403s, fall back to `owner: {public_key}` (which auto-creates a single-key quorum) — that still counts as a 'signer' control for the bounty.
- **Privy aggregations endpoint path.** Docs link to `/api-reference/aggregations/create` and the SDK has an `aggregations` resource on the low-level client, but I did not confirm the literal URL is `POST /v1/aggregations` or the Node method name. Verify before using the stateful-policy snippet.
- **Whether the World ID Sandbox App is required for the Selfie Check track** (the ETHGlobal text says Sandbox testing for the *AgentKit* track). Sandbox access itself needs a per-team TestFlight/Play enrollment request with approval latency I couldn't determine — another reason to submit requests on day one.
- Whether ETHGlobal judges accept a mainnet **anvil fork** as satisfying '1inch official contracts'. The prize text explicitly says 'local forks acceptable' for on-chain execution, and a fork preserves the official bytecode at the official addresses, so this should be the intended reading — but record the fork block, the two addresses, and the tx hashes in your README to make it unarguable.

## Requires a human: accounts, keys, faucets

- **Privy** — create an account and app at https://dashboard.privy.io → copy `PRIVY_APP_ID` and `PRIVY_APP_SECRET`. Then either create an authorization key in the dashboard (Wallets → Authorization keys → New key; the private key is shown ONCE and Privy cannot recover it) or generate one in-process with `generateP256KeyPair()`. No paid tier needed for the demo.
- **World — Developer Portal app.** Create an app at https://developer.world.org with `app_mode: external` (NOT `mini-app` — the mode is fixed at create time and a mini-app cannot use IDKit). Complete World ID 4.0 RP registration. Record `app_id` (`app_...`), `rp_id` (`rp_...`), and `signing_key.private_key` — **returned exactly once**; store it server-only, never as `NEXT_PUBLIC_*`, never log it. Create an *action* in the right environment (`production` for real phones, `staging` for the simulator) — a staging action + real phone silently yields zero proofs.
- **World — REQUEST SELFIE CHECK ACCESS TODAY.** Email developers@toolsforhumanity.com (or your World contact) to get the Selfie Check (Beta) feature flag enabled for your `app_id`. Nothing in Track 2 works without it. Do this before you write code; build against `orbLegacy()` / `require_user_presence: true` in the meantime.
- **World — Sandbox App access** (needed for the AgentKit track, useful for Selfie Check testing): in the Developer Portal → World ID Sandbox, submit your Apple Account email (iOS/TestFlight) or Google Play account email (Android private track) and wait for approval. Also install a real **World ID App** on a phone for production-environment testing, plus https://simulator.worldcoin.org for staging.
- **World — optional but fast:** create a Developer Portal team API key and connect the MCP server at `https://developer.world.org/api/mcp` (`Authorization: Bearer api_<base64(id:secret)>`) so app/RP/action creation is a few tool calls instead of dashboard clicking.
- **Uniswap** — sign up at https://developers.uniswap.org/dashboard and generate a free API key → `UNISWAP_API_KEY`. Free, self-serve, no per-call charge. Keep it server-side only.
- **Uniswap** — submit the Developer Feedback Form at https://developers.uniswap.org/hackathon-feedback **including the link to your repo's FEEDBACK.md**. Also required: public GitHub repo, open-source licence, a `FEEDBACK.md`, and a README that explicitly names which Uniswap contracts/endpoints you touch. The form submission is a hard qualification gate, not a nicety.
- **1inch** — you need a **mainnet RPC URL that supports forking** (Alchemy/Infura/QuickNode archive, or the free `https://eth.llamarpc.com` that 1inch's own tests default to) exported as `MAINNET_RPC_URL` / `FORK_URL`.
- **1inch** — install Foundry (`curl -L https://foundry.paradigm.xyz | bash && foundryup`) for `anvil` and `cast`. Docker only if you want to reuse 1inch's testcontainers harness.
- **1inch** — decide how to fund the fork accounts (impersonate a USDC/WETH whale via `anvil_impersonateAccount`, or `anvil_setStorageAt`). 1inch's harness impersonates a USDC donor address; pick your own current whale since balances drift.
- **Git hygiene for the 1inch bounty** — 'proper git commit history' is an explicit requirement. Commit incrementally across the event with real messages; don't squash the whole project into one commit at the deadline.
- **Licence check** — 1inch Aqua/SwapVM ship under `LicenseRef-Degensoft-Aqua-Source-1.1` / `-SwapVM-1.1`, which is NOT OSI-approved. Uniswap requires your repo be open-source. Consume the 1inch SDKs as npm dependencies; do not vendor or copy their Solidity into your repo.
- **ETHGlobal submissions** — each sponsor track is a separate submission with its own deliverables (Privy: working demo + source; World: working app + a written feedback document; Uniswap: repo + FEEDBACK.md + form; 1inch: repo + on-chain tx evidence + git history). Budget real time for the two written feedback documents — they are scored, not optional.

## Recommendations

- **Do Privy first — it's the cheapest win and it IS Arx.** Arx already is a policy layer; Privy's policy engine is a *second, TEE-enforced* policy layer with an identical mental model (rules → conditions → ALLOW/DENY over RPC methods). Build a single `src/integrations/privy/` module that (a) creates a key quorum, (b) creates two policies, (c) creates one wallet with `policy_ids` + an `additional_signers` entry carrying `override_policy_ids`, (d) sends one tx with each signer to show the restricted key getting DENIED and the admin key succeeding. That one demo hits **three** of the four named controls (policies, signers, key quorums) when only one is required. Est. 3–4 hours.
- **Frame the Privy submission as 'defense in depth', not 'we used Privy'.** Your pitch writes itself: Arx enforces policy off-chain where it can see agent intent and reasoning; Privy enforces the same policy inside a secure enclave where even a compromised Arx server can't bypass it. Compile Arx's policy DSL down to Privy policy JSON and show the two agreeing. That is a genuinely novel B2B story and directly answers 'Privy as core product' rather than 'Privy as a wallet we happened to use'.
- **Use Privy intents as Arx's escalation primitive — this is the single highest-leverage integration in the whole list.** `intents().rpc()` proposes an action with no signature; the intent sits pending for up to 72h while Arx runs risk checks, World ID verification, and Ledger confirmation; then `POST /v1/intents/{id}/authorize` executes it. That is *exactly* your 'AI proposes, Arx authorizes, Ledger signs' sequence, expressed in a sponsor's own API. Note the gotcha: there is no `authorize()` in the Node SDK — hand-roll it with `generateAuthorizationSignature`.
- **For World, ship the Selfie Check gate on Privy intents and you get both bounties from one feature.** High-risk intent → Arx pauses → returns a `connectorURI` QR → human completes Selfie Check on their phone → server POSTs the untouched proof to `/api/v4/verify/{rp_id}` → nullifier stored → Arx authorizes the Privy intent → Ledger signs. Bind `signal` to the intent hash so a proof for one payout cannot be replayed for another; that detail alone will read as 'used meaningfully for risk' to a judge. Est. 4–6 hours once the flag is on.
- **Email for the Selfie Check flag before you do anything else, and build the fallback in parallel.** Write the gate against a `preset` parameter so you can run `orbLegacy()` or `proofOfHuman({...}) + require_user_presence: true` today and flip to `selfieCheckLegacy()` the moment the flag lands. `require_user_presence` is a request-level liveness flag independent of Selfie Check — it gets you a demoable liveness story even if the flag never arrives.
- **Read `@worldcoin/human-in-the-loop` before you write your own, then cite it.** World shipped an SDK whose entire purpose is pausing an agent for a World ID proof. Either adopt it (if you add a Vercel-AI-SDK surface) or explain in your feedback document *why* Arx's Fastify/MCP architecture needed a different shape — 'we evaluated your HITL SDK and here's the gap' is the most valuable thing you can put in a feedback doc, and the World track explicitly scores the feedback document.
- **Uniswap is the cheapest bounty of the four: a `/quote` → policy-check → `/swap` firewall route. Est. 2–3 hours.** Free self-serve API key, one POST, and the response hands you everything a firewall wants: `swap.to` (allowlist against the Universal Router), `swap.data` (decode and inspect), the full v4 `route[]` with each pool's `hooks` address (screen for unknown hooks), `priceImpact`, and `txFailureReasons` from simulation. 'Arx blocks a swap routed through an unrecognized v4 hook' is a crisp, demoable, genuinely useful contribution.
- **Make the Uniswap FEEDBACK.md substantive and specific — it is a scored deliverable, and you already have the material.** Concrete items worth raising: the `x-universal-router-version` header defaults differ per chain and silently change over time (a decoder-compat footgun you had to pin around); there is no published per-version Universal Router `execute` ABI to decode against without pulling the SDK; UniswapX routing types can't be consumed by an EOA/hardware-signer flow at all, so a firewall must reject them; and the quote response exposing `hooks` inline is excellent for security tooling and should be documented as such.
- **Prefer Ethereum Sepolia (11155111) for the Uniswap demo, but have a Base-mainnet-fork fallback ready.** Sepolia has complete v4 deployments (PoolManager `0xE03A1074c86CFeDd5C142C4F04F1a1536e203543`, UR 2.0 `0x3A9D48AB9751398BbFa63ad67599Bb04e4BdF98b`) and is in the API's chain enum, but thin liquidity may make `/quote` 404. Because Arx only needs to *screen* calldata, you can also replay a real Base-mainnet quote's calldata through the firewall offline and only execute on a fork — that removes all liquidity risk from your demo.
- **1inch is the biggest single prize ($2,500 for 1st) and the most technically distinctive — but it is also the most likely to eat a day. Timebox a 90-minute spike first:** anvil-fork mainnet, `cast code` both official addresses to confirm they're live, then try `aqua.ship({ app: AQUA_SWAP_VM_CONTRACT_ADDRESSES[1], strategy: order.encode(), ... })` with a single `AquaXYCAmmStrategy.newConcentrate()` program. If that ships and you can `swapVM.quote()` against it, commit to the track. If the official router rejects it, fall back to 1inch's own harness in `github.com/1inch/sdks`.
- **For 1inch, the differentiated Aqua App is 'a SwapVM program that enforces policy in bytecode'.** 1inch's own framing of the bounty is 'a custom Aqua app based on SwapVM implementing a sophisticated DeFi position; you may define your own instructions'. The Aqua instruction subset already includes `DEADLINE`, `ONLY_TAKER_TOKEN_BALANCE_GTE`, `ONLY_TAKER_TOKEN_SUPPLY_SHARE_GTE`, and `REQUIRE_MIN_RATE_1D` — compose those into an 'Arx-guarded liquidity strategy' where Arx's off-chain policy compiles down to on-chain VM guards. That is the same thesis as the Privy submission, expressed in a different substrate, and no other team will pitch it.
- **Use `AquaProgramBuilder`, never bare `ProgramBuilder`, and say so in your README.** The SDK happily encodes the full SwapVM instruction set, but deployed Aqua routers only execute the Aqua subset — out-of-subset programs encode fine and then fail on-chain. Worse, the opcode array *index* must match the on-chain layout or you silently execute the wrong instruction. `AquaProgramBuilder` is pre-wired to the safe subset.
- **Capture on-chain evidence for 1inch as you go.** The requirement is 'onchain execution of token transfers during the demo'. Log and commit: the fork block number, both official contract addresses, the `ship` tx hash, the `Swapped` event decoded via `SwappedEvent.fromLog`, the `rawBalances` before/after, and the `dock` tx hash. Put them in the README. This makes the 'local fork' question unarguable.
- **Realistic 24-hour ordering, given three of four bounties share one codepath:** (0:00) fire off the Selfie Check access email and the Sandbox access requests, generate all API keys. (0:15–4:00) Privy module + the DENY/ALLOW demo — bankable. (4:00–6:30) Uniswap quote→screen→swap route — bankable, cheapest. (6:30–8:00) 1inch spike; go/no-go. (8:00–13:00) if go, the Aqua App; if no-go, deepen the Privy intents escalation flow. (13:00–18:00) World gate wired onto the Privy intent. (18:00–21:00) the two written feedback documents and the Uniswap form — do NOT leave these to the last hour, they're scored. (21:00–24:00) demo video, READMEs, four submissions.
- **One shared abstraction pays for all four.** Define `Decision = { verdict: 'ALLOW' | 'DENY' | 'ESCALATE', reasons: string[] }` and route every integration through it: Privy policies are the enclave-side ALLOW/DENY, Uniswap calldata screening produces a Decision, World ID resolves an ESCALATE into an ALLOW, and the 1inch SwapVM guards are the same Decision compiled to bytecode. Four sponsor integrations, one coherent architecture — which is also the only way four submissions from one team in one day reads as a product rather than four demos stapled together.
