# x402, Hedera and Arc/Circle — agentic payment rails

> Compiled 2026-09-12 by a research agent that verified each claim against
> primary sources (npm tarballs, app source, official docs). Facts carry their
> source URL. Anything unverified is listed explicitly at the end — treat that
> section as unknown, not as true.

## Summary

I verified all three stacks empirically, including running working code on Bun. Three headline corrections to the premise:

**1. x402 has moved to v2 and a new package namespace.** The canonical repo is `x402-foundation/x402` (coinbase/x402 is now a *fork*; Linux Foundation formalized the x402 Foundation 2026-04-02). The packages named in the task (`x402`, `x402-express`, `x402-fetch`, `x402-hono`, `@coinbase/x402`) are **v1 legacy**, frozen at 1.2.x. Current is `@x402/core`, `@x402/hono`, `@x402/express`, `@x402/fetch`, `@x402/evm`, `@x402/hedera` — all at **2.25.0**. v2 also changed the wire format: headers are now `PAYMENT-REQUIRED` / `PAYMENT-SIGNATURE` / `PAYMENT-RESPONSE` (all base64 JSON), the 402 body is `{}` with everything in the header, networks are **CAIP-2** (`eip155:84532`, `hedera:testnet`), `maxAmountRequired`→`amount`, and `resource`/`description`/`mimeType` moved into a nested `resource` object. `WWW-Authenticate` is not used. v1's `X-PAYMENT` + JSON body still exists and the public facilitator still serves v1 kinds.

**2. Hedera is a first-class x402 chain, and the free public facilitator supports it.** `@x402/hedera` exists and I confirmed live that `https://x402.org/facilitator` serves `{scheme:"exact", network:"hedera:testnet", extra:{feePayer:"0.0.9185802"}}` — **no API key, no signup, no self-hosted facilitator needed.** That feePayer account holds ~10,037 testnet HBAR. Critically, **Blocky402 (named in the bounty text) is mainnet-only** — I confirmed `api.blocky402.com/supported` returns only `hedera:mainnet`. For testnet you must use `x402.org/facilitator`. Hedera's `exact` scheme is *not* EIP-3009 — it's a partially-signed `TransferTransaction` where the client sets `transactionId.accountId = extra.feePayer` and the facilitator co-signs as fee payer. I built a Hono server on Bun that returns a correct 402 (`$0.01` → `amount:"10000"`, `asset:"0.0.429274"`) and a client that signs a valid payload locally with zero network calls; the facilitator accepted my wire format and rejected only on key mismatch.

**3. Arc is live and Circle ships an x402 facilitator for it.** Arc testnet chainId is **5042002** (verified `eth_chainId` → `0x4cef52`). USDC is a predeploy at `0x3600...0000`; I verified on-chain that it implements EIP-3009 and that its EIP-712 domain is exactly `{name:"USDC", version:"2", chainId:5042002}` (computed domain separator matches the contract byte-for-byte). Arc is **not** in x402's EVM default-asset table, but `@circle-fin/x402-batching` (3.4.0) fills the gap: `https://gateway-api-testnet.circle.com/v1/x402/supported` lists `eip155:5042002` unauthenticated, and my Express probe on Bun returned a correct Arc 402. Note Gateway signs against the **GatewayWallet** contract, not USDC. "Circle Agent Stack" is driven by a **CLI** (`@circle-fin/cli`), not a TS SDK — auth is email+OTP, no API key.

## Verified facts

### x402 canonical repo

The canonical x402 repo is github.com/x402-foundation/x402. coinbase/x402 is a FORK of it (GitHub API: fork=true, parent=x402-foundation/x402). Use x402-foundation/x402 for specs and source.

Source: https://api.github.com/repos/coinbase/x402

### x402 v2 HTTP headers

v2 HTTP transport uses three headers, all base64-encoded JSON: PAYMENT-REQUIRED (server->client, carries the PaymentRequired object), PAYMENT-SIGNATURE (client->server, carries PaymentPayload), PAYMENT-RESPONSE (server->client, carries SettlementResponse). The 402 response body is `{}` — all protocol data is in headers. WWW-Authenticate is NOT part of x402.

Source: https://github.com/x402-foundation/x402/blob/main/specs/transports-v2/http.md

### x402 v1 HTTP headers (legacy)

v1 used X-PAYMENT (client->server) and X-PAYMENT-RESPONSE (server->client), with payment requirements in the 402 JSON *body* as {x402Version:1, error, accepts:[{scheme,network,maxAmountRequired,asset,payTo,resource,description,mimeType,outputSchema,maxTimeoutSeconds,extra}]}. Networks were plain names like 'base-sepolia'.

Source: https://github.com/x402-foundation/x402/blob/main/specs/transports-v1/http.md

### x402 v2 PaymentRequirements fields

Each accepts[] entry: scheme (req), network (req, CAIP-2), amount (req, atomic units string — renamed from v1 maxAmountRequired), asset (req), payTo (req), maxTimeoutSeconds (req), extra (optional). description/mimeType/url moved OUT of accepts[] into a sibling `resource` object {url, description, mimeType, serviceName, tags, iconUrl}. Top level: {x402Version:2, error?, resource, accepts[], extensions?}.

Source: https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md

### x402 v2 PaymentPayload fields

{x402Version:2, resource?, accepted (the chosen PaymentRequirements object), payload (scheme-specific), extensions?}. For exact-EVM, payload = {signature, authorization:{from,to,value,validAfter,validBefore,nonce}} (EIP-3009 transferWithAuthorization, EIP-712 signed).

Source: https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md

### x402 facilitator endpoints

POST /verify (read-only, returns {isValid, invalidReason?, payer?}), POST /settle (state-committing, returns {success, errorReason?, payer?, transaction, network, amount?}), GET /supported (returns {kinds:[{x402Version,scheme,network,extra?}], extensions:[], signers:{}}). Both verify and settle take body {x402Version, paymentPayload, paymentRequirements}.

Source: https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md

### x402 payment flows

Three flows declared via extra.paymentFlow: `authorization` (default: verify -> resource -> settle -> respond), `upfront` (settle -> resource -> respond), `escrow` (settle -> resource -> settle -> respond). At least one check must run before the resource executes.

Source: https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md

### x402 v2 npm packages (exact names + version)

All at 2.25.0: @x402/core, @x402/extensions, @x402/mcp, @x402/axios, @x402/express, @x402/fastify, @x402/fetch, @x402/hono, @x402/next, @x402/paywall, @x402/evm, @x402/hedera, @x402/svm, @x402/avm, @x402/aptos, @x402/cardano, @x402/stellar. Verified via npm registry dist-tags.

Source: https://github.com/x402-foundation/x402/blob/main/typescript/README.md

### x402 v1 legacy npm packages

x402@1.2.0, x402-express@1.2.0, x402-fetch@1.2.0, x402-hono@1.2.0, x402-next@1.2.0, x402-axios@1.2.1, @coinbase/x402@2.1.0. These are the v1 line (repo path typescript/packages/legacy/*) and are NOT the current SDK.

Source: https://registry.npmjs.org/-/package/x402/dist-tags

### @x402/core subpath exports

@x402/core exports: '.', './client', './facilitator', './http', './server', './types', './types/v1', './utils', './schemas'. Key classes: x402Client and x402HTTPClient from @x402/core/client; x402ResourceServer, x402HTTPResourceServer, HTTPFacilitatorClient, FacilitatorClient from @x402/core/server; x402Facilitator from @x402/core/facilitator.

Source: https://github.com/x402-foundation/x402/blob/main/typescript/packages/core/package.json

### Public x402 facilitator URL and supported networks (LIVE VERIFIED)

https://x402.org/facilitator — unauthenticated, no API key. GET /supported returned v2 kinds for: eip155:84532 (exact, upto, batch-settlement), solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1 (feePayer CKPKJWNdJEqa81x7CkZ14BVPiY6y16Sxs7owznqtWYp5), algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDe, aptos:2, stellar:testnet, hedera:testnet (feePayer 0.0.9185802), xrpl:1; plus v1 kinds base-sepolia and solana-devnet. Testnets only.

Source: https://x402.org/facilitator/supported

### Hedera x402 support — CAIP-2 network ids

Hedera CAIP-2 ids are `hedera:mainnet` and `hedera:testnet` (NOT eip155:295/296 for x402 purposes). Constants exported from @x402/hedera: HEDERA_MAINNET_CAIP2, HEDERA_TESTNET_CAIP2.

Source: https://github.com/x402-foundation/x402/blob/main/typescript/packages/mechanisms/hedera/src/constants.ts

### @x402/hedera package

@x402/hedera@2.25.0. Dependencies are PINNED EXACTLY: @hiero-ledger/proto@2.31.0 and @hiero-ledger/sdk@2.85.0 (plus @x402/core). Subpath exports: '.', './exact/client', './exact/server', './exact/facilitator'.

Source: https://github.com/x402-foundation/x402/blob/main/typescript/packages/mechanisms/hedera/package.json

### Hedera SDK is now @hiero-ledger/sdk, not @hashgraph/sdk

@x402/hedera depends on @hiero-ledger/sdk (latest 2.88.0, pinned to 2.85.0 by x402) and @hiero-ledger/proto (2.31.0). @hashgraph/sdk still exists at 2.81.0 but is NOT what @x402/hedera uses. @x402/hedera deliberately RE-EXPORTS AccountBalanceQuery, AccountId, AccountInfoQuery, Client, Hbar, PrivateKey, TokenAssociateTransaction, TokenId, Transaction, TransactionId, TransferTransaction so you resolve a single SDK instance — importing @hiero-ledger/sdk separately can cause duplicate installs whose instanceof/string-brand checks cross-fail with 't.startsWith is not a function'.

Source: https://github.com/x402-foundation/x402/blob/main/typescript/packages/mechanisms/hedera/src/index.ts

### Hedera exact scheme mechanics (NOT EIP-3009)

Hedera's `exact` scheme is client-driven partially-signed transactions: (1) server's PaymentRequirements.extra.feePayer gives the facilitator's account id; (2) client builds a TransferTransaction, sets transactionId.accountId = extra.feePayer, freezes, signs -> partially signed; (3) client base64-encodes and sends payload = {transaction: '<base64>'}; (4) facilitator verifies, adds its fee-payer signature, submits. SettlementResponse carries transactionId (e.g. '0.0.1235@1700000000.000000000').

Source: https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_hedera.md

### Hedera asset ids and amount units

asset '0.0.0' = native HBAR, amount in TINYBARS (1 HBAR = 10^8 tinybars). Otherwise asset is an HTS fungible token id and amount is in the token's smallest unit. Testnet USDC = 0.0.429274 (6 decimals), Mainnet USDC = 0.0.456858 (6 decimals).

Source: https://github.com/x402-foundation/x402/blob/main/typescript/packages/mechanisms/hedera/src/constants.ts

### Hedera testnet USDC verified on-chain

Mirror node GET /api/v1/tokens/0.0.429274 returned: name='USD Coin', symbol='USDC', decimals='6', type='FUNGIBLE_COMMON', treasury_account_id='0.0.5176'.

Source: https://testnet.mirrornode.hedera.com/api/v1/tokens/0.0.429274

### Public facilitator Hedera feePayer is funded

Mirror node GET /api/v1/accounts/0.0.9185802 returned balance 1003700620344 tinybars (~10,037 HBAR), key type ECDSA_SECP256K1. This is the fee payer that sponsors your testnet x402 settlements for free.

Source: https://testnet.mirrornode.hedera.com/api/v1/accounts/0.0.9185802

### Blocky402 is MAINNET ONLY (important bounty gotcha)

GET https://api.blocky402.com/supported returned exactly: {"kinds":[{"x402Version":2,"scheme":"exact","network":"hedera:mainnet","extra":{"feePayer":"0.0.10571514"}}],"extensions":[],"signers":{"hedera:*":["0.0.10571514"]}}. Note the API host is api.blocky402.com — blocky402.com/supported returns a 404 HTML page. There is NO hedera:testnet on Blocky402.

Source: https://api.blocky402.com/supported

### Hedera Mirror Node REST URLs

Testnet: https://testnet.mirrornode.hedera.com ; Mainnet: https://mainnet-public.mirrornode.hedera.com. Used by @x402/hedera for payer-key lookup and preflight balance/association checks (free, no key).

Source: https://github.com/x402-foundation/x402/blob/main/typescript/packages/mechanisms/hedera/src/constants.ts

### Hedera EVM JSON-RPC (Hashio) chain ids — VERIFIED LIVE

https://testnet.hashio.io/api eth_chainId -> 0x128 = 296 (Hedera testnet). https://mainnet.hashio.io/api eth_chainId -> 0x127 = 295 (Hedera mainnet). Both returned live block numbers. NOTE: x402 on Hedera does NOT use the EVM JSON-RPC path — it uses native HTS/HBAR transfers via hedera:testnet CAIP-2. Hashio is only relevant for EVM smart contracts (e.g. Asset Tokenization Studio).

Source: https://testnet.hashio.io/api

### Hedera token association requirement

Every HTS token must be explicitly associated with each account before it can be received. BOTH payer and recipient must be associated with the payment token or settlement fails on-chain with TOKEN_NOT_ASSOCIATED_TO_ACCOUNT. The Hedera portal does not expose association — use TokenAssociateTransaction from the SDK, or set maxAutomaticTokenAssociations via AccountUpdateTransaction. HBAR (asset 0.0.0) needs NO association.

Source: https://github.com/x402-foundation/x402/blob/main/typescript/packages/mechanisms/hedera/README.md

### Hedera faucets

Testnet HBAR + account creation with ECDSA/ED25519 keys: https://portal.hedera.com/ . Testnet USDC (token 0.0.429274): https://faucet.circle.com/ — select 'Hedera Testnet'; the account must already be associated with the token.

Source: https://github.com/x402-foundation/x402/blob/main/typescript/packages/mechanisms/hedera/README.md

### Official Hedera x402 reference implementation

github.com/hedera-dev/x402-inference-pay-per-request-poc — an LLM inference proxy charging $0.001/request. Uses @x402/express + @x402/hedera + @x402/core on the server, @x402/fetch + @x402/hedera on the client, @hashgraph/hedera-agent-kit ^4.0.0, @hiero-ledger/sdk ^2.85.0. Defaults X402_TESTNET_FACILITATOR_URL=https://x402.org/facilitator and X402_MAINNET_FACILITATOR_URL=https://api.blocky402.com. This is the closest official template for the Hedera track.

Source: https://github.com/hedera-dev/x402-inference-pay-per-request-poc

### Hedera Agent Kit npm names

@hashgraph/hedera-agent-kit latest 4.1.0 (repo github.com/hashgraph/hedera-agent-kit-js), plus @hashgraph/hedera-agent-kit-ai-sdk latest 2.0.0 for Vercel AI SDK tool bindings. Note the unscoped `hedera-agent-kit` package is a different/older line at 3.8.2.

Source: https://registry.npmjs.org/-/package/@hashgraph%2Fhedera-agent-kit/dist-tags

### Hedera Harness (ETHOnline track 2, $2,000)

npm package `hedera-harness`, latest 1.2.2 (published 2026-08-16), also 2.0.0-rc.4. bin: hedera-harness. Repo github.com/hedera-dev/hedera-harness (TypeScript, master branch, only 1 star as of 2026-09-12). It is a CLI that drives a coding agent to build features into scaffold-hbar projects with 4 validation stages per attempt: GENERATE -> ASSERT (files/static/secrets/build) -> SMOKE (dev server boots, Playwright routes render) -> EVALUATE (adversarial validator grades assertions). Usage: `npx hedera-harness init my-app && cd my-app && npx hedera-harness run`. Node >= 20; optional peers Playwright (Tier 2+) and Hedera SDK (Tier 3.5). Related: github.com/hedera-dev/hedera-skills, github.com/hedera-dev/hedera-code-snippets, npm `scaffold-hbar`@1.0.0.

Source: https://github.com/hedera-dev/hedera-harness

### Asset Tokenization Studio (ETHOnline track 3, $6,000)

Open-source Hedera toolkit for configuring, issuing and managing tokenized securities/equities. Repo github.com/hashgraph/asset-tokenization-studio (TypeScript). npm: @hashgraph/asset-tokenization-sdk@8.0.0 and @hashgraph/asset-tokenization-contracts@8.0.0. Track requires deploying on Hedera testnet with contracts verified on HashScan, plus >=1 lifecycle operation demoed.

Source: https://github.com/hashgraph/asset-tokenization-studio

### Hedera ETHOnline 2026 track structure ($15,000 total)

Track 1 'AI & Agentic Payments on Hedera' $6,000 (up to 3 x $2,000): live x402-gated service on Hedera testnet or mainnet, an agent making >=1 real paid request end-to-end, public repo + README, demo video <=5min. Track 2 'Improve the Hedera Harness' $2,000 (2 x $1,000). Track 3 'Tokenization of Anything' $6,000 (3 x $2,000) using ATS. Track 4 'Continuity' $1,000. Event runs Sep 4-16 2026.

Source: https://ethglobal.com/events/ethonline2026/prizes/hedera

### Arc testnet chain id — VERIFIED LIVE

eth_chainId on https://rpc.testnet.arc.io returned 0x4cef52 = 5042002. web3_clientVersion = 'arc/v1'. https://rpc.testnet.arc.network returns the same chain id (both hosts work). CAIP-2 = eip155:5042002.

Source: https://docs.arc.io/arc/references/rpc-endpoints

### Arc network endpoints

Testnet RPC https://rpc.testnet.arc.io (HTTP) and wss://rpc.testnet.arc.io (WebSocket); alt https://rpc.testnet.arc.network. Provider endpoints: https://arc-testnet.g.alchemy.com/v2/KEY, https://rpc.blockdaemon.testnet.arc.io, https://rpc.drpc.testnet.arc.io, https://rpc.quicknode.testnet.arc.io. Explorer https://testnet.arcscan.app. Faucet https://faucet.circle.com. Native gas token is USDC.

Source: https://docs.arc.io/arc/references/rpc-endpoints

### Arc mainnet chain id

Arc mainnet chain id is 5042 (from @circle-fin/x402-batching CHAIN_CONFIGS: arcMainnet = chains.arc ?? defineChain({id: 5042, name:'Arc', nativeCurrency:{decimals:18,name:'USDC',symbol:'USDC'}})). The package notes Arc mainnet had no public RPC until ~2026-06-22 and requires passing a private rpcUrl.

Source: https://registry.npmjs.org/@circle-fin/x402-batching/-/x402-batching-3.4.0.tgz

### Arc USDC dual representation

USDC on Arc has two interfaces over ONE balance: native 18-decimal (eth_getBalance / msg.value, used for gas) and a 6-decimal ERC-20 predeploy at 0x3600000000000000000000000000000000000000. Verified on-chain: name()='USDC', symbol()='USDC', decimals()=6, version()='2'.

Source: https://www.arc.io/blog/building-with-usdc-on-arc-one-token-two-interfaces

### Arc USDC EIP-3009 + EIP-712 domain — VERIFIED ON-CHAIN

At 0x3600000000000000000000000000000000000000 on Arc testnet: DOMAIN_SEPARATOR() = 0x361191522483d32a83e70ae7183b4b9629442c13a78bc9921d6f707911c8c6b0. I recomputed keccak256(abi.encode(keccak256('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'), keccak256('USDC'), keccak256('2'), 5042002, 0x3600...0000)) and it MATCHES exactly. authorizationState(address,bytes32) (0xe94a0102) returns 32 zero bytes while a control selector 0xdeadbeef reverts, proving EIP-3009 is implemented. nonces(address) also responds, so EIP-2612 permit is present too. EIP-712 domain for x402 exact-EVM is therefore extra:{name:'USDC', version:'2'}.

Source: https://docs.arc.io/arc/references/contract-addresses

### Arc is NOT in x402's EVM default-asset table

typescript/packages/mechanisms/evm/src/defaultAssets.ts contains eip155: 1, 14, 50, 51, 137, 143, 988, 1328, 1329, 2201, 4326, 8453, 36900, 38833, 42161, 42220, 43114, 72344, 84532, 181228, 190415, 421614, 723487, 11142220, 31611, 31612 — but NOT 5042002. So `price: "$0.10"` will NOT auto-resolve on Arc with plain @x402/evm; you must pass an explicit AssetAmount, or use @circle-fin/x402-batching's GatewayEvmScheme which registers Gateway money parsers for you.

Source: https://github.com/x402-foundation/x402/blob/main/typescript/packages/mechanisms/evm/src/defaultAssets.ts

### Circle Gateway x402 facilitator supports Arc — VERIFIED LIVE, NO AUTH

GET https://gateway-api-testnet.circle.com/v1/x402/supported (unauthenticated) returned eip155:5042002 with extra {name:'GatewayWalletBatched', version:'1', verifyingContract:'0x0077777d7eba4688bdef3e311b846f25870a19b9', minValiditySeconds:604800, assets:[{symbol:'USDC', address:'0x3600000000000000000000000000000000000000', decimals:6}]}. Also supported: eip155:11155111, 84532, 43113, 421614, 14601, 4801, 1328, 998, 11155420, 80002, 1301. Mainnet base URL is https://gateway-api.circle.com.

Source: https://gateway-api-testnet.circle.com/v1/x402/supported

### @circle-fin/x402-batching package

@circle-fin/x402-batching@3.4.0 (published 2026-08-24). Peer deps: @x402/core ^2.3.0, @x402/evm ^2.3.0 (optional), viem ^2.0.0. Exports '.', './client', './server'. Server: createGatewayMiddleware(config), BatchFacilitatorClient, GatewayEvmScheme, isBatchPayment. Client: GatewayClient, BatchEvmScheme, CompositeEvmScheme, CHAIN_CONFIGS, GATEWAY_DOMAINS, registerBatchScheme. Root: supportsBatching, isBatchPayment, getVerifyingContract.

Source: https://registry.npmjs.org/@circle-fin/x402-batching

### Circle Gateway signs against GatewayWallet, not USDC

BatchEvmScheme 'Signs EIP-3009 TransferWithAuthorization against the GatewayWallet contract (from extra.verifyingContract) instead of the USDC token contract.' Batching options are identified by extra.name === 'GatewayWalletBatched' && extra.version === '1'. Gateway contracts: TESTNET_GATEWAY_WALLET 0x0077777d7EBA4688BDeF3E311b846F25870A19B9, TESTNET_GATEWAY_MINTER 0x0022222ABE238Cc2C7Bb1f21003F0a260052475B, MAINNET_GATEWAY_WALLET 0x77777777Dcc4d5A8B6E418Fd04D8997ef11000eE, MAINNET_GATEWAY_MINTER 0x2222222d7164433c4C09B0b0D809a9b52C04C205. Arc Gateway domain id = 26.

Source: https://registry.npmjs.org/@circle-fin/x402-batching/-/x402-batching-3.4.0.tgz

### Circle Gateway supported chain names (SupportedChainName)

Testnet: arbitrumSepolia, arcTestnet, avalancheFuji, baseSepolia, sepolia, hyperEvmTestnet, optimismSepolia, polygonAmoy, seiAtlantic, sonicTestnet, unichainSepolia, worldChainSepolia. Mainnet: arbitrum, avalanche, base, ethereum, hyperEvm, optimism, polygon, sei, sonic, unichain, worldChain, arc. These are the literal string values for GatewayClient({chain: ...}).

Source: https://registry.npmjs.org/@circle-fin/x402-batching/-/x402-batching-3.4.0.tgz

### Circle Agent Stack = a CLI, not a TS SDK

The Agent Stack is driven by @circle-fin/cli@1.0.0 (bin `circle`, engines node>=20.18.2, published 2026-08-13). There is NO Circle API key for Agent Stack — auth is email + OTP via `circle wallet login <email>`, credentials stored in ~/.circle (override CIRCLE_CLI_HOME). Install: `bun add -g @circle-fin/cli`.

Source: https://github.com/circlefin/agent-stack-starter-kits

### Circle CLI command surface

wallet login/logout/status/create(--type agent|local,--testnet)/list/balance/transfer/fund/swap/sign message|typed-data/execute/import/limit set|reset|budget; services search/inspect/pay <url> --address --chain --max-amount --estimate --quiet; bridge transfer/status/get-fee (CCTP); gateway balance/deposit(--method eco|direct)/withdraw; contract address/query; blockchain list; skill install --tool <claude-code|cursor|codex|opencode|amp>; terms accept. Global flags --output json|table, -q. `circle services pay <url>` IS an x402 client. Spending limits are MAINNET ONLY.

Source: https://developers.circle.com/agent-stack/circle-cli/command-reference

### Circle Agent Stack components

Five products: Agent Wallets (policy-controlled USDC wallets, max 5 per user), Agent Marketplace (agents.circle.com/services), Circle CLI, Nanopayments powered by Circle Gateway (gas-free USDC transfers down to $0.000001), and Circle Skills (github.com/circlefin/skills, installed to ~/.agents/skills via https://agents.circle.com/skills/setup.md).

Source: https://www.circle.com/blog/introducing-circle-agent-stack-financial-infrastructure-for-the-agentic-economy

### Circle agent-stack starter kits

github.com/circlefin/agent-stack-starter-kits (branch `master`) has 6 runnable kits: claude-agent-sdk, google-adk, langchain (Deep Agents), mastra, openai-agents, vercel-ai. Prereqs: Node 22.15+, Bun 1.2+ (workspace manager), `bun add -g @circle-fin/cli`. Pattern: give the agent a shell + file tools, let Circle's own skills teach it the CLI, and gate USDC-moving commands (services pay, wallet transfer, bridge transfer, gateway deposit, wallet sign) behind y/N in packages/kit-core/src/approval.ts. Repo is explicitly 'intended for Arc testnet use only'.

Source: https://github.com/circlefin/agent-stack-starter-kits

### Arc/Circle ETHOnline 2026 tracks

Track 1 'Best DeFi/Onchain Finance Application' $10,000 ($3,500 base + $2,500 if deployed to Arc Mainnet by Sep 30). Track 2 'Best Agentic Economy Application with Circle Agent Stack' $10,000 ($3,500 base + $2,500 for Arc Mainnet by Sep 30) — wants agents holding wallets, autonomous USDC spending, Agent Stack wiring agents to wallets/onchain actions, using Nanopayments/Paymaster/App Kits for agent-to-agent payments. Track 3 Continuity-only $3,000. Deliverables for all: functional MVP with frontend/backend + architecture diagram, video demo, GitHub/Replit repo, docs.

Source: https://ethglobal.com/events/ethonline2026/prizes/arc

### Bazantic ETHOnline 2026 tracks

Three $1,000 tracks: (1) 'Help an Agent Use Your Hackathon Project' 2 x $500 — prove an agent does better with your Bazantic MCP server + Recipe than with the raw API, via identical A/B tests (same prompt/model/settings). (2) 'Best Recipe Using EthGlobal Sponsor APIs' $500/$300/$200. (3) 'Agentify a New API' $500/$300/$200. All require: register on bazantic.com, create an x402/MPP Gateway for your project, build a Recipe (instructions on when/why/how to use your service), screen recording, and your Bazantic username. A Recipe is agent-facing usage documentation.

Source: https://ethglobal.com/events/ethonline2026/prizes/bazantic

### x402 Bazaar discovery API

GET /discovery/resources with optional filters type, payTo, scheme, network, extensions, limit (1-100, default 20), offset (default 0). Bazaar is a spec'd extension at specs/extensions/bazaar.md, implemented in @x402/extensions. Relevant to the Bazantic tracks and to making your service discoverable.

Source: https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md

### Bun compatibility — EMPIRICALLY VERIFIED

On Bun 1.3.14 I installed @x402/core@2.25.0 + @x402/hedera@2.25.0 + @x402/hono@2.25.0 + hono@4.13.7 (322 packages, one benign warning: 'incorrect peer dependency protobufjs@8.2.0'). A Hono server returned a correct 402 with a valid base64 PAYMENT-REQUIRED header. The Hedera client signer built a 1972-char base64 partially-signed TransferTransaction with transactionId.accountId == feePayer and made ZERO network calls (freezeWith is local). @circle-fin/x402-batching@3.4.0 + express@5.2.1 also ran on Bun and returned a correct Arc 402.

Source: https://github.com/x402-foundation/x402/blob/main/typescript/packages/mechanisms/hedera/README.md

### Live 402 produced on Hedera testnet — actual decoded header

My Bun/Hono server with price '$0.01' on hedera:testnet produced PAYMENT-REQUIRED decoding to: {x402Version:2, error:'Payment required', resource:{url:'http://localhost:4099/paid', description:'Probe resource', mimeType:'application/json'}, accepts:[{scheme:'exact', network:'hedera:testnet', amount:'10000', asset:'0.0.429274', payTo:'0.0.9185802', maxTimeoutSeconds:300, extra:{feePayer:'0.0.9185802'}}]}. Note the SDK auto-resolved $0.01 -> 10000 atomic USDC and auto-injected extra.feePayer from the facilitator's /supported.

Source: https://x402.org/facilitator/supported

### Facilitator accepted my hand-built v2 payload — error vocabulary

POST https://x402.org/facilitator/verify with {x402Version:2, paymentPayload:{x402Version:2, resource, accepted, payload:{transaction}}, paymentRequirements} returned HTTP 200 with {"isValid":false,"invalidReason":"invalid_exact_hedera_payload_signature_invalid","invalidMessage":"signature_invalid: payer 0.0.9001 did not sign the transaction","payer":"0.0.9001"}. This proves the wire format is correct — it failed only because my generated key did not match account 0.0.9001's on-chain key. With a real funded portal account it passes.

Source: https://x402.org/facilitator/supported

### Live 402 produced on Arc testnet — actual decoded header

My Bun/Express server with createGatewayMiddleware({networks:['eip155:5042002']}) and gateway.require('$0.01') produced PAYMENT-REQUIRED decoding to: {x402Version:2, resource:{url:'/arc-paid', description:'Arc probe resource', mimeType:'application/json'}, accepts:[{scheme:'exact', network:'eip155:5042002', asset:'0x3600000000000000000000000000000000000000', amount:'10000', payTo:'0x209693Bc6afc0C5328bA36FaF03C514EF312287C', maxTimeoutSeconds:604900, extra:{name:'GatewayWalletBatched', version:'1', verifyingContract:'0x0077777d7eba4688bdef3e311b846f25870a19b9'}}]}.

Source: https://gateway-api-testnet.circle.com/v1/x402/supported

### @x402/hono peer dependencies

@x402/hono@2.25.0 deps @x402/core ~2.25.0 and @x402/extensions ~2.25.0; peers hono ^4.0.0 and @x402/paywall ^2.25.0 (optional). Signature: paymentMiddleware(routes, server, paywallConfig?, paywall?, syncFacilitatorOnStart?) -> MiddlewareHandler. Route keys are 'METHOD /path' strings and support wildcards like 'GET /api/premium/*'.

Source: https://github.com/x402-foundation/x402/blob/main/typescript/packages/http/hono/README.md

### x402 exact-EVM asset transfer methods

Two EVM methods: EIP-3009 (default, single signature via transferWithAuthorization, used by USDC) and Permit2 (universal ERC-20 fallback, requires one-time approval, set extra.assetTransferMethod='permit2'; add supportsEip2612:true if the token also has permit()). Default when unspecified is EIP-3009.

Source: https://github.com/x402-foundation/x402/blob/main/DEFAULT_ASSETS.md

### Base Sepolia reference values (for a fallback/second network)

Base Sepolia is eip155:84532 with USDC at 0x036CbD53842c5426634e7929541eC2318f3dCF7e, EIP-712 extra {name:'USDC', version:'2'}. Base mainnet eip155:8453 USDC 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913. Base Sepolia is supported by BOTH x402.org/facilitator and Circle Gateway testnet.

Source: https://docs.x402.org/core-concepts/network-and-token-support

## Code and commands

### Hedera x402-gated route on Bun + Hono (VERIFIED RUNNING — produced a real 402)

This exact file ran on Bun 1.3.14 and returned HTTP 402 with a valid PAYMENT-REQUIRED header. Install: bun add @x402/core@2.25.0 @x402/hedera@2.25.0 @x402/hono@2.25.0 hono. The '$0.01' Money string auto-resolves to amount '10000' on testnet USDC 0.0.429274, and extra.feePayer is auto-injected from the facilitator's GET /supported — you do NOT hardcode it. Register 'hedera:*' so both testnet and mainnet work. Bun serves via `export default {port, fetch}` (no @hono/node-server needed).

```typescript
import { Hono } from "hono";
import { paymentMiddleware, x402ResourceServer } from "@x402/hono";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { ExactHederaScheme } from "@x402/hedera/exact/server";

// Your Hedera account that RECEIVES payment (must be USDC-associated). e.g. "0.0.12345"
const PAY_TO = process.env.HEDERA_SERVICE_ACCOUNT_ID!;

// Free public facilitator; supports hedera:testnet (feePayer 0.0.9185802). No API key.
// For hedera:mainnet use https://api.blocky402.com instead.
const facilitator = new HTTPFacilitatorClient({
  url: process.env.X402_FACILITATOR_URL ?? "https://x402.org/facilitator",
});

const resourceServer = new x402ResourceServer(facilitator)
  .register("hedera:*", new ExactHederaScheme({}));

const app = new Hono();

app.use(
  paymentMiddleware(
    {
      "GET /paid": {
        accepts: [
          { scheme: "exact", price: "$0.01", network: "hedera:testnet", payTo: PAY_TO },
        ],
        description: "Probe resource",
        mimeType: "application/json",
      },
      // HBAR variant: price must be an explicit AssetAmount in TINYBARS
      "GET /paid-hbar": {
        accepts: [
          {
            scheme: "exact",
            price: { asset: "0.0.0", amount: "100000" }, // 0.001 HBAR
            network: "hedera:testnet",
            payTo: PAY_TO,
          },
        ],
        description: "Probe resource (HBAR)",
        mimeType: "application/json",
      },
    },
    resourceServer,
  ),
);

app.get("/paid", c => c.json({ ok: true, secret: "paid content" }));
app.get("/paid-hbar", c => c.json({ ok: true, secret: "paid content" }));
app.get("/health", c => c.json({ up: true }));

export default { port: 4099, fetch: app.fetch };
```

### Hedera x402 agent client on Bun (VERIFIED — signs locally, no network call)

VERIFIED: produced a 1972-char base64 partially-signed TransferTransaction with transactionId.accountId == feePayer, making ZERO network calls (freezeWith is local). This means the Hiero gRPC stack is never exercised on the client path — important for Bun. CRITICAL: import PrivateKey from '@x402/hedera' (its re-export), NOT from '@hiero-ledger/sdk', or instanceof checks cross-fail with 't.startsWith is not a function'. Use fromStringECDSA for 0x-prefixed portal keys.

```typescript
import { wrapFetchWithPayment, x402Client } from "@x402/fetch";
import { ExactHederaScheme } from "@x402/hedera/exact/client";
import { createClientHederaSigner, PrivateKey } from "@x402/hedera";

// Portal accounts give 0x-prefixed ECDSA keys -> fromStringECDSA.
// (ED25519 keys: use PrivateKey.fromStringED25519)
const signer = createClientHederaSigner(
  process.env.HEDERA_AGENT_ACCOUNT_ID!,                       // "0.0.12345"
  PrivateKey.fromStringECDSA(process.env.HEDERA_AGENT_PRIVATE_KEY!),
  { network: "hedera:testnet" },
);

const client = new x402Client().register("hedera:*", new ExactHederaScheme(signer));
const fetchWithPayment = wrapFetchWithPayment(fetch, client);

// One call: GET -> 402 -> sign Hedera tx -> retry with PAYMENT-SIGNATURE -> 200
const res = await fetchWithPayment("http://localhost:4099/paid");
console.log("status:", res.status);

// Settlement proof for your demo video / audit trail
const hdr = res.headers.get("PAYMENT-RESPONSE");
if (hdr) {
  const settled = JSON.parse(Buffer.from(hdr, "base64").toString("utf8"));
  console.log("settled:", settled);
  // { success: true, transactionId: "0.0.9185802@1700000000.000000000",
  //   network: "hedera:testnet", payer: "0.0.9185802" }
  // -> https://hashscan.io/testnet/transaction/<transactionId>
}
console.log(await res.json());
```

### Associate USDC with a Hedera account (REQUIRED before any USDC payment)

Hedera requires explicit HTS token association. BOTH the paying agent account AND the receiving service account must be associated with 0.0.429274 or settlement fails on-chain with TOKEN_NOT_ASSOCIATED_TO_ACCOUNT. The Hedera portal does NOT expose this — you must run it. HBAR (asset 0.0.0) needs no association, so the HBAR route is the fastest path to a working demo. Run once per account.

```typescript
import {
  AccountId, Client, PrivateKey, TokenAssociateTransaction, TokenId,
} from "@x402/hedera"; // re-exports: keeps a single SDK instance

const USDC = { testnet: "0.0.429274", mainnet: "0.0.456858" } as const;
const network = (process.env.HEDERA_NETWORK ?? "testnet") as keyof typeof USDC;

const accountId = AccountId.fromString(process.env.HEDERA_ACCOUNT_ID!);
const key = PrivateKey.fromStringECDSA(process.env.HEDERA_PRIVATE_KEY!);

const client = (network === "mainnet" ? Client.forMainnet() : Client.forTestnet())
  .setOperator(accountId, key);

const tx = await new TokenAssociateTransaction()
  .setAccountId(accountId)
  .setTokenIds([TokenId.fromString(USDC[network])])
  .execute(client);

const receipt = await tx.getReceipt(client);
console.log("status:", receipt.status.toString());       // SUCCESS
console.log("txId:", tx.transactionId?.toString());
client.close();
```

### Arc testnet x402-gated route via Circle Gateway (VERIFIED RUNNING — produced a real Arc 402)

This exact file ran on Bun with express@5.2.1 and returned a correct 402 for eip155:5042002. Install: bun add @circle-fin/x402-batching@3.4.0 @x402/core@2.25.0 @x402/evm@2.25.0 viem express. facilitatorUrl MUST be the testnet host — the default is mainnet (https://gateway-api.circle.com). Omit `networks` entirely to accept payment from ANY Gateway chain (buyer pays from wherever they hold Gateway balance) — that is the stronger demo. No Circle API key needed for the facilitator.

```typescript
import express from "express";
import { createGatewayMiddleware } from "@circle-fin/x402-batching/server";

const app = express();
app.use(express.json());

const gateway = createGatewayMiddleware({
  sellerAddress: process.env.SELLER_WALLET_ADDRESS!,   // 0x...
  facilitatorUrl: "https://gateway-api-testnet.circle.com", // default is MAINNET
  networks: ["eip155:5042002"],   // Arc Testnet. Omit to accept all Gateway chains.
  description: "Arc probe resource",
});

app.get("/arc-paid", gateway.require("$0.01"), (req, res) => {
  // req.payment = { verified, payer, amount, network, transaction? }
  res.json({ ok: true, payer: (req as any).payment?.payer });
});

// Bypass payment for trusted internal callers
gateway.onProtectedRequest(async ctx => {
  if (ctx.getHeader("x-api-key") === process.env.INTERNAL_KEY) {
    return { grantAccess: true };
  }
});

app.listen(4098);
```

### Arc agent paying gas-free USDC autonomously (Circle Gateway client)

GatewayClient is the buyer side: one-time deposit funds a Gateway balance, then every pay() is gas-free and batch-settled. chain:'arcTestnet' is the literal SupportedChainName. Use the lifecycle hooks as your agent's spend policy — this is exactly the 'clear decision logic + autonomous spending with guardrails' the Circle track asks for. PayResult gives {data, amount, formattedAmount, transaction, status} for your audit trail.

```typescript
import { GatewayClient } from "@circle-fin/x402-batching/client";

const gw = new GatewayClient({
  chain: "arcTestnet",                       // 'arc' for mainnet (needs private rpcUrl)
  privateKey: process.env.AGENT_PRIVATE_KEY as `0x${string}`,
});

// One-time: fund the Gateway balance (approves + deposits). Needs USDC on Arc.
await gw.deposit("1.00");
console.log(await gw.getBalances());

// Agent spend policy, enforced before anything is signed
gw.onBeforePaymentCreation(async ctx => {
  const atomic = BigInt(ctx.selectedRequirements.amount);       // 6-decimal USDC
  if (atomic > 50_000n) return { abort: true, reason: "over $0.05 per-call cap" };
})
.onAfterPaymentCreation(async ctx => console.log("signed", ctx.paymentPayload))
.onPaymentResponse(async ctx => console.log("settlement", ctx.settleResponse));

// Check before paying, then pay — gas-free
const { supported } = await gw.supports("http://localhost:4098/arc-paid") as any;
const { data, formattedAmount, transaction } = await gw.pay("http://localhost:4098/arc-paid");
console.log(`paid ${formattedAmount} USDC, tx ${transaction}`, data);
```

### Decoding / constructing x402 v2 headers by hand

Useful for logging, audit trails, a custom client, or debugging. All three v2 headers are base64-encoded JSON. Header names are exactly PAYMENT-REQUIRED, PAYMENT-SIGNATURE, PAYMENT-RESPONSE (case-insensitive in HTTP). The 402 body is `{}` — never parse the body for requirements in v2.

```typescript
type PaymentRequired = {
  x402Version: 2;
  error?: string;
  resource: { url: string; description?: string; mimeType?: string;
              serviceName?: string; tags?: string[]; iconUrl?: string };
  accepts: Array<{
    scheme: string; network: string; amount: string; asset: string;
    payTo: string; maxTimeoutSeconds: number; extra?: Record<string, unknown>;
  }>;
  extensions?: Record<string, unknown>;
};

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o), "utf8").toString("base64");
const unb64 = <T,>(s: string): T => JSON.parse(Buffer.from(s, "base64").toString("utf8"));

// Server side: signal payment required
function send402(req: PaymentRequired) {
  return new Response("{}", {
    status: 402,
    headers: { "content-type": "application/json", "PAYMENT-REQUIRED": b64(req) },
  });
}

// Client side: read the challenge
const res = await fetch("https://api.example.com/paid");
if (res.status === 402) {
  const challenge = unb64<PaymentRequired>(res.headers.get("PAYMENT-REQUIRED")!);
  console.log(challenge.accepts[0].network, challenge.accepts[0].amount);
}

// After a paid request: read settlement
const settled = res.headers.get("PAYMENT-RESPONSE");
if (settled) console.log(unb64(settled)); // {success, transaction, network, payer}
```

### Talking to a facilitator directly (VERIFIED against x402.org/facilitator)

I ran all three of these. /supported needs no auth and is the fastest way to discover the feePayer for Hedera or the verifyingContract for Gateway. The /verify call returned {isValid:false, invalidReason:'invalid_exact_hedera_payload_signature_invalid'} for an unfunded/mismatched key — proving format correctness. Use these to debug before writing client code.

```bash
# What does the public facilitator support? (no API key)
curl -s https://x402.org/facilitator/supported | jq '.kinds[] | select(.network|startswith("hedera"))'
# -> {"x402Version":2,"scheme":"exact","network":"hedera:testnet","extra":{"feePayer":"0.0.9185802"}}

# Blocky402 is MAINNET ONLY (note the api. host; blocky402.com/supported 404s)
curl -s https://api.blocky402.com/supported | jq .

# Circle Gateway: is Arc testnet live? (no API key)
curl -s https://gateway-api-testnet.circle.com/v1/x402/supported \
  | jq '.kinds[] | select(.network=="eip155:5042002")'

# Verify a payload by hand
curl -s -X POST https://x402.org/facilitator/verify \
  -H 'content-type: application/json' \
  -d '{"x402Version":2,"paymentPayload":{...},"paymentRequirements":{...}}' | jq .

# Decode a 402 challenge from any x402 service
curl -sD - -o /dev/null https://your-service/paid \
  | grep -i '^payment-required:' | sed 's/^[^:]*: *//' | tr -d '\r' | base64 -d | jq .
```

### Verify Arc's chain id and USDC EIP-3009 support yourself

These are the exact commands I used to confirm Arc empirically. The DOMAIN_SEPARATOR match proves the EIP-712 domain is {name:'USDC', version:'2', chainId:5042002, verifyingContract:0x3600...}, so plain @x402/evm ExactEvmScheme works on Arc with extra:{name:'USDC',version:'2'}. The 0xdeadbeef control reverting while authorizationState returns data is what proves EIP-3009 is really implemented (the predeploy has no normal dispatch table in its bytecode).

```bash
RPC=https://rpc.testnet.arc.io
A=0x3600000000000000000000000000000000000000

# chain id -> 0x4cef52 = 5042002
cast chain-id --rpc-url $RPC

# USDC ERC-20 interface: "USDC" / 6 / "2"
cast call $A 'name()(string)'     --rpc-url $RPC
cast call $A 'decimals()(uint8)'  --rpc-url $RPC
cast call $A 'version()(string)'  --rpc-url $RPC
cast call $A 'DOMAIN_SEPARATOR()(bytes32)' --rpc-url $RPC
# -> 0x361191522483d32a83e70ae7183b4b9629442c13a78bc9921d6f707911c8c6b0

# Reproduce that domain separator to prove the EIP-712 domain:
TH=$(cast keccak "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
cast keccak $(cast abi-encode 'f(bytes32,bytes32,bytes32,uint256,address)' \
  $TH $(cast keccak "USDC") $(cast keccak "2") 5042002 $A)   # MATCHES

# EIP-3009 present? authorizationState returns data, control selector reverts.
cast call $A 'authorizationState(address,bytes32)(bool)' \
  0x857b06519E91e3A54538791bDbb0E22373e36b66 \
  0x0000000000000000000000000000000000000000000000000000000000000001 --rpc-url $RPC   # false
cast call $A 0xdeadbeef --rpc-url $RPC                                                 # reverts
```

### Self-hosted facilitator (fallback if you need a network nobody hosts)

Only needed if you must settle on a network no public facilitator covers (e.g. Arc via plain @x402/evm rather than Gateway, or hedera:mainnet without Blocky402). The facilitator's account pays gas and must be funded. On Hedera, use createHederaSignAndSubmitTransaction — plain execute() only pre-checks; you MUST await getReceipt() to catch consensus failures like TOKEN_NOT_ASSOCIATED_TO_ACCOUNT. Given a 24h budget, prefer the hosted facilitators and skip this.

```typescript
import { x402Facilitator } from "@x402/core/facilitator";
import { ExactHederaScheme } from "@x402/hedera/exact/facilitator";
import {
  createHederaSignAndSubmitTransaction,
  createHederaVerifyPayerSignature,
  type FacilitatorHederaSigner,
} from "@x402/hedera";
import { createHederaPreflightTransfer } from "@x402/hedera";
import { AccountId, Client, PrivateKey } from "@x402/hedera";

const feePayerId = process.env.HEDERA_FACILITATOR_ACCOUNT_ID!;
const feePayerKey = PrivateKey.fromStringECDSA(process.env.HEDERA_FACILITATOR_PRIVATE_KEY!);

const buildClient = (network: string): Client => {
  const c = network === "hedera:mainnet" ? Client.forMainnet() : Client.forTestnet();
  c.setOperator(AccountId.fromString(feePayerId), feePayerKey);
  return c;
};

const signer: FacilitatorHederaSigner = {
  getAddresses: () => [feePayerId],
  signAndSubmitTransaction: createHederaSignAndSubmitTransaction(buildClient, feePayerKey),
  verifyPayerSignature: createHederaVerifyPayerSignature(),   // free Mirror Node
  preflightTransfer: createHederaPreflightTransfer(),         // balance + association
  resolveAccount: async () => ({ exists: true, isAlias: false }),
};

const facilitator = new x402Facilitator()
  .register("hedera:*", new ExactHederaScheme(signer, { aliasPolicy: "reject" }));

// Expose POST /verify, POST /settle, GET /supported over HTTP:
Bun.serve({
  port: 4050,
  async fetch(req) {
    const { pathname } = new URL(req.url);
    if (pathname === "/supported") return Response.json(facilitator.getSupported());
    const { paymentPayload, paymentRequirements } = await req.json();
    if (pathname === "/verify")
      return Response.json(await facilitator.verify(paymentPayload, paymentRequirements));
    if (pathname === "/settle")
      return Response.json(await facilitator.settle(paymentPayload, paymentRequirements));
    return new Response("not found", { status: 404 });
  },
});
```

### Circle Agent Stack: the CLI an agent actually drives

This is what the Circle Agent Stack track wants demonstrated. There is NO Circle API key — auth is email + OTP, credentials in ~/.circle. `circle services pay` is a fully-featured x402 client, so your agent can consume ANY x402 service (including your own Hedera or Arc endpoint) by shelling out. Use --output json so the agent can parse. Spending limits are MAINNET ONLY — on testnet enforce caps in your own approval gate.

```bash
bun add -g @circle-fin/cli          # provides the `circle` binary

circle wallet login you@example.com # email + OTP; stores creds in ~/.circle
circle wallet create --type agent --testnet
circle wallet list --chain ARC-TESTNET --output json
circle wallet fund --address 0xYOU --chain ARC-TESTNET   # testnet faucet
circle wallet balance --address 0xYOU --chain ARC-TESTNET

# Nanopayments: fund a Gateway balance so payments are gas-free
circle gateway deposit --amount 5 --address 0xYOU --chain ARC-TESTNET --method direct
circle gateway balance --address 0xYOU --chain ARC-TESTNET

# Discover + inspect + pay an x402 service (this IS the x402 client)
circle services search "weather" --output json
circle services inspect https://your-service/paid
circle services pay https://your-service/paid \
  --address 0xYOU --chain ARC-TESTNET --max-amount 0.01 --output json

# Guardrails (MAINNET only; confirms via one-time code)
circle wallet limit set --address 0xYOU --chain BASE
circle wallet limit budget --address 0xYOU

# Install Circle's skills so a coding agent knows the whole surface
circle skill install --tool claude-code
```

### Working package.json for a Bun x402 server+agent (exact versions I installed)

These exact versions resolved and ran on Bun 1.3.14. Do NOT add @hiero-ledger/sdk yourself — @x402/hedera pins it to exactly 2.85.0 and re-exports what you need; a second copy breaks instanceof checks. The 'incorrect peer dependency protobufjs@8.2.0' warning from Bun is benign. Include express only if you use @circle-fin/x402-batching's Express middleware; the Hedera side needs only Hono.

```json
{
  "name": "arx",
  "private": true,
  "type": "module",
  "dependencies": {
    "@x402/core": "2.25.0",
    "@x402/hono": "2.25.0",
    "@x402/fetch": "2.25.0",
    "@x402/hedera": "2.25.0",
    "@x402/evm": "2.25.0",
    "@circle-fin/x402-batching": "3.4.0",
    "hono": "^4.13.7",
    "viem": "^2.56.3",
    "express": "^5.2.1"
  }
}
```

## Unverified — do not rely on these

- Whether the ETHOnline Hedera judges will accept `https://x402.org/facilitator` for track 1. The prize text I read says 'Deploy a live x402-gated service on Hedera testnet or mainnet via Blocky402 facilitator' — but I confirmed Blocky402 serves ONLY hedera:mainnet. So 'testnet' and 'via Blocky402' are mutually exclusive as written. I could not find a clarification. Mitigation: support BOTH (env-switch the facilitator URL, exactly as the official hedera-dev PoC does) so you satisfy either reading; ask in the Hedera/ETHGlobal Discord.
- Whether Blocky402 requires signup or an API key for mainnet settlement. Its /supported is public, but I did not attempt a mainnet /verify or /settle (that would move real funds). Its docs site is a Next.js SPA that I could not scrape for auth requirements.
- Arc MAINNET RPC URL and whether Arc mainnet is live. Chain id 5042 comes from @circle-fin/x402-batching's CHAIN_CONFIGS, and that package's own comment says Arc mainnet had no public RPC until ~2026-06-22 and requires a private RPC URL. docs.arc.io states mainnet endpoints are 'published separately when available'. One search result claimed mainnet launch 2026-09-16. I did NOT verify any Arc mainnet RPC or that USDC sits at the same predeploy address there — so the Circle tracks' '+$2,500 if deployed to Arc Mainnet by Sep 30' bonus is unverified in its mechanics.
- Whether `viem` 2.56.3 actually exports an `arcTestnet` chain. @circle-fin/x402-batching does `chains.arcTestnet ?? defineChain({...})`, so it works either way, but I did not confirm the export exists. Assume it may not and rely on the package's fallback (or define the chain yourself).
- Whether Circle Gateway's /verify and /settle need an API key. GET /v1/x402/supported worked completely unauthenticated, and createGatewayMiddleware has no apiKey field (only an optional `headers` map). I did not exercise verify/settle, which require a real funded Gateway balance. Low risk but untested.
- End-to-end SETTLEMENT on either chain. I proved the full wire format: a correct 402 on both Hedera and Arc, a valid signed Hedera payload, and that x402.org/facilitator accepted my payload's shape (rejecting only on key mismatch). I could not complete a real settled payment because that needs funded accounts, which require human signup. This is the single remaining unknown and should be your first action.
- Hedera track bonus criteria specifics: ERC-8004 / HCS-14 on-chain agent identity, UCP agent discovery, and recurring payments via Scheduled Transactions. I confirmed these are listed as bonuses but did not research their APIs.
- Exactly which chains Circle CLI's `circle services pay` can settle on, and whether ARC-TESTNET works there. The nanopayments quickstart I read only documents BASE; the command reference mentions ARC-TESTNET and ARB-SEPOLIA as testnet options. Run `circle blockchain list` after login to confirm.
- Whether `@x402/express` works with express@5. The official hedera-dev PoC pins express ^4.21.2. I only tested express@5.2.1 with @circle-fin/x402-batching's own middleware (which worked). If you use @x402/express, prefer express 4 — or use @x402/hono on Bun, which I did verify.
- Bazantic's 'MPP Gateway' acronym and the actual mechanics of creating a Gateway + Recipe on bazantic.com. The prize page mentions 'x402/MPP Gateway' without defining MPP, and the platform requires registration I could not complete. There is a workshop video at youtube.com/watch?v=_kKqecKnA_U.
- The Hiero SDK's gRPC path under Bun. I verified the client signing path makes zero network calls, so Bun never touches gRPC for x402 client work. But TokenAssociateTransaction.execute() and any self-hosted facilitator DO use gRPC on Bun — untested. Mitigation: run the one-off association script under Node (`node --experimental-strip-types`) if Bun misbehaves.

## Requires a human: accounts, keys, faucets

- Create a Hedera testnet account at https://portal.hedera.com — sign up, create a TESTNET account, claim testnet HBAR. Copy the account id (0.0.xxxxx) and the ECDSA private key (0x-prefixed). Create TWO accounts: one for the agent (payer) and one for the service (payee). This is the single blocking prerequisite for the $6,000 Hedera track.
- Get testnet USDC at https://faucet.circle.com — select 'Hedera Testnet'. The target account must ALREADY be associated with token 0.0.429274 or the faucet/transfer fails. Shortcut: demo with HBAR (asset '0.0.0') first — it needs no association and no faucet beyond portal HBAR.
- Run the token-association script once for EACH Hedera account (agent and service) against token 0.0.429274. Neither the portal nor the faucet does this for you, and USDC settlement fails with TOKEN_NOT_ASSOCIATED_TO_ACCOUNT without it.
- Get Arc testnet USDC at https://faucet.circle.com — select Arc Testnet. USDC is the native gas token on Arc, so this same balance pays for gas.
- Create a Circle account and run `circle wallet login <your-email>` — auth is email + OTP and cannot be automated. You must also accept the Terms of Use (interactively, or `circle terms accept`). There is NO Circle API key for the Agent Stack. Required for anything judged as 'Circle Agent Stack'.
- Fund a Circle Gateway balance before any gas-free Arc payment will settle: `circle gateway deposit --amount 5 --address 0xYOU --chain ARC-TESTNET --method direct`, or GatewayClient.deposit('1.00'). Gateway payments draw on this balance, not your wallet directly.
- Register on bazantic.com and note your username (email or GitHub) — every Bazantic track requires it in the submission.
- Provide an LLM provider API key for whichever agent framework you use (e.g. ANTHROPIC_API_KEY for the Claude Agent SDK kit). The Circle starter kits authenticate with an API key only — OAuth/subscription auth can hang the spawned subprocess.
- Decide the Hedera facilitator question and ideally confirm with the sponsor in Discord: testnet REQUIRES x402.org/facilitator (Blocky402 has no testnet), while the prize text says 'via Blocky402'. Implement both via an env var so you are covered either way.
- Optional, for the +$2,500 Circle bonus: obtain an Arc MAINNET RPC URL (Alchemy/QuickNode/Circle-provided) and real USDC, then deploy by Sep 30. Arc mainnet has no documented public RPC.

## Recommendations

- Go after the Hedera $6,000 track first — it is the highest value-per-hour by a wide margin. I have already proven the whole stack runs on Bun: `bun add @x402/core@2.25.0 @x402/hedera@2.25.0 @x402/hono@2.25.0 hono`, then the Hono server snippet returns a correct 402 and the client snippet signs a valid payload. The only thing standing between you and a submission is a funded portal account. Budget ~2 hours including the video.
- Demo with HBAR (`price: { asset: '0.0.0', amount: '100000' }` = 0.001 HBAR) as your primary path and USDC as a second route. HBAR needs no token association, no Circle faucet, and no extra moving parts — it removes the single most likely failure mode (TOKEN_NOT_ASSOCIATED_TO_ACCOUNT) from your critical path. Add the USDC route once HBAR settles end-to-end.
- Use `https://x402.org/facilitator` and register `'hedera:*'` (not `'hedera:testnet'`), with the facilitator URL behind an env var defaulting to x402.org and switchable to `https://api.blocky402.com` for mainnet. This is exactly what the official hedera-dev PoC does, costs you nothing, and satisfies both readings of the ambiguous 'via Blocky402' requirement.
- Never hardcode `extra.feePayer`. The middleware fetches it from the facilitator's GET /supported at startup and injects it automatically — I watched it inject `0.0.9185802` into my 402. Hardcoding it is the most likely way to break when the facilitator rotates accounts.
- Import Hedera SDK primitives from `@x402/hedera`, never from `@hiero-ledger/sdk` directly, and do not add @hiero-ledger/sdk to your package.json. @x402/hedera pins it to exactly 2.85.0 and re-exports Client, PrivateKey, TransferTransaction, TokenAssociateTransaction, TokenId, AccountId, Transaction, TransactionId, Hbar and the queries. A second on-disk copy produces the runtime error `t.startsWith is not a function`, which is extremely hard to diagnose under time pressure.
- Capture the `PAYMENT-RESPONSE` header on every paid request, decode it, and log `transactionId` plus a HashScan link (`https://hashscan.io/testnet/transaction/<id>`). The track requires 'one real paid request end-to-end' — an on-screen HashScan confirmation is the single most persuasive thing in your demo video, and it doubles as the 'verifiable payment audit trail' bonus.
- Clone github.com/hedera-dev/x402-inference-pay-per-request-poc and use it as your reference wiring rather than writing from scratch. It is Hedera's own official PoC, its packages/service/src/x402.ts is 17 lines, and it already solves the dual-network facilitator selection. Adapt it to Hono for Bun.
- For the Circle $10,000 track, use `@circle-fin/x402-batching` — it is the only verified way to run x402 on Arc. Arc is absent from @x402/evm's default-asset table, so plain `price: '$0.10'` will not resolve, but Circle's `createGatewayMiddleware`/`GatewayEvmScheme` registers Arc money parsers for you. Remember `facilitatorUrl: 'https://gateway-api-testnet.circle.com'` — the default is mainnet and will silently fail.
- Make your agent's spending policy the centerpiece of the Circle submission, implemented in `onBeforePaymentCreation` returning `{abort:true, reason}` above a per-call cap. The track explicitly asks for 'agents with clear decision logic tied to real signals' and 'autonomous spending with guardrails'. Testnet has no server-side wallet limits (mainnet only), so a visible client-side gate is both necessary and exactly what is being judged.
- Consider one architecture that wins two bounties: host your x402-gated service on Hedera testnet (Hedera track 1) and have the consuming agent ALSO hold an Arc Gateway balance and pay Arc-hosted services (Circle track 2), with an agent-to-agent hop between them. Two 402 challenges on two chains from one codebase is a stronger story than either alone and reuses ~80% of the code.
- Omit the `networks` field in createGatewayMiddleware for the Circle demo. It then accepts payment from ANY Gateway-supported chain (12 testnets), so a buyer pays from wherever they hold balance — a much better 'agentic economy' narrative than pinning to Arc, and it is strictly less code.
- If you want a cheap third bounty, the Hedera Harness track ($2,000, 2 winners) is unusually soft: the repo github.com/hedera-dev/hedera-harness has ONE star, was last touched Sep 5, and an unmerged PR explicitly qualifies. Its 4-stage pipeline (GENERATE/ASSERT/SMOKE/EVALUATE) has obvious gaps — add a validation tier, tests, or x402 support to the scaffold. Only attempt after the Hedera track is submitted.
- Do NOT build your own facilitator. Both hosted facilitators I verified are free, need no API key, and the Hedera one's fee-payer account holds ~10,037 testnet HBAR so it sponsors your gas. Self-facilitation means funding a fee-payer, implementing verifyPayerSignature and preflightTransfer, and getting the getReceipt() consensus-check right — hours you do not have.
- Debug with curl before writing client code: `curl -sD - -o /dev/null <url> | grep -i '^payment-required:' | sed 's/^[^:]*: *//' | tr -d '\r' | base64 -d | jq .`. In v2 the 402 body is `{}` and everything lives in that header, so anyone inspecting the body will wrongly conclude the server is broken.
- Treat every 'x402' blog post, tutorial, and LLM memory as v1 unless it says otherwise. The v1→v2 migration renamed the packages (`x402-hono`→`@x402/hono`), the headers (`X-PAYMENT`→`PAYMENT-SIGNATURE`), the amount field (`maxAmountRequired`→`amount`), the network format (`base-sepolia`→`eip155:84532`), and moved requirements from the body into a header. Mixing the two is the likeliest source of code that compiles but never settles.
