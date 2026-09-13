# Ledger Agent Stack — verified package and API reference

> Compiled 2026-09-12 by a research agent that verified each claim against
> primary sources (npm tarballs, app source, official docs). Facts carry their
> source URL. Anything unverified is listed explicitly at the end — treat that
> section as unknown, not as true.

## Summary

The "Ledger Agent Stack" is not one SDK — it is four independently-shipped pieces the ETHOnline 2026 page bundles under one name: (1) the **Device Management Kit (DMK)** TypeScript SDK plus per-chain **signer kits** and per-environment **transport kits**; (2) the **Ledger Wallet CLI** (`@ledgerhq/wallet-cli` v2.1.0, a compiled Bun binary) whose `ring` command group exposes the **Ledger Key Ring / LKRP**; (3) **DMK Skills** — plain Markdown SKILL.md files in `github.com/LedgerHQ/agent-skills`, installed with `npx skills add`; (4) **Clear Signing / ERC-7730**, whose registry moved to the Ethereum Foundation on 2026-05-12.

Everything important I verified by downloading the actual npm tarballs and reading the `.d.ts` files, because **the published docs are wrong in several places**. Confirmed current versions (2026-09-12): `@ledgerhq/device-management-kit@1.9.0`, `@ledgerhq/device-signer-kit-ethereum@1.18.0`, `@ledgerhq/context-module@2.5.0` (a hard peer dep — install it or the build fails), `@ledgerhq/device-transport-kit-node-hid@1.0.1`, `@ledgerhq/device-transport-kit-speculos@1.2.1`, `@ledgerhq/device-transport-kit-web-hid@1.2.4`, `@ledgerhq/wallet-cli@2.1.0`.

Doc bugs to avoid: the DMK how-to page shows `dmk.connect({ deviceId })` and `executeDeviceAction({ sessionId, openAppDeviceAction })` — the real 1.9.0 signatures are `connect({ device, sessionRefresherOptions })` and `executeDeviceAction({ sessionId, deviceAction })`. The npm README for the ETH signer shows `new SignerEthBuilder({ sdk, sessionId })`; the real arg is `{ dmk, sessionId, originToken? }`. The Speculos README imports from a non-existent package name `@ledgerhq/device-transport-speculos` (correct: `...-transport-kit-speculos`), and the concepts skill calls Speculos a "TCP socket" transport when it is actually HTTP (`POST {url}/apdu`, SSE on `GET {url}/events`).

For a Bun project the single biggest landmine: **`device-transport-kit-node-hid` is CJS-only** (both `import` and `require` resolve to `lib/cjs/index.js`) and pulls native `node-hid@^3.2.0` + `usb@^2.16.0`. The Speculos transport is pure ESM+CJS with zero native deps, so build and demo against Speculos and treat node-hid as the optional real-hardware path.

The highest-leverage discovery for the bounty's headline ask ("secrets they cannot leak", "Key Ring on hosts with no USB port") is `@ledgerhq/device-trusted-app-kit-ledger-keyring-protocol@0.5.0`: `authenticate()` returns `{ jwt, trustchainId, applicationPath, encryptionKey }`, and a second call with a **persisted keypair + trustchainId and no `sessionId`** re-authenticates with **no device attached**. That is exactly a capability broker, and it is the programmatic form of what `wallet-cli ring` does.

## Verified facts

### Bounty terms

Ledger x ETHOnline 2026: Sep 4–16 2026, submissions close Sep 13. $5,000 total pool. Track 01 'AI Agents x Ledger' $3,500 (1st $2,000 / 2nd $1,000 / 3rd $500); Track 02 'Continuity' $1,500 (1st $1,000 / 2nd $500). Track 01 example directions state verbatim: 'Agents that use secrets they cannot leak: a broker hands out scoped capabilities, never the API key.' and 'Bring the Key Ring to hosts with no USB port: enroll a VPS, a CI runner, or a hosted agent.' followed by 'Both must be built on the Ledger Agent Stack, and in particular on the Ledger Key Ring CLI (wallet-cli ring).'

Source: https://developers.ledger.com/ethonline

### Bounty submission requirement

'Every submission has to include feedback on the tooling. We judge the Developer Experience (DX) feedback as much as the code.' What to include: feedback on docs & SDKs, gaps/confusing flows, specific improvements with screenshots or PRs. Bonus: tutorial/code-sample ideas, navigation or search improvements, time-saver suggestions.

Source: https://developers.ledger.com/ethonline

### Docs in Markdown form

Every developers.ledger.com doc page has a clean Markdown twin at the same path with '.md' appended, e.g. https://developers.ledger.com/docs/ai-tools/ledger-cli.md . The page itself advertises this: 'If you are an AI agent, LLM, or automated tool, a clean Markdown version of this page is available at ... optimised for AI and LLM tools.' Verified HTTP 200 for ai-tools/*, clear-signing/*, device-interaction/*, ledger-wallet-provider/overview.

Source: https://developers.ledger.com/docs/ai-tools/ledger-cli.md

### DMK version

@ledgerhq/device-management-kit latest = 1.9.0, published 2026-09-02T13:51:52Z. Dependencies: @noble/hashes ^1.8.0, @sentry/minimal 6.19.7, inversify 7.5.1, isomorphic-ws ^5.0.0, purify-ts 2.1.0, reflect-metadata 0.2.2, semver 7.7.2, uuid 11.0.3, ws ^8.18.0, xstate 5.19.2. peerDependencies: rxjs 7.8.2 (exact pin). exports: ESM ./lib/esm/index.js, CJS ./lib/cjs/index.js, types ./lib/types/index.d.ts.

Source: https://registry.npmjs.org/@ledgerhq/device-management-kit

### rxjs pin

rxjs is a peerDependency pinned to the EXACT version 7.8.2 (not a range) by @ledgerhq/device-management-kit, @ledgerhq/device-transport-kit-node-hid and @ledgerhq/device-transport-kit-speculos. Install rxjs@7.8.2 exactly.

Source: https://registry.npmjs.org/@ledgerhq/device-management-kit

### ETH signer kit version + peer deps

@ledgerhq/device-signer-kit-ethereum latest = 1.18.0 (2026-09-02). peerDependencies: @ledgerhq/context-module ^2.5.0 AND @ledgerhq/device-management-kit ^1.9.0. Own dependencies include ethers 6.14.1, @ledgerhq/signer-utils ^1.3.0, @ledgerhq/device-contacts-kit ^0.4.0, inversify 7.5.1, purify-ts 2.1.0, reflect-metadata 0.2.2, semver 7.7.2, xstate 5.19.2.

Source: https://registry.npmjs.org/@ledgerhq/device-signer-kit-ethereum

### context-module is mandatory

@ledgerhq/context-module latest = 2.5.0 (2026-08-28). It is a peer dependency of the ETH signer kit and is imported internally, NOT only for Clear Signing. The Ledger DMK skill states verbatim: 'Installing the eth signer kit without it causes a build failure (Module not found: Can't resolve \'@ledgerhq/context-module\'). Install it unconditionally when using the Ethereum signer.' NOTE: context-module@2.5.0 itself declares peerDependencies { "@ledgerhq/device-management-kit": "0.9.2" } — a stale exact pin that will produce a peer-dep warning/error against DMK 1.9.0; use --legacy-peer-deps on npm or ignore under Bun/pnpm.

Source: https://registry.npmjs.org/@ledgerhq/context-module

### node-hid transport — CJS only + native deps

@ledgerhq/device-transport-kit-node-hid@1.0.1 (published 2026-04-14). Its package.json exports map BOTH "import" and "require" to "./lib/cjs/index.js" — there is no ESM build. dependencies: node-hid ^3.2.0, usb ^2.16.0, purify-ts 2.1.0, uuid 11.0.3. peerDependencies: @ledgerhq/device-management-kit ^1.2.0, rxjs 7.8.2. README says 'tested successfully on Node v20'. Exports: nodeHidIdentifier, NodeHidTransport, nodeHidTransportFactory. Transport identifier string is "NODE-HID".

Source: https://registry.npmjs.org/@ledgerhq/device-transport-kit-node-hid

### Speculos transport package name

The official DMK<->Speculos transport is @ledgerhq/device-transport-kit-speculos, latest 1.2.1. It talks HTTP, not TCP. dependencies: @sentry/minimal 6.19.7, purify-ts 2.1.0 (no native modules). peerDependencies: rxjs 7.8.2, @ledgerhq/device-management-kit ^1.5.1. Exports: speculosIdentifier, SpeculosTransport, speculosTransportFactory, HttpSpeculosDatasource. Transport identifier string is "SPECULOS_HTTP_TRANSPORT". NOTE: there is NO package named @ledgerhq/device-transport-kit-speculos-http (404 on npm), and the package README wrongly imports from '@ledgerhq/device-transport-speculos'.

Source: https://registry.npmjs.org/@ledgerhq/device-transport-kit-speculos

### Speculos transport factory signature

From lib/types/src/api/SpeculosTransport.d.ts: `export declare const speculosTransportFactory: (speculosUrl?: string, isE2E?: boolean, deviceModelId?: DeviceModelId) => TransportFactory;`  Note it is a FUNCTION that returns a TransportFactory — you must CALL it: .addTransport(speculosTransportFactory('http://localhost:5000')). This differs from nodeHidTransportFactory / webHidTransportFactory, which ARE TransportFactory values and must be passed uncalled.

Source: https://registry.npmjs.org/@ledgerhq/device-transport-kit-speculos

### Speculos HTTP wire protocol used by DMK

HttpSpeculosDatasource (built ESM source) does: postApdu -> HTTP POST `${baseUrl}/apdu` with JSON body { data: <apdu hex string> }, returns response .data ; isServerAvailable -> GET `${baseUrl}/events` with 2000ms timeout ; openEventStream -> fetch GET `${baseUrl}/events?stream=true` with Accept: text/event-stream, parses lines prefixed 'data: '. Sends header X-Ledger-Client-Version: ldmk-transport-speculos/<pkg version>. Default Speculos port in the README example is 5000.

Source: https://registry.npmjs.org/@ledgerhq/device-transport-kit-speculos

### DMK real API signatures (1.9.0)

From lib/types/src/api/DeviceManagementKit.d.ts and the use-case types: startDiscovering(args: { transport?: TransportIdentifier }): Observable<DiscoveredDevice>; listenToAvailableDevices(args: { transport?: TransportIdentifier }): Observable<DiscoveredDevice[]>; connect(args: { device: DiscoveredDevice | ConnectedDevice; sessionRefresherOptions?: { isRefresherDisabled: boolean; pollingInterval?: number } }): Promise<DeviceSessionId>; disconnect({ sessionId }); sendApdu({ sessionId, apdu }): Promise<ApduResponse>; sendCommand({ sessionId, command, abortTimeout? }): Promise<CommandResult>; executeDeviceAction({ sessionId, deviceAction }): { observable, cancel }; getDeviceSessionState({ sessionId }): Observable<DeviceSessionState>; getConnectedDevice({ sessionId }); close(); setProvider(n); getProvider(); isEnvironmentSupported(); listConnectedDevices(); listenToConnectedDevice(); disableDeviceSessionRefresher({ sessionId, blockerId }).

Source: https://registry.npmjs.org/@ledgerhq/device-management-kit

### DOC BUG — connect()

The published DMK how-to page and the npm README both show `dmk.connect({ deviceId: device.id, { isRefresherDisabled: true } })`. That is NOT the 1.9.0 API. ConnectUseCaseArgs is `{ device: DiscoveredDevice | ConnectedDevice; sessionRefresherOptions?: DeviceSessionRefresherOptions }`. Passing deviceId will not compile.

Source: https://developers.ledger.com/docs/device-interaction/dmk-ts/integration/how_to/dmk

### DOC BUG — executeDeviceAction()

The DMK how-to page shows `await dmk.executeDeviceAction({ sessionId, openAppDeviceAction })`. Real type ExecuteDeviceActionUseCaseArgs is `{ readonly sessionId: string; readonly deviceAction: DeviceAction<...> }` — the key must be `deviceAction`. Also, executeDeviceAction is NOT async; it returns `{ observable, cancel }` synchronously.

Source: https://developers.ledger.com/docs/device-interaction/dmk-ts/integration/how_to/dmk

### DOC BUG — SignerEthBuilder arg name

The device-signer-kit-ethereum npm README shows `new SignerEthBuilder({ sdk, sessionId }).build()`. The real 1.18.0 type is `SignerEthBuilderConstructorArgs = { dmk: DeviceManagementKit; sessionId: DeviceSessionId; originToken?: string }`. The key is `dmk`, not `sdk`. Builder methods: .withContextModule(contextModule), .withAddressBook(addressBook), .build().

Source: https://registry.npmjs.org/@ledgerhq/device-signer-kit-ethereum

### SignerEth interface (1.18.0) — exact

export interface SignerEth { signTransaction(derivationPath: string, transaction: Uint8Array, options?: TransactionOptions): SignTransactionDAReturnType; signMessage(derivationPath: string, message: string | Uint8Array, options?: MessageOptions): SignPersonalMessageDAReturnType; signTypedData(derivationPath: string, typedData: TypedData, options?: TypedDataOptions): SignTypedDataDAReturnType; getAddress(derivationPath: string, options?: AddressOptions): GetAddressDAReturnType; verifySafeAddress(safeContractAddress: string, options?: SafeAddressOptions): VerifySafeAddressDAReturnType; signDelegationAuthorization(derivationPath: string, chainId: number, contractAddress: string, nonce: number): SignDelegationAuthorizationDAReturnType; }  TransactionOptions = { skipOpenApp?: boolean }. AddressOptions = { checkOnDevice?: boolean; returnChainCode?: boolean }. Output of signTransaction = Signature = { r: `0x${string}`; s: `0x${string}`; v: number }.

Source: https://registry.npmjs.org/@ledgerhq/device-signer-kit-ethereum

### How signTransaction parses the Uint8Array (decisive for EIP-1559)

The internal EthersTransactionMapperService (read from lib/cjs) does exactly: `const r = ethers.Transaction.from(bufferToHexaString(t)); if (Number(r.chainId) <= 0) return Left(new Error('Pre-EIP-155 transactions are not supported')); return Right({ subset: { chainId, to, data, selector: data.slice(0,10), value }, serializedTransaction: getBytes(r.unsignedSerialized), type: r.type || 0 })`. So the Uint8Array you pass must be an ethers-parseable serialized UNSIGNED typed transaction, and chainId must be > 0. TransactionType enum: LEGACY=0, EIP2930=1, EIP1559=2, EIP4844=3.

Source: https://registry.npmjs.org/@ledgerhq/device-signer-kit-ethereum

### signTransaction device-action steps (for UI/telemetry)

SignTransactionDAStep enum values: OPEN_APP='signer.eth.steps.openApp', GET_APP_CONFIG, GET_ADDRESS, WEB3_CHECKS_OPT_IN, WEB3_CHECKS_OPT_IN_RESULT, PARSE_TRANSACTION, BUILD_CONTEXTS, PROVIDE_CONTEXTS, SIGN_TRANSACTION, BLIND_SIGN_TRANSACTION_FALLBACK, DETECT_BLIND_SIGNING. The Pending intermediateValue carries { requiredUserInteraction, step } — so you can detect blind-signing fallback programmatically and refuse to proceed.

Source: https://registry.npmjs.org/@ledgerhq/device-signer-kit-ethereum

### Transport identifier constants

Import identifiers, never hardcode: webHidIdentifier === "WEB-HID" (from @ledgerhq/device-transport-kit-web-hid), nodeHidIdentifier === "NODE-HID", speculosIdentifier === "SPECULOS_HTTP_TRANSPORT". Verified the two latter strings inside the shipped bundles.

Source: https://registry.npmjs.org/@ledgerhq/device-transport-kit-node-hid

### DeviceModelId enum (needed for speculosTransportFactory 3rd arg)

export declare enum DeviceModelId { NANO_S='nanoS', NANO_SP='nanoSP', NANO_X='nanoX', STAX='stax', FLEX='flex', APEX='apexp' }. Also exported: LEDGER_VENDOR_ID = 11415 (0x2c97).

Source: https://registry.npmjs.org/@ledgerhq/device-management-kit

### DMK top-level exports you will actually import

From lib/types/src/api/index.d.ts, all exported at package root: DeviceManagementKitBuilder, ConsoleLogger, ApduBuilder (+APDU_MAX_PAYLOAD), ApduParser, CommandUtils, CommandResultFactory, CommandResultStatus, isSuccessCommandResult, OpenAppCommand, CloseAppCommand, GetOsVersionCommand, GetAppAndVersionCommand, OpenAppDeviceAction, DeviceActionStatus, UserInteractionRequired, DeviceStatus, DeviceSessionStateType, GenuineCheckDeviceAction, ListInstalledAppsDeviceAction, InstallAppDeviceAction, UninstallAppDeviceAction, DmkNetworkClient, bufferToHexaString / hexaStringToBuffer / isHexaString.

Source: https://registry.npmjs.org/@ledgerhq/device-management-kit

### Signer kits available (all chains)

@ledgerhq/device-signer-kit-ethereum 1.18.0, -solana 1.13.0, -bitcoin 1.3.3, -cosmos 1.0.1, -hyperliquid 1.1.0, -zcash 0.7.1, -aleo 0.4.0, -concordium 0.5.0, -icp 0.2.0, -xrp 0.2.0, -polkadot 0.2.0, -tron 0.2.0. Transport kits: -web-hid 1.2.4, -web-ble 1.3.2, -node-hid 1.0.1, -react-native-hid 1.0.4, -react-native-ble 1.3.2, -speculos 1.2.1, -mockserver 1.1.1.

Source: https://registry.npmjs.org/-/v1/search?text=ledgerhq%20device-signer-kit

### wallet-cli install + version

@ledgerhq/wallet-cli latest = 2.1.0 (2026-07-30). Install: `npm i -g @ledgerhq/wallet-cli` / `pnpm add -g` / `yarn global add` / `bun add -g`. Verify: `wallet-cli --version` -> 'wallet-cli v2.1.0'. It is a COMPILED BINARY: package.json has bin {wallet-cli: ./bin/wallet-cli} plus optionalDependencies @ledgerhq/wallet-cli-{darwin-arm64,linux-arm64,linux-x64,windows-x64}@2.1.0. Built with Bun + Bunli. No importable JS API.

Source: https://registry.npmjs.org/@ledgerhq/wallet-cli

### wallet-cli command surface (v2.1.0)

Command groups: account discover | assets token / token-by-id | balances | earn yields/positions/deposit/withdraw | genuine-check | operations | receive | ring init/encrypt/decrypt/keys/destroy | send | session view/reset | skill install/doctor/list/retrieve | swap quote/execute/status. Universal flags: --output json|human (human default), --dry-run on send/earn. Networks: bitcoin, ethereum(+EVM), solana. Read-only (no device, CI-safe): balances, operations, earn yields, earn positions, assets token*, session view, skill *.

Source: https://developers.ledger.com/docs/ai-tools/ledger-cli.md

### wallet-cli ring — exact semantics

Verbatim from docs: 'The Ledger Key Ring (LKRP) encrypts and decrypts data under keys tied to your Ledger device. Run `ring init` once to provision the key ring via the device, and always protect it with a password. After that, `ring encrypt` and `ring decrypt` need network access to restore the trustchain, but no device.' Keys are AES-256-GCM derived per-name with HKDF-SHA256 from the LKRP-shared root key. `--key <name>` is mandatory and must match at decrypt; names are free-form, max 253 chars, no whitespace. Files via -i/-o; text via stdin/stdout. `ring keys` lists keys this machine used; `ring destroy` removes local credentials AND the remote LKRP application. `ring init --name my-laptop` names the machine. `ring init --unsecure-no-password` leaves the ring unprotected (docs: 'do not use it for anything holding real data').

Source: https://developers.ledger.com/docs/ai-tools/ledger-cli.md

### wallet-cli ring — password injection for agents/CI

'The `ring` commands read the password from the WALLET_PASS environment variable whenever there is no interactive terminal, which is the case in CI and when an agent runs the command.' Docs mandate command substitution, never a literal: macOS store once `security add-generic-password -a default -s ledger-wallet-cli -w`; inject `WALLET_PASS=$(security find-generic-password -a default -s ledger-wallet-cli -w) wallet-cli ring init`. Linux: `WALLET_PASS=$(secret-tool lookup service ledger-wallet-cli account default) wallet-cli ring encrypt --key my-key -i secrets.txt -o secrets.enc`. Warning: 'When an agent drives the CLI, it must never choose, type, or otherwise handle the password value.'

Source: https://developers.ledger.com/docs/ai-tools/ledger-cli.md

### wallet-cli ring — key rotation caveat

From the wallet-cli agent skill: 'the domain key derives from the ring's wallet-sync encryption key, which the LKRP protocol rotates when a ring member is removed. After a rotation, data encrypted before it can no longer be decrypted' — decrypt fails with 'wrong key name, corrupted data, or the Ledger Key Ring rotated' and the CLI prints '⚠ Ledger Key Ring rotated'. Re-encrypt after removing a member. `ring destroy` aborts with no changes on a wrong password AND if WALLET_PASS is set but empty (treated as a failed keychain lookup, not a skip).

Source: https://github.com/LedgerHQ/agent-skills/blob/main/skills/wallet-cli/wallet-cli-usage/SKILL.md

### wallet-cli ring — sandbox requirement for agents

The official wallet-cli skill states: 'account discover, receive, send, genuine-check, swap execute, ring encrypt, ring decrypt, ring keys, ring destroy must use dangerouslyDisableSandbox: true — the first group is blocked by USB restrictions; the ring commands are blocked by OS keychain access restrictions.' Also: 'Never run two device commands in parallel — they fail with [object Object] or garbled APDU.'

Source: https://github.com/LedgerHQ/agent-skills/blob/main/skills/wallet-cli/wallet-cli-usage/SKILL.md

### Key Ring programmatic TS API (LKRP trusted app kit)

@ledgerhq/device-trusted-app-kit-ledger-keyring-protocol@0.5.0. `new LedgerKeyringProtocolBuilder({ dmk, applicationId: number, env?: LKRPEnv, baseUrl?: string }).withCryptoService(svc?).build()` returns `interface LedgerKeyringProtocol { authenticate(input): AuthenticateDAReturnType; encryptData(encryptionKey: Uint8Array, data: Uint8Array): Promise<Uint8Array>; decryptData(encryptionKey: Uint8Array, data: Uint8Array): Promise<Uint8Array>; }`. AuthenticateUsecaseInput = { keyPair: KeyPair; clientName: string; permissions: Permissions } & ({ trustchainId: string; sessionId?: DeviceSessionId } | { trustchainId?: undefined; sessionId: DeviceSessionId }) — i.e. WITH a trustchainId the sessionId (device) is OPTIONAL. Completed output = { jwt: JWT; trustchainId: string; applicationPath: string; encryptionKey: Uint8Array }. enum LKRPEnv { PROD='prod', STAGING='staging' }. enum Permissions { OWNER=4294967295, CAN_ENCRYPT=1, CAN_DERIVE=2, CAN_ADD_BLOCK=4 }. Steps: lkrp.steps.openApp -> authenticate -> getTrustchain -> extractEncryptionKey. Default trustchain backend URL found in the bundle: https://trustchain.api.live.ledger.com/v1 . Crypto: NobleCryptoService (Curve.K256/P256, EncryptionAlgo.AES256_GCM, HashAlgo.SHA256), NobleKeyPair.generate(curve) / NobleKeyPair.from(privateKey, curve). Note: the npm README for this package is an empty skeleton (all sections blank) — the .d.ts files are the only documentation.

Source: https://registry.npmjs.org/@ledgerhq/device-trusted-app-kit-ledger-keyring-protocol

### DMK Skills — what they are and where they live

DMK Skills are plain Markdown instruction files (SKILL.md with YAML frontmatter containing only `name` and `description`) in github.com/LedgerHQ/agent-skills (default branch main, last push 2026-09-08). Layout: skills/dmk/manifest.json ; skills/dmk/dmk-intent-vocabulary/SKILL.md ; skills/dmk/dmk-business-logic/SKILL.md ; skills/dmk/ledger-dmk-implementation/{SKILL.md, dmk-sdk-reference.md, dmk-code-patterns.md, dmk-platform-patterns.md} ; skills/wallet-cli/wallet-cli-usage/{SKILL.md, references/business-logic.md}. The manifest declares name, displayName, description, version 1.0.0, sdkPackage '@ledgerhq/device-management-kit', a skills[] array with per-skill referenceFiles, and a concatenationOrder[].

Source: https://github.com/LedgerHQ/agent-skills

### DMK Skills — install commands

All three DMK skills: `npx skills add ledgerhq/agent-skills -s ledger-dmk-implementation dmk-intent-vocabulary dmk-business-logic`. Shorthand on the overview page: `npx skills add ledgerhq/agent-skills`. wallet-cli skill: `npx skills add LedgerHQ/agent-skills -s wallet-cli-usage` (add -g for global), or from the installed binary `wallet-cli skill install --agent claude|cursor|codex|agents` (+ --global, --dir, --force) and `wallet-cli skill doctor [--fix] [--force]`. The installer is the npm package `skills` (latest 1.5.26, 2026-09-11), bins `skills` and `add-skill`.

Source: https://developers.ledger.com/docs/ai-tools/ledger-dmk-skills.md

### wallet-cli embedded skill + provenance

Since wallet-cli 2.1.0 the agent skill ships embedded in the compiled binary. `skill install` maps --agent to .<agent>/skills under cwd (agents -> .agents/skills), or $HOME with --global; --dir overrides. On install it writes a provenance sidecar `.wallet-cli-skill.json` next to each skill recording wallet-cli version + content hash. `skill doctor` classifies each installed skill as up-to-date / outdated / modified-locally / missing and exits non-zero on drift; --fix reinstalls outdated+missing, --force also overwrites local edits. A one-time first-run nudge prints to stderr only, is silent under --output json, and is disabled with WALLET_CLI_NO_NUDGE=1.

Source: https://registry.npmjs.org/@ledgerhq/wallet-cli

### Clear Signing — what it is and who owns it now

Clear Signing is defined by ERC-7730. A protocol author writes a JSON descriptor mapping each contract function or EIP-712 message to human-readable fields; it is published to an open registry; at signing time a compatible wallet fetches the matching descriptor and renders it on the signer's Secure Screen. 'Clear Signing never modifies the transaction; it adds a display layer that is verified on the signer itself.' On 2026-05-12 Ledger transferred stewardship to the Ethereum Foundation (Trillion Dollar Security Initiative). Registry: https://github.com/ethereum/clear-signing-erc7730-registry . Canonical home: https://clearsigning.org . Spec: https://eips.ethereum.org/EIPS/eip-7730

Source: https://developers.ledger.com/docs/clear-signing/overview.md

### ERC-7730 descriptor structure

Three sections: context (what it binds to — contract.abi + contract.deployments[{chainId,address}], optional addressMatcher/factory; or eip712.schemas + optional eip712.domain/deployments), metadata (owner required; info{url,legalName,deploymentDate}; enums; constants; token{ticker,name,decimals}), display (display.formats keyed by function, each with intent + fields[]). Field keys may be a Solidity declaration 'transfer(address _to,uint256 _value)', a canonical signature 'transfer(address,uint256)', or a 4-byte selector '0xa9059cbb'. Every parameter must appear in fields or excluded.

Source: https://developers.ledger.com/docs/clear-signing/reference/erc7730-reference.md

### ERC-7730 format types and path roots

Formats: raw | amount (native currency) | tokenAmount (params tokenPath or token, optional threshold + message) | nftName (collectionPath or collection) | date (encoding: timestamp|blockheight) | duration | addressOrName (optional type) | enum ($ref to $.metadata.enums.NAME) | unit (params.unit). Path roots: '#' = the structured data being signed (decoded calldata params / EIP-712 fields, e.g. #.amount); '$' = values in the merged ERC-7730 file (e.g. $.metadata.constants.stETHaddress); '@' = transaction envelope container fields (@.to, @.value). A bare path is equivalent to '#.'. Array/byte slicing: tokens[], tokens[0], data[4:], data[:32].

Source: https://developers.ledger.com/docs/clear-signing/reference/erc7730-reference.md

### ERC-7730 versioning

Ledger docs note verbatim: 'Ledger's tools and the registry currently target ERC-7730 v1. Version 2 is in draft.' HOWEVER the live registry README and real descriptors (e.g. registry/lido/calldata-stETH.json) use "$schema": "../../specs/erc7730-v2.schema.json" and the PR requirement is validation against specs/erc7730-v2.schema.json. The Ledger doc page is behind the registry. v2 descriptors add interpolatedIntent and params.sources/types on addressName.

Source: https://github.com/ethereum/clear-signing-erc7730-registry/blob/master/README.md

### ERC-7730 registry submission rules

Layout: registry/$entity/calldata-$contractName.json, eip712-$messageName.json, common-$shared.json (no calldata/eip712 prefix for includes), testsv2/$name.tests.json, sigs/$name.eip155-1-0x$auditor.json. PR rules: one entity per PR; at least one ERC-7730-compatible file at the entity root; prefixed calldata- or eip712-; must validate against specs/erc7730-v2.schema.json; every descriptor added/changed needs a test file with at least one test case per function in display.formats (CI derives each format's selector and looks for it in the test calldata). Reviewers use docs/REVIEWING.md.

Source: https://github.com/ethereum/clear-signing-erc7730-registry/blob/master/README.md

### erc7730 validation tooling

Python package `erc7730` (Python 3.12+). `pip install erc7730` then: `erc7730 lint registry/uniswap/calldata-UniswapV3Router02.json`, `erc7730 format`, `erc7730 generate --address 0xContractAddress --chain-id 1 --owner "Entity Name" --url "https://entity.url"`. Or ad-hoc with uv: `uvx erc7730 lint <file>` / `uv tool install erc7730`. PyPI: https://pypi.org/project/erc7730/

Source: https://github.com/ethereum/clear-signing-erc7730-registry/blob/master/README.md

### originToken — gates Clear Signing

Verbatim from the wallet-integration guide: 'Wallet integration requires enrollment in Ledger's partner program to obtain an originToken.' and 'The default context module requires an originToken. It identifies your application to Ledger's security services and enables Clear Signing along with the other transaction security features — Transaction Check and Web3 checks, and trusted names. Without a valid token, those features are unavailable.' Passed as `new SignerEthBuilder({ dmk, sessionId, originToken: 'your-origin-token' }).build()`. Request form: https://docs.google.com/forms/d/e/1FAIpQLSe4xsr-KzPhQdaYMlNe9r9hY7XPZvbwFPutYOx6p3GOW4ALsg/viewform

Source: https://developers.ledger.com/docs/clear-signing/for-wallets.md

### Ethereum derivation paths + the m/ trap

Ledger Live ETH path: 44'/60'/{account}'/0/0 . MetaMask-style: 44'/60'/0'/0/{index} . Solana: 44'/501'/{account}'/0' . BTC native segwit: 84'/0'/{account}' . CRITICAL: never use an 'm/' prefix — DerivationPathUtils.splitPath splits on '/' and parseInt('m') is NaN, throwing 'invalid number provided' with no hint at the cause. Applies to all chains and all signer kits.

Source: https://github.com/LedgerHQ/agent-skills/blob/main/skills/dmk/ledger-dmk-implementation/dmk-sdk-reference.md

### Device error codes / rejection detection

User rejection is not one error type. RefusedByUserDAError (_tag, ETH device-action layer); errorCode '5501' (global ActionRefusedError); '6985' (conditions of use not satisfied, generic); '6982' (Solana canceled by user). UnknownDeviceExchangeError buries errorCode in error.originalError.errorCode — always check `error?.errorCode ?? error?.originalError?.errorCode`. Other: DeviceLockedError / 5515 locked; 6807 app not installed; 6a80 blind signing not enabled; 6e00 wrong app open; 6d00 INS not supported; DeviceDisconnectedWhileSendingError; SendApduTimeoutError; NoAccessibleDeviceError; OpeningConnectionError.

Source: https://github.com/LedgerHQ/agent-skills/blob/main/skills/dmk/ledger-dmk-implementation/dmk-sdk-reference.md

### Session and signer lifecycle rules

Sessions are chain-agnostic: one sessionId works with any signer kit without reconnecting. Signer instances must be recreated when sessionId changes (reconnection) — do not reuse across sessions. One DMK instance per application/process (each nodeHidTransportFactory registers USB hotplug listeners; multiple instances stack them). Secure-channel actions (GenuineCheck, ListInstalledApps, InstallApp, UninstallApp) need a live WebSocket to Ledger's HSM backend — not available offline. AllowSecureConnection is prompted once per device reboot.

Source: https://github.com/LedgerHQ/agent-skills/blob/main/skills/dmk/ledger-dmk-implementation/dmk-sdk-reference.md

### Ledger Wallet Provider — actual package name

The docs page names '@ledgerhq/ledger-wallet-provider-evm' and '@ledgerhq/ledger-wallet-provider-solana'. NEITHER EXISTS ON NPM (404). The real published package is @ledgerhq/ledger-wallet-provider@1.4.2 (2026-08-18) plus @ledgerhq/ledger-wallet-provider-core@1.4.2. Install: `npm install @ledgerhq/ledger-wallet-provider` and import '@ledgerhq/ledger-wallet-provider/styles.css'. It is a Lit web-components library exposing an EIP-1193 provider via EIP-6963. Entry point: `initializeLedgerProvider({ devConfig, target, dAppIdentifier, apiKey, floatingButtonPosition, walletTransactionFeatures, loggerLevel, dmkConfig })` returning a cleanup fn; then `window.dispatchEvent(new Event('eip6963:requestProvider'))`. Browser-only, NO SSR, no mobile browsers (WebHID/WebBLE unavailable on iOS/Android). Requires a Ledger apiKey.

Source: https://registry.npmjs.org/@ledgerhq/ledger-wallet-provider

### DOC BUG — signTransaction arity in the wallet guide

The Clear Signing for-wallets page shows `const signature = await signerEth.signTransaction(transaction);` — wrong on two counts: signTransaction takes (derivationPath, transaction, options?) and returns { observable, cancel }, not a promise.

Source: https://developers.ledger.com/docs/clear-signing/for-wallets.md

### DOC BUG — Speculos described as TCP

The dmk-business-logic skill's transport table says 'Speculos | TCP socket to emulator | Development/CI only'. The shipped @ledgerhq/device-transport-kit-speculos is HTTP/SSE (POST /apdu, GET /events). Good DX feedback item for the bounty.

Source: https://github.com/LedgerHQ/agent-skills/blob/main/skills/dmk/dmk-business-logic/SKILL.md

### Stale version table in the official skill

dmk-sdk-reference.md's 'Compatible Package Versions' table lists DMK 1.2.0, web-hid 1.2.3, ETH signer 1.12.0, BTC signer 1.3.0, Solana signer 1.7.1 as 'known-working'. Actual latest as of 2026-09-12: DMK 1.9.0, web-hid 1.2.4, ETH 1.18.0, BTC 1.3.3, Solana 1.13.0. The skill itself advises 'Always use the npm type definitions as the source of truth — not the GitHub source.'

Source: https://github.com/LedgerHQ/agent-skills/blob/main/skills/dmk/ledger-dmk-implementation/dmk-sdk-reference.md

### ETH signer address book (new in 1.18.0)

SignerEthBuilder.withAddressBook(addressBook: EvmAddressBook) makes the device show a saved contact name instead of the raw recipient address. Shape: { contactGroups: [{ contactName, groupHandle, hmacProof, externalAddresses: [{ scope: 'Ethereum', address, chainId: 1n, hmacRest }] }], ledgerAccounts: [] }. Rules: snapshot must be complete and is read as-is (rebuild the signer to change it); EVM entries only; matches on address AND chainId and only against the transaction recipient (a recipient inside ERC-20 transfer calldata still shows raw); a match replaces the ENS trusted name; nothing here can break a signature.

Source: https://registry.npmjs.org/@ledgerhq/device-signer-kit-ethereum

### Ledger device app names for chain routing

Ethereum/EVM -> app 'Ethereum' + SignerEthBuilder; Bitcoin -> 'Bitcoin' + SignerBtcBuilder; Solana -> 'Solana' + SignerSolanaBuilder; Cosmos -> 'Cosmos'; Hyperliquid -> 'Hyperliquid'; Aleo -> 'Aleo'; Zcash -> 'Zcash'. Security Key (FIDO2) app is opened with new OpenAppCommand('Security Key'). Dashboard/no-app shows state.currentApp.name as 'BOLOS' or 'Dashboard'.

Source: https://github.com/LedgerHQ/agent-skills/blob/main/skills/dmk/ledger-dmk-implementation/dmk-sdk-reference.md

### Linux prerequisites for node-hid

wallet-cli README: on Linux install USB/HID build deps — `sudo apt-get update && sudo apt-get install libudev-dev libusb-1.0-0-dev`. The DMK skill adds that Linux users may need udev rules (https://github.com/AUR/ledger-udev-rules).

Source: https://registry.npmjs.org/@ledgerhq/wallet-cli

## Code and commands

### Install — Bun, Speculos-first (recommended primary path)

context-module is a hard peer dep of the eth signer and is imported internally — omit it and the build fails with "Module not found: Can't resolve '@ledgerhq/context-module'". context-module@2.5.0 declares an exact stale peer on device-management-kit@0.9.2, so npm needs --legacy-peer-deps; Bun and pnpm tolerate it. rxjs must be exactly 7.8.2 (peer deps pin the exact version, not a range).

```bash
# core + transports + eth signer
bun add @ledgerhq/device-management-kit@1.9.0 \
  @ledgerhq/device-transport-kit-speculos@1.2.1 \
  @ledgerhq/device-signer-kit-ethereum@1.18.0 \
  @ledgerhq/context-module@2.5.0 \
  rxjs@7.8.2 reflect-metadata@0.2.2

# optional: real USB hardware (native, CJS-only — see notes)
bun add @ledgerhq/device-transport-kit-node-hid@1.0.1

# optional: programmatic Key Ring / LKRP
bun add @ledgerhq/device-trusted-app-kit-ledger-keyring-protocol@0.5.0

# CLI + agent skills
npm i -g @ledgerhq/wallet-cli            # v2.1.0, compiled binary
npx skills add ledgerhq/agent-skills -s ledger-dmk-implementation dmk-intent-vocabulary dmk-business-logic
npx skills add -g LedgerHQ/agent-skills -s wallet-cli-usage
```

### DMK singleton — Speculos transport (no hardware, no native modules)

Signature from lib/types: (speculosUrl?: string, isE2E?: boolean, deviceModelId?: DeviceModelId) => TransportFactory. Import "reflect-metadata" once at the process entry — inversify needs it. Build exactly one DMK per process and call dmk.close() on shutdown.

```typescript
// src/dmk.ts
import "reflect-metadata";
import {
  ConsoleLogger,
  DeviceManagementKitBuilder,
} from "@ledgerhq/device-management-kit";
import {
  speculosTransportFactory,
  speculosIdentifier, // === "SPECULOS_HTTP_TRANSPORT"
} from "@ledgerhq/device-transport-kit-speculos";

const SPECULOS_URL = process.env.SPECULOS_URL ?? "http://localhost:5000";

// NOTE: speculosTransportFactory is a FUNCTION returning a TransportFactory —
// it MUST be called. nodeHidTransportFactory / webHidTransportFactory are NOT.
export const dmk = new DeviceManagementKitBuilder()
  .addLogger(new ConsoleLogger())
  .addTransport(speculosTransportFactory(SPECULOS_URL))
  .build();

export const TRANSPORT = speculosIdentifier;
```

### DMK singleton — real USB via node-hid

Asymmetry with Speculos is real and will bite you: nodeHid/webHid factories are passed uncalled, speculosTransportFactory must be invoked. This package is CJS-only (exports map both import and require to lib/cjs) and depends on native node-hid@^3.2.0 + usb@^2.16.0. Keep it in a separate module behind a dynamic import so a Bun/ESM build of the Speculos path never touches it.

```typescript
// src/dmk-usb.ts
import "reflect-metadata";
import { DeviceManagementKitBuilder } from "@ledgerhq/device-management-kit";
import {
  nodeHidTransportFactory, // a TransportFactory value — pass UNCALLED
  nodeHidIdentifier,       // === "NODE-HID"
} from "@ledgerhq/device-transport-kit-node-hid";

export const dmk = new DeviceManagementKitBuilder()
  .addTransport(nodeHidTransportFactory)
  .build();

export const TRANSPORT = nodeHidIdentifier;
```

### Connect (headless/CLI) — listenToAvailableDevices, no browser picker

DeviceStatus values: CONNECTED | LOCKED | BUSY | NOT_CONNECTED. Extra session fields (currentApp, batteryStatus) only exist when state.sessionStateType !== DeviceSessionStateType.Connected. Battery is unreliable over USB.

```typescript
import { firstValueFrom, filter, take, timeout } from "rxjs";
import {
  DeviceStatus,
  type DeviceSessionId,
} from "@ledgerhq/device-management-kit";
import { dmk, TRANSPORT } from "./dmk";

const TIMEOUT_MS = 60_000;

export async function openSession(): Promise<DeviceSessionId> {
  // Passive watch — correct for Node/Bun. startDiscovering() is the browser path
  // and must be triggered from a user gesture there.
  const devices = await firstValueFrom(
    dmk.listenToAvailableDevices({ transport: TRANSPORT }).pipe(
      filter((list) => list.length > 0),
      timeout(TIMEOUT_MS),
    ),
  );

  if (devices.length > 1) {
    throw new Error("Multiple Ledger devices — refusing to pick autonomously");
  }

  // REAL 1.9.0 signature: { device, sessionRefresherOptions? }
  // (the docs' `{ deviceId }` form does not compile)
  const sessionId = await dmk.connect({
    device: devices[0]!,
    sessionRefresherOptions: { isRefresherDisabled: false, pollingInterval: 3000 },
  });

  const state = await firstValueFrom(
    dmk.getDeviceSessionState({ sessionId }).pipe(take(1)),
  );
  if (state.deviceStatus === DeviceStatus.LOCKED) {
    process.stderr.write("Device locked — enter your PIN\n");
    await firstValueFrom(
      dmk.getDeviceSessionState({ sessionId }).pipe(
        filter((s) => s.deviceStatus !== DeviceStatus.LOCKED),
        take(1),
        timeout(TIMEOUT_MS),
      ),
    );
  }
  return sessionId;
}
```

### Observable -> promise helper (every signer call returns { observable, cancel })

UnknownDeviceExchangeError hides errorCode inside originalError — always check both. Treat rejection as a distinct outcome, not an error.

```typescript
import { firstValueFrom, filter, map } from "rxjs";
import {
  DeviceActionStatus,
  UserInteractionRequired,
} from "@ledgerhq/device-management-kit";

export function runAction<T>(action: {
  observable: any;
  cancel: () => void;
}): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    action.observable.subscribe({
      next: (state: any) => {
        switch (state.status) {
          case DeviceActionStatus.Pending: {
            const { requiredUserInteraction, step } = state.intermediateValue;
            // HITL gate: tell the human what the device wants
            process.stderr.write(`[device] ${requiredUserInteraction}${step ? ` (${step})` : ""}\n`);
            if (requiredUserInteraction === UserInteractionRequired.UnlockDevice) {
              // escalate rather than silently waiting
            }
            break;
          }
          case DeviceActionStatus.Completed:
            resolve(state.output as T);
            break;
          case DeviceActionStatus.Error:
            reject(state.error);
            break;
          case DeviceActionStatus.Stopped:
            reject(new Error("Action cancelled on device"));
            break;
        }
      },
      error: reject,
    });
  });
}

export function isDeviceRejection(error: unknown): boolean {
  const tag = (error as any)?._tag ?? "";
  const code =
    (error as any)?.errorCode ?? (error as any)?.originalError?.errorCode ?? "";
  return (
    tag === "RefusedByUserDAError" ||
    code === "5501" || // global ActionRefusedError
    code === "6985" || // conditions of use not satisfied
    code === "6982"    // Solana: canceled by user
  );
}
```

### Sign an EIP-1559 transaction — viem (exact bytes the signer expects)

Verified against the signer's internal EthersTransactionMapperService, which does ethers.Transaction.from(hex) then getBytes(tx.unsignedSerialized) — so any ethers-parseable serialized unsigned typed tx works. chainId <= 0 returns Left('Pre-EIP-155 transactions are not supported'). The v -> yParity mapping is my inference from EIP-1559 semantics; assert recovery by comparing recoverAddress(raw) against getAddress() output before you broadcast.

```typescript
import { serializeTransaction, parseGwei, parseEther, hexToBytes,
         type TransactionSerializableEIP1559 } from "viem";
import { SignerEthBuilder } from "@ledgerhq/device-signer-kit-ethereum";
import { dmk } from "./dmk";
import { runAction } from "./run-action";

const DERIVATION_PATH = "44'/60'/0'/0/0"; // NEVER prefix with "m/"

export async function signEip1559(sessionId: string) {
  // REAL constructor arg is `dmk` (the npm README's `sdk` is wrong)
  const signerEth = new SignerEthBuilder({
    dmk,
    sessionId,
    originToken: process.env.LEDGER_ORIGIN_TOKEN, // needed for Clear Signing
  }).build();

  const tx: TransactionSerializableEIP1559 = {
    type: "eip1559",
    chainId: 1,                       // MUST be > 0 (pre-EIP-155 is rejected)
    nonce: 42,
    to: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    value: parseEther("0.01"),
    data: "0x",
    gas: 21_000n,
    maxFeePerGas: parseGwei("30"),
    maxPriorityFeePerGas: parseGwei("1.5"),
  };

  // Unsigned serialization: viem omits r/s/v when no signature is supplied.
  const unsignedHex = serializeTransaction(tx);        // "0x02f8..."
  const txBytes = hexToBytes(unsignedHex);             // Uint8Array

  const sig = await runAction<{ r: `0x${string}`; s: `0x${string}`; v: number }>(
    signerEth.signTransaction(DERIVATION_PATH, txBytes),
  );

  // Re-serialize WITH the signature to get a broadcastable raw tx
  const raw = serializeTransaction(tx, {
    r: sig.r,
    s: sig.s,
    yParity: sig.v & 1, // device returns v; EIP-1559 wants yParity 0/1
  });
  return { sig, raw };
}
```

### Same thing with ethers v6 (the signer's own internal parser)

ethers 6.14.1 is already a direct dependency of device-signer-kit-ethereum, so this adds no new install. This is byte-for-byte what the signer does internally, so it is the lowest-risk path.

```typescript
import { Transaction, getBytes, parseEther, parseUnits } from "ethers";

const tx = Transaction.from({
  type: 2,
  chainId: 1,
  nonce: 42,
  to: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  value: parseEther("0.01"),
  data: "0x",
  gasLimit: 21_000n,
  maxFeePerGas: parseUnits("30", "gwei"),
  maxPriorityFeePerGas: parseUnits("1.5", "gwei"),
});

const txBytes = getBytes(tx.unsignedSerialized);
// ... signerEth.signTransaction(path, txBytes) ...
// then, to broadcast:
// tx.signature = { r: sig.r, s: sig.s, v: sig.v };  const raw = tx.serialized;
```

### Detect and refuse blind signing (strong bounty differentiator)

SignTransactionDAStep is exported from the package root. Full enum: OPEN_APP, GET_APP_CONFIG, GET_ADDRESS, WEB3_CHECKS_OPT_IN, WEB3_CHECKS_OPT_IN_RESULT, PARSE_TRANSACTION, BUILD_CONTEXTS, PROVIDE_CONTEXTS, SIGN_TRANSACTION, BLIND_SIGN_TRANSACTION_FALLBACK, DETECT_BLIND_SIGNING. This turns "clear boundaries between autonomous behavior and explicit approval" from a claim into enforced code.

```typescript
import { DeviceActionStatus } from "@ledgerhq/device-management-kit";
import { SignTransactionDAStep } from "@ledgerhq/device-signer-kit-ethereum";

const { observable, cancel } = signerEth.signTransaction(path, txBytes);

const sub = observable.subscribe((state) => {
  if (state.status === DeviceActionStatus.Pending) {
    const step = (state.intermediateValue as any).step;
    if (
      step === SignTransactionDAStep.DETECT_BLIND_SIGNING ||
      step === SignTransactionDAStep.BLIND_SIGN_TRANSACTION_FALLBACK
    ) {
      // No ERC-7730 descriptor for this contract: the human would be asked to
      // approve raw hex. Abort instead of letting the agent push it through.
      cancel();
      sub.unsubscribe();
      throw new Error("Refusing to blind-sign: no clear-signing descriptor");
    }
  }
});
```

### Raw APDU + custom Command

Pre-built commands: OpenAppCommand, CloseAppCommand, GetOsVersionCommand, GetAppAndVersionCommand — always gate on isSuccessCommandResult(result) before touching result.data.

```typescript
import {
  ApduBuilder, ApduParser, CommandUtils, CommandResultFactory,
  GlobalCommandErrorHandler, InvalidStatusWordError,
  type Command, type CommandResult, type ApduResponse,
} from "@ledgerhq/device-management-kit";

// Raw APDU
const apdu = new ApduBuilder({ cla: 0xe0, ins: 0xd8, p1: 0x00, p2: 0x00 })
  .addAsciiStringToData("Ethereum")
  .build();
const res = await dmk.sendApdu({ sessionId, apdu });
const parser = new ApduParser(res);
if (!CommandUtils.isSuccessResponse(res)) {
  throw new Error(`SW ${parser.encodeToHexaString(res.statusCode)}`);
}

// Preferred: a typed Command
class MyCommand implements Command<{ data: string }> {
  args = undefined;
  getApdu() {
    return new ApduBuilder({ cla: 0xe0, ins: 0x02, p1: 0x00, p2: 0x00 })
      .addAsciiStringToData("payload").build();
  }
  parseResponse(response: ApduResponse): CommandResult<{ data: string }> {
    if (!CommandUtils.isSuccessResponse(response)) {
      return CommandResultFactory({ error: GlobalCommandErrorHandler.handle(response) });
    }
    const p = new ApduParser(response);
    const raw = p.extractFieldByLength(32);
    if (!raw) return CommandResultFactory({ error: new InvalidStatusWordError("Missing data") });
    return CommandResultFactory({ data: { data: p.encodeToHexaString(raw) } });
  }
}
const r = await dmk.sendCommand({ sessionId, command: new MyCommand() });
```

### Device actions (correct key is `deviceAction`, and it is NOT async)

GenuineCheck / ListInstalledApps / InstallApp / UninstallApp open a secure channel to Ledger's HSM over WebSocket — they need internet and will NOT work against Speculos or offline. Expect a one-time AllowSecureConnection prompt per device reboot.

```typescript
import {
  OpenAppDeviceAction,
  GenuineCheckDeviceAction,
  ListInstalledAppsDeviceAction,
} from "@ledgerhq/device-management-kit";

// docs show { sessionId, openAppDeviceAction } — wrong. Real key: deviceAction.
const { observable, cancel } = dmk.executeDeviceAction({
  sessionId,
  deviceAction: new OpenAppDeviceAction({ appName: "Ethereum" }),
});

const genuine = dmk.executeDeviceAction({
  sessionId,
  deviceAction: new GenuineCheckDeviceAction({ input: { unlockTimeout: 60_000 } }),
});
// Completed -> state.output.isGenuine (boolean)

const apps = dmk.executeDeviceAction({
  sessionId,
  deviceAction: new ListInstalledAppsDeviceAction({ input: { unlockTimeout: 60_000 } }),
});
// Completed -> state.output.installedApps
```

### wallet-cli ring — headless secret broker (the bounty's headline pattern)

Verified command set and flags from the docs + the official wallet-cli skill. ring encrypt/decrypt need NO device after init but DO need network. Keys are AES-256-GCM derived per --key name via HKDF-SHA256 from the LKRP root. NEVER pipe decrypt to stdout in an agent context — it lands in the transcript; always use -o or a direct pipe. Removing a ring member rotates the root key and permanently breaks older ciphertext.

```bash
# --- one-time, on a machine WITH the Ledger plugged in ---
security add-generic-password -a default -s ledger-wallet-cli -w   # macOS: store ring password
WALLET_PASS=$(security find-generic-password -a default -s ledger-wallet-cli -w) \
  wallet-cli ring init --name broker-laptop

# encrypt the agent's API keys under a named key
WALLET_PASS=$(security find-generic-password -a default -s ledger-wallet-cli -w) \
  wallet-cli ring encrypt --key agent-prod -i .env -o .env.enc
# commit .env.enc, never .env

# --- later, on a VPS / CI runner with NO USB port ---
# needs network (restores the trustchain) but NO device
export WALLET_PASS="$RING_PASSWORD_FROM_SECRET_STORE"
wallet-cli ring decrypt --key agent-prod -i .env.enc -o /dev/shm/.env
set -a; . /dev/shm/.env; set +a; shred -u /dev/shm/.env

wallet-cli ring keys      # list keys this machine has used
wallet-cli ring destroy   # wipe local creds + remote LKRP application
```

### Key Ring programmatically — device-less re-auth (broker service)

This is the programmatic equivalent of `wallet-cli ring`, and it is exactly the bounty's 'Bring the Key Ring to hosts with no USB port'. The device-less branch is guaranteed by the type: AuthenticateUsecaseInput accepts { trustchainId: string; sessionId?: DeviceSessionId }. CAVEAT: this package's npm README is an empty skeleton — every signature here came from reading the .d.ts files, and I could NOT confirm what applicationId value to use or the exact enroll/derive semantics end-to-end. Budget an hour to spike it, and keep the wallet-cli-subprocess path as your fallback demo.

```typescript
import "reflect-metadata";
import {
  LedgerKeyringProtocolBuilder,
  NobleCryptoService,
  NobleKeyPair,
  Curve,
  Permissions,
  LKRPEnv,
} from "@ledgerhq/device-trusted-app-kit-ledger-keyring-protocol";
import { dmk } from "./dmk";
import { runAction } from "./run-action";

const APPLICATION_ID = 16; // integer app id on the trustchain — see caveats

const lkrp = new LedgerKeyringProtocolBuilder({
  dmk,
  applicationId: APPLICATION_ID,
  env: LKRPEnv.PROD,          // -> https://trustchain.api.live.ledger.com/v1
}).build();

// ---------- 1. ENROLL (device required, once) ----------
const keyPair = await NobleKeyPair.generate(Curve.K256);
const enrolled = await runAction<{
  jwt: unknown; trustchainId: string; applicationPath: string; encryptionKey: Uint8Array;
}>(
  lkrp.authenticate({
    keyPair,
    clientName: "arx-broker",
    permissions: Permissions.OWNER,
    sessionId,                 // <- device present
  }),
);
// Persist enrolled.trustchainId + the RAW PRIVATE KEY of keyPair securely.
// This pair IS the host's membership credential.

// ---------- 2. RE-AUTH ON A USB-LESS HOST (no device) ----------
const crypto = new NobleCryptoService();
const restored = crypto.importKeyPair(savedPrivateKeyBytes, Curve.K256);
const session = await runAction<{ encryptionKey: Uint8Array; jwt: unknown }>(
  lkrp.authenticate({
    keyPair: restored,
    clientName: "arx-broker-vps",
    permissions: Permissions.CAN_ENCRYPT,
    trustchainId: enrolled.trustchainId,   // sessionId omitted -> no device
  }),
);

// ---------- 3. USE ----------
const blob = await lkrp.encryptData(session.encryptionKey, new TextEncoder().encode("sk-live-..."));
const plain = await lkrp.decryptData(session.encryptionKey, blob);
```

### Complete ERC-7730 v2 descriptor (real registry file, Lido stETH)

Fetched verbatim from registry/lido/calldata-stETH.json on master. This is v2 (note interpolatedIntent, visible, addressName with params.sources/types) — the shape actually accepted by the registry today, which differs from the v1 example on Ledger's docs page. For your own contract: file at registry/<entity>/calldata-<ContractName>.json plus testsv2/calldata-<ContractName>.tests.json with at least one case per function in display.formats.

```json
{
  "$schema": "../../specs/erc7730-v2.schema.json",
  "context": {
    "$id": "stETH",
    "contract": {
      "deployments": [
        { "chainId": 1, "address": "0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84" }
      ]
    }
  },
  "metadata": {
    "owner": "Lido DAO",
    "info": { "url": "https://lido.fi" },
    "constants": { "stETHaddress": "0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84" },
    "contractName": "stETH"
  },
  "display": {
    "formats": {
      "approve(address _spender, uint256 _amount)": {
        "intent": "Approve stETH",
        "interpolatedIntent": "Allow to spend {_amount}",
        "fields": [
          {
            "label": "Spender",
            "format": "addressName",
            "params": { "types": ["contract"], "sources": ["local"] },
            "path": "#._spender",
            "visible": "always"
          },
          {
            "label": "Amount",
            "format": "tokenAmount",
            "path": "#._amount",
            "params": {
              "token": "$.metadata.constants.stETHaddress",
              "threshold": "0x8000000000000000000000000000000000000000000000000000000000000000",
              "message": "Unlimited"
            },
            "visible": "always"
          }
        ]
      },
      "submit(address _referral)": {
        "intent": "Stake ETH",
        "interpolatedIntent": "Stake {@.value}",
        "fields": [
          { "label": "Amount", "format": "amount", "path": "@.value" },
          { "label": "Referral", "path": "#._referral", "visible": "never" }
        ]
      },
      "transfer(address _recipient, uint256 _amount)": {
        "intent": "Transfer stETH",
        "interpolatedIntent": "Send {_amount} to {_recipient}",
        "fields": [
          {
            "label": "Recipient",
            "format": "addressName",
            "params": { "types": ["eoa", "wallet"], "sources": ["local", "ens"] },
            "path": "#._recipient",
            "visible": "always"
          },
          {
            "label": "Amount",
            "format": "tokenAmount",
            "path": "#._amount",
            "params": { "token": "$.metadata.constants.stETHaddress" },
            "visible": "always"
          }
        ]
      }
    }
  }
}
```

### ERC-7730 authoring + validation loop

`uvx erc7730` needs no install step (uv). Or: pip install erc7730 (Python 3.12+). CI derives each format's 4-byte selector and greps the test calldata for it, so a missing test case fails the PR.

```bash
git clone https://github.com/ethereum/clear-signing-erc7730-registry
cd clear-signing-erc7730-registry

# generate a starting descriptor from a verified contract
uvx erc7730 generate --address 0xYourContract --chain-id 1 \
  --owner "Arx" --url "https://arx.example"

# validate + canonicalize
uvx erc7730 lint registry/arx/calldata-ArxBroker.json
uvx erc7730 format

# PR rules: one entity per PR, files prefixed calldata-/eip712-,
# must validate against specs/erc7730-v2.schema.json, and each descriptor
# needs testsv2/<name>.tests.json covering every function in display.formats.
```

### Speculos — run the emulator the DMK transport expects

CONFIRMED from the transport source: it POSTs {baseUrl}/apdu with JSON { data: <hex> } and probes {baseUrl}/events. NOT CONFIRMED: the exact docker image tag / flag spelling and where to get a prebuilt Ethereum app .elf — verify against github.com/LedgerHQ/speculos before relying on this. Also note the Speculos device has no user to press buttons: for signing flows you must drive the emulator's button/touch endpoints or use isE2E=true in speculosTransportFactory.

```bash
# Speculos exposes the HTTP API the DMK transport uses: POST /apdu, GET /events
docker run --rm -it -p 5000:5000 \
  -v "$PWD/apps:/apps" \
  ghcr.io/ledgerhq/speculos \
  --model nanosp --display headless --api-port 5000 \
  /apps/ethereum.elf

# smoke-test the exact endpoint the transport hits (GetAppAndVersion)
curl -s -X POST http://localhost:5000/apdu \
  -H 'Content-Type: application/json' \
  -d '{"data":"b001000000"}'
```

## Unverified — do not rely on these

- Bun compatibility of @ledgerhq/device-transport-kit-node-hid. It is CJS-only and depends on native node-hid@^3.2.0 + usb@^2.16.0; its README says 'tested successfully on Node v20' and the DMK skill says 'DMK packages are ESM-only — use type: module'. I did not run `bun add` or `bun run` against it. Verify early: if it fails, the skill documents a fallback (a custom Transport over the `usb` package's WebUSB API, LEDGER_VENDOR_ID 0x2c97, 64-byte frames, endpoint 3, configuration value 1) — but that is a real implementation, not a drop-in.
- The correct `applicationId` integer to pass to LedgerKeyringProtocolBuilder. The type says `applicationId: number` and the LKRP spec link points to a private Ledger Atlassian wiki page. I could not find the value wallet-cli uses (the binary is compiled). Without it, enrollment may land on the wrong trustchain application.
- Whether the device-less LKRP re-authenticate path actually works end-to-end with only a persisted keypair + trustchainId. The TYPE permits it (sessionId optional when trustchainId is present) and wallet-cli's device-less `ring encrypt/decrypt` is strong evidence, but I did not execute it. I also could not confirm how the ring PASSWORD fits the programmatic API — `authenticate()` takes no password parameter, so the wallet-cli password may protect a locally stored keypair rather than the protocol itself.
- Which device app `ring init` opens. The wallet-cli skill says the ring 'is provisioned once on your Ledger via the Ledger Sync app'; the LKRP kit has an lkrp.steps.openApp step but I could not read the app name string out of the bundle. If the Ledger Sync app is not installed, `ring init` may fail.
- Whether `wallet-cli ring init` works against Speculos or requires real hardware. Everything points to real hardware over USB (the CLI is 'USB-based'), which means the ring half of a demo cannot be emulated.
- Speculos specifics: the exact container image/tag, CLI flag spelling, and where to obtain a prebuilt Ethereum app .elf. Also unconfirmed: how to drive on-device approval under Speculos for signTransaction — whether `isE2E: true` in speculosTransportFactory auto-approves, or whether you must POST to Speculos' button/touch endpoints. The transport's `isE2E?: boolean` and `openEventStream` suggest one of these, but nothing documents it.
- Whether the Ethereum app running under Speculos will Clear Sign. Clear Signing needs the context module to fetch descriptors from Ledger's backend using a valid originToken; with no token the signer falls back to blind signing. So a Speculos-only demo may only ever show blind signing.
- How to obtain an originToken in time. The docs route it through a Google Form and 'Ledger's partner program' with no stated SLA — almost certainly longer than the 24 hours to deadline.
- The @ledgerhq/ledger-wallet-provider apiKey: what it gates, whether it is required, and how to get one. The README shows apiKey: 'your-api-key' with no acquisition path.
- Whether 'npx skills add ledgerhq/agent-skills' installs into Claude Code's skill directory in a way this project can consume, and what the resulting on-disk layout is. I read the source SKILL.md files directly from GitHub rather than running the installer. Note the agent-skills root README has a broken command referencing a non-existent repo: 'npx skills add -g LedgerHQ/developer-ai-skills -s wallet-cli-usage' (correct repo is LedgerHQ/agent-skills) — good DX-feedback material.
- The v -> yParity conversion when re-serializing an EIP-1559 transaction from the device's { r, s, v }. The device returns `v: number`; I inferred yParity = v & 1. Verify by recovering the sender from your serialized raw tx and comparing it to signerEth.getAddress() before broadcasting anything.
- Exact per-flag help output for `wallet-cli ring init|encrypt|decrypt|keys|destroy`. I have --name, --key, -i, -o, --unsecure-no-password and --output from docs and the skill, but I did not run `wallet-cli ring <cmd> --help` (the CLI is a platform-specific compiled binary I did not install).
- Whether '@ledgerhq/dmk-ledger-wallet' (v0.5.0, 2026-08-24, no description, no README) is relevant. It peers on DMK ^1.8.0 and depends on pako/rxjs/xstate/semver, which smells like a Ledger-Wallet trusted-app kit, but it is entirely undocumented.
- Whether Ledger publishes an official DMK<->Speculos documentation page. The skills reference the package and 'USB Speculos' as a transport option, but I found no developers.ledger.com page covering it — another DX gap worth reporting.

## Requires a human: accounts, keys, faucets

- Install the CLI globally yourself and run it once: `npm i -g @ledgerhq/wallet-cli` then `wallet-cli --version` (expect v2.1.0). It is a platform-specific compiled binary and I did not install it.
- Have a physical Ledger device (Nano S+/X, Flex, Stax) unlocked and plugged in over USB for `ring init`, `account discover`, `genuine-check`, and any real hardware signing. Install the Ethereum app via Ledger Live, and check whether the Ledger Sync app is needed for the ring.
- Store the ring password in your OS keychain BEFORE any agent touches the CLI: macOS `security add-generic-password -a default -s ledger-wallet-cli -w`; Linux use secret-tool. Then run `WALLET_PASS=$(security find-generic-password -a default -s ledger-wallet-cli -w) wallet-cli ring init --name <host>` yourself. Per Ledger's own guidance an agent must never choose, type, or handle the password value.
- Decide and provision the secret store for the USB-less host (VPS/CI) that will hold the ring password — GitHub Actions secret, Doppler, systemd credential, etc. The Key Ring removes the need to host the SECRETS, not the need to deliver the ring PASSWORD.
- Apply for a Ledger partner-program originToken if you want real Clear Signing in the demo: https://docs.google.com/forms/d/e/1FAIpQLSe4xsr-KzPhQdaYMlNe9r9hY7XPZvbwFPutYOx6p3GOW4ALsg/viewform . Assume it will not arrive before the Sept 13 deadline and design the demo to degrade honestly (show a blind-signing warning rather than pretending).
- If you use @ledgerhq/ledger-wallet-provider, obtain a Ledger apiKey — the README requires one and documents no acquisition path.
- Install Docker (or Speculos locally) and obtain an Ethereum app .elf for the emulator, if you take the Speculos path.
- Install `uv` or Python 3.12+ if you want to lint an ERC-7730 descriptor (`uvx erc7730 lint`).
- Join the ETHOnline Ledger Telegram support group — it is the fastest route to the unresolved LKRP applicationId question and to Speculos approval mechanics.
- On Linux, install USB/HID build deps before node-hid: `sudo apt-get install libudev-dev libusb-1.0-0-dev`, plus udev rules.
- Write the mandatory Developer Experience feedback yourself (a real submission requirement, judged equally with code). The doc bugs listed in confirmed_facts are ready-made material: connect({deviceId}), executeDeviceAction({openAppDeviceAction}), SignerEthBuilder({sdk}), the non-existent @ledgerhq/ledger-wallet-provider-evm / -solana package names, the Speculos README's wrong import path, the empty LKRP README, the stale version table in the official skill, Speculos mislabeled as TCP, and the broken 'LedgerHQ/developer-ai-skills' command in the agent-skills README. Consider filing them as PRs for bonus points.

## Recommendations

- Pin exact versions in package.json and do NOT float: device-management-kit 1.9.0, device-signer-kit-ethereum 1.18.0, context-module 2.5.0, device-transport-kit-speculos 1.2.1, rxjs 7.8.2. The @ledgerhq packages publish a 0.0.0-develop-<date> build DAILY (874+ versions of DMK alone); a caret range will drift under you mid-hackathon. Install context-module unconditionally — the ETH signer imports it internally and the build fails without it. On npm you will need --legacy-peer-deps because context-module@2.5.0 still declares an exact peer on device-management-kit@0.9.2.
- Build against Speculos first, hardware second. Put the transport behind one module boundary (`makeDmk(kind: 'speculos' | 'nodehid')`) and dynamically import the node-hid module only in the hardware branch. Speculos is pure ESM/CJS with zero native deps; node-hid is CJS-only with two native addons and is the single most likely thing to eat hours on Bun. Remember the asymmetry: `speculosTransportFactory(url)` is CALLED, `nodeHidTransportFactory` is passed UNCALLED.
- Write your code from the .d.ts files, not the docs. Four of the doc/README snippets you would naturally copy do not compile against 1.9.0/1.18.0: connect({deviceId}) -> connect({device}); executeDeviceAction({sessionId, openAppDeviceAction}) -> ({sessionId, deviceAction}); SignerEthBuilder({sdk,...}) -> ({dmk,...}); signerEth.signTransaction(transaction) -> (derivationPath, transaction, options?) returning {observable, cancel} not a promise. Extract the tarballs (`npm pack` / curl the registry tarball) and read lib/types — it is 10 minutes and saves an evening.
- Make blind-signing refusal your headline feature. Subscribe to the signTransaction observable and hard-abort on SignTransactionDAStep.DETECT_BLIND_SIGNING or BLIND_SIGN_TRANSACTION_FALLBACK. This is machine-enforced, demoable in 30 seconds, and speaks directly to two judging criteria at once ('clear boundaries between autonomous behavior and explicit approval', 'concrete use of Ledger primitives, not just wallet branding'). No other team is likely to do it.
- For the 'broker hands out scoped capabilities, never the API key' brief, ship the wallet-cli subprocess version FIRST and treat the programmatic LKRP kit as a stretch. `wallet-cli ring decrypt --key <name> -i x.enc -o -` driven from a Bun broker that (a) never returns the plaintext to the agent, (b) only ever performs the scoped call on the agent's behalf, and (c) returns a short-lived handle, is a complete, defensible demo built entirely on documented behavior. The LKRP TS kit is more impressive but has an undocumented applicationId and an empty README.
- Exploit the one genuinely strong Key Ring property in your pitch: after `ring init`, encrypt/decrypt need NETWORK but NOT the device, and the ring is recoverable from the seed on any machine. That is literally Track 01's 'Bring the Key Ring to hosts with no USB port' — one device tap on your laptop, then a VPS and a CI runner both decrypt with no hardware present. Record that as your walkthrough: laptop tap -> git commit of .env.enc -> VPS decrypts -> agent runs.
- Use the doc pages' `.md` twins (append .md to any developers.ledger.com/docs URL) as your in-repo reference, and commit the three DMK SKILL.md files. This makes the project self-documenting for judges, demonstrates the DMK-skills requirement concretely, and costs nothing.
- Do NOT budget time on real Clear Signing unless an originToken lands. Without it the context module cannot fetch descriptors and everything falls back to blind signing. Instead, author an ERC-7730 v2 descriptor for your own contract, validate it with `uvx erc7730 lint`, and open the registry PR — the PR itself is demonstrable Clear Signing work that needs no partner token. Copy the v2 shape from registry/lido/calldata-stETH.json, not the v1 example on Ledger's docs page, and remember testsv2/ needs a case per function or CI rejects the PR.
- Handle rejection as a first-class outcome, not an error. Use the isDeviceRejection() helper (checks _tag RefusedByUserDAError plus errorCode 5501/6985/6982 at BOTH error.errorCode and error.originalError.errorCode). Agents that retry a deliberate human 'no' are exactly the anti-pattern the judging criteria call out.
- Never prefix a derivation path with 'm/'. DerivationPathUtils calls parseInt on each segment, parseInt('m') is NaN, and you get 'invalid number provided' with zero indication of the cause. Use "44'/60'/0'/0/0". Hardcode paths as literals; never accept one from agent output.
- Guard against device contention explicitly: serialize all device-touching work through a single async queue. Two concurrent device commands fail with '[object Object]' or garbled APDU — an hour-eating bug with a useless error message. One DMK instance per process, and call dmk.close() on SIGINT/SIGTERM.
- Write the DX feedback document as you build, not at the end. It is judged equally with the code, and you already have ten concrete, verifiable findings (listed in confirmed_facts) including two non-existent npm package names in live docs. Filing even two of them as PRs against LedgerHQ/agent-skills is explicitly called out for bonus points and is probably the cheapest differentiation available.
