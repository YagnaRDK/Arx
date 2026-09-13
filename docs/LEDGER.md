# The Ledger signer boundary

Arx's authorization pipeline ends at a hardware signer. This document is the
reference for that boundary: the exact APDU commands implemented, where each
byte comes from, the four signer modes and exactly what each one proves, the
signing sequence, how to run the emulator and where its app binary comes from,
and — the part that matters most for anyone judging this — a frank separation of
what has been executed and verified from what has only been written.

The other half of the Ledger integration, the Key Ring and the capability
broker, is in [`KEYRING.md`](KEYRING.md).

**AI proposes, Arx authorizes, the device signs.** The device is a signing
boundary, not a second policy engine (invariant 9). Everything below exists to
make the final step provable rather than assumed.

---

## 1. What is implemented

| Module                                  | Role                                                           |
| --------------------------------------- | -------------------------------------------------------------- |
| `src/ledger/bip32.ts`                   | Derivation-path parsing and the app's path encoding            |
| `src/ledger/apdu.ts`                    | APDU framing, status words, the `LedgerTransport` seam         |
| `src/ledger/transport-speculos-http.ts` | APDUs over the Speculos REST API                               |
| `src/ledger/transport-speculos-tcp.ts`  | APDUs over the raw length-prefixed socket                      |
| `src/ledger/transport-simulator.ts`     | The `app-ethereum` protocol, in-process, for `SIGNER_MODE=sim` |
| `src/ledger/eth-app.ts`                 | The `app-ethereum` command set                                 |
| `src/ledger/tx-serialize.ts`            | viem-backed unsigned/signed serialization and the digest       |
| `src/ledger/speculos-control.ts`        | Emulator automation and **device-screen capture**              |
| `src/ledger/clear-signing.ts`           | ERC-7730 descriptors and screen rendering                      |
| `src/signer/*`                          | The adapters, the factory, and signature verification          |

Operational files, because the emulator path is only reproducible if the setup
is too:

| File                                | Role                                                         |
| ----------------------------------- | ------------------------------------------------------------ |
| `scripts/speculos-up.sh`            | Docker preflight, app fetch + SHA-256 verification, bring-up |
| `docker-compose.speculos.yml`       | The emulator service: model, seed, ports 5000/9999           |
| `data/ledger-apps/CHECKSUMS.sha256` | Pinned digests for every app-ethereum release asset Arx runs |

---

## 2. The APDU table

Command bytes are taken from Ledger's published specification. Nothing here was
inferred from behaviour or guessed.

Primary source for every row:
<https://github.com/LedgerHQ/app-ethereum/blob/master/doc/ethapp.adoc>
(the "APDUs list" table and each command's _Coding_ section)

| Command                | CLA    | INS    | P1                                          | P2                                       | Data                                                                        | Response                                                             |
| ---------------------- | ------ | ------ | ------------------------------------------- | ---------------------------------------- | --------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| GET ETH PUBLIC ADDRESS | `0xE0` | `0x02` | `0x00` return / `0x01` display+confirm      | `0x00` no chain code / `0x01` chain code | `count \| index₀…indexₙ` (4B BE each), optional 8B BE chain ID              | `pubKeyLen \| pubKey \| addrLen \| ASCII address \| [chainCode(32)]` |
| SIGN ETH TRANSACTION   | `0xE0` | `0x04` | `0x00` first chunk / `0x80` following chunk | `0x00` process & start flow              | first chunk: `count \| index₀…indexₙ \| rlpChunk`; later chunks: `rlpChunk` | `v(1) \| r(32) \| s(32)`                                             |
| GET APP CONFIGURATION  | `0xE0` | `0x06` | `0x00`                                      | `0x00`                                   | none                                                                        | `flags(1) \| major(1) \| minor(1) \| patch(1)`                       |

Constants live in `src/ledger/eth-app.ts` as `ETH_CLA`, `ETH_INS`, `ETH_P1`,
`ETH_P2`, each with the source URL beside it.

Two independent confirmations of `CLA 0xE0 / INS 0x04 / P1 0x00|0x80 / P2 0x00`:

- `hw-app-eth`'s `signTransaction` `APDU_FIELDS` enum —
  <https://github.com/LedgerHQ/ledger-live/blob/develop/libs/ledgerjs/packages/hw-app-eth/src/Eth.ts>
- the Device Management Kit's `SignTransactionCommand.getApdu()` —
  <https://github.com/LedgerHQ/device-sdk-ts/blob/develop/packages/signer/signer-eth/src/internal/app-binder/command/SignTransactionCommand.ts>

### GET APP CONFIGURATION flag bits

| Bit    | Meaning                                              |
| ------ | ---------------------------------------------------- |
| `0x01` | arbitrary data signature enabled by user             |
| `0x02` | ERC-20 token information must be provided externally |
| `0x10` | Transaction Check enabled                            |
| `0x20` | Transaction Check opt-in done                        |

Older `hw-app-eth` releases read `0x04`/`0x08` as Stark support. The current app
specification documents `0x10`/`0x20`, and the app specification wins for the
app we actually talk to. Recorded in `ETH_CONFIG_FLAGS`.

### Not implemented

Deliberately absent, so nothing here is a half-built guess: PROVIDE ERC-20 TOKEN
INFORMATION (`0x0A`), SIGN ETH PERSONAL MESSAGE (`0x08`), SIGN ETH EIP-712
(`0x0C`), SET PLUGIN / SET EXTERNAL PLUGIN (`0x16`/`0x12`), PROVIDE TRUSTED NAME
(`0x22`), PROVIDE NETWORK INFORMATION (`0x30`), SIGN EIP-7702 AUTHORIZATION
(`0x34`). The consequence is concrete and worth stating: **without the token and
plugin provisioning commands, an ERC-20 transfer reviewed on the device shows a
raw contract call, not "Send 25 USDT".** Arx's own clear-signing render
(`clear-signing.ts`) computes the human-readable view and labels it a
_preview_; it is not the device's rendering.

### Derivation-path encoding

`44'/60'/0'/0/0` encodes to 21 bytes:

```
05 8000002c 8000003c 80000000 00000000 00000000
^  ^
|  44 + 0x80000000 (hardened)
count (max 10 per the specification)
```

One deliberate divergence from Ledger's client: `hw-app-eth`'s `splitPath`
silently skips any path segment it cannot parse as a number. Arx rejects it
instead (`ArxError` / `INVALID_TRANSACTION`). Silently dropping a segment would
sign with a _different key_ than the caller named.

### Status words

Values from `StatusCodes` in `@ledgerhq/errors`
(<https://github.com/LedgerHQ/ledger-live/tree/develop/libs/ledgerjs/packages/errors>);
messages follow the same file's `getAltStatusMessage`.

| SW            | Ledger name                          | Arx `DecisionCode`        |
| ------------- | ------------------------------------ | ------------------------- |
| `0x9000`      | `OK`                                 | — (success)               |
| `0x6985`      | `CONDITIONS_OF_USE_NOT_SATISFIED`    | `SIGNER_REJECTED_BY_USER` |
| `0x5501`      | `USER_REFUSED_ON_DEVICE`             | `SIGNER_REJECTED_BY_USER` |
| `0x6A80`      | `INCORRECT_DATA`                     | `INVALID_TRANSACTION`     |
| `0x6700`      | `INCORRECT_LENGTH`                   | `SIGNING_FAILED`          |
| `0x6B00`      | `INCORRECT_P1_P2`                    | `SIGNING_FAILED`          |
| `0x6D00`      | `INS_NOT_SUPPORTED`                  | `SIGNER_UNAVAILABLE`      |
| `0x6E00`      | `CLA_NOT_SUPPORTED` (wrong app open) | `SIGNER_UNAVAILABLE`      |
| `0x6D02`      | `UNKNOWN_APDU`                       | `SIGNER_UNAVAILABLE`      |
| `0x5515`      | `LOCKED_DEVICE`                      | `SIGNER_UNAVAILABLE`      |
| `0x6982`      | `SECURITY_STATUS_NOT_SATISFIED`      | `SIGNER_UNAVAILABLE`      |
| `0x6D07`      | `DEVICE_NOT_ONBOARDED`               | `SIGNER_UNAVAILABLE`      |
| `0x6Fxx`      | `TECHNICAL_PROBLEM`                  | `SIGNING_FAILED`          |
| anything else | `UNKNOWN_STATUS_WORD`                | `SIGNING_FAILED`          |

`0x6985` is a **normal outcome, not an error**: a human declining on the device
is the approval boundary working. An unrecognised status word is never treated
as success — fail closed.

---

## 3. The signer modes, and exactly what each proves

`SIGNER_MODE` selects one adapter behind one interface. There is no default
fallback in `createSignerAdapter()`: every mode is an explicit branch, because a
mode Arx does not implement must not quietly become the mock signer. That is
invariant 8's exact failure — a mock signature presented where a real one was
expected.

| Mode       | Adapter name   | `signatureType` | `emulated` | Key lives in                | Needs                      |
| ---------- | -------------- | --------------- | ---------- | --------------------------- | -------------------------- |
| `mock`     | `mock-signer`  | `MOCK`          | `true`     | nowhere — there is no key   | nothing                    |
| `sim`      | `speculos-sim` | `REAL`          | `true`     | this Bun process's memory   | nothing                    |
| `speculos` | `speculos`     | `REAL`          | `true`     | the emulator's process      | Docker                     |
| `dmk`      | `ledger-dmk`   | `REAL`          | `false`    | the device's Secure Element | a physical Ledger          |
| `privy`    | `privy-stub`   | `REAL`          | `false`    | nowhere — it cannot sign    | reports itself unavailable |

Read that table as a ladder of claims, each rung adding one thing the rung
below could not support.

### `mock` — a labelled placeholder

Deterministic, offline, and deliberately impossible to mistake for a signature.
Four independent markers say so: the adapter name, `signatureType: "MOCK"`
carried on the result and echoed on every API response, a `0xmock_` prefix on
`signedTransaction` (which is not valid RLP, so it cannot be broadcast even by
accident), and an `r` component that is the literal ASCII bytes of `mock`
repeated eight times. `verified` is always `false` — there is nothing to
recover.

**Proves:** that the authorization pipeline reaches the signer boundary and that
an approval was consumed exactly once.
**Proves nothing about:** cryptography, the APDU protocol, or a device.

### `sim` — real cryptography, simulated device

This is the mode to reach for on a machine with no Docker and no hardware, and
it is worth being precise about, because its honest description is both stronger
and weaker than people assume.

It drives the **same** `EthereumApp` codec the Speculos adapter uses, against
`SimulatedEthereumAppTransport` — an in-process implementation of the
`app-ethereum` APDU protocol. That transport parses the same APDUs, accumulates
the same chunked payload, decides completeness from the RLP length header the
way the app's streaming parser does, applies the same `v` conventions, returns
the same response layouts, and is keyed from Speculos' published default test
mnemonic, so it reports the same address the emulator would:
`0xDad77910DbDFdE764fC21FCD4E74D71bBACA6D8D` at `44'/60'/0'/0/0`.

What is **real** in `sim`:

- the APDU framing and chunking, byte for byte, through the production codec;
- the RLP payload — the real unsigned serialization from `tx-serialize.ts`;
- the secp256k1 signature, over the real keccak-256 digest of those exact bytes;
- the verification step: `SignerService` recomputes the digest from the
  canonical transaction and recovers the signer with viem, then compares it to
  the address the adapter reported. A mismatch is
  `SIGNATURE_VERIFICATION_FAILED`, never a success;
- the broadcastable signed RLP, round-trippable through viem's
  `parseTransaction`;
- the status-word paths, including a simulated user refusal (`0x6985`) and
  unsupported transaction types.

What is **not** real, and is never claimed to be:

- **the key is in this process's memory.** There is no Secure Element, no
  hardware isolation, and no key that a compromised host cannot read.
- **there is no Trusted Display** and no human confirmation, so `sim` cannot
  support any statement about a person having reviewed a transaction. What it
  emits is `clearSigningPreview` — Arx's own local render, tagged as a preview —
  and never `deviceScreens`, which is a capture.
- it is an implementation of the protocol written by the same hand as the codec
  it exercises. Two implementations agreeing is weaker evidence than one of them
  being Ledger's.

Two guardrails keep the mode from drifting into a claim it cannot carry:
`getStatus()` reports `emulated: true` with a `detail` string that says the
device is simulated, and the constructor **throws** under
`NODE_ENV=production` — because in production an in-process software key is
precisely the thing Arx exists to make unnecessary.

**Proves:** the codec is correct, the chunking is correct, the `v`/`yParity`
handling is correct, and a signature produced through this path genuinely
recovers to the expected account.
**Proves nothing about:** hardware isolation, human presence, or Ledger's own
app binary.

```bash
SIGNER_MODE=sim bun run dev
curl -s localhost:3000/signer | jq
```

### `speculos` — Ledger's own app binary, no hardware

The real `app-ethereum` ELF, published by Ledger, running under Ledger's
emulator, reached over the documented REST or TCP transport. The signature is a
genuine secp256k1 signature over the real digest, produced by the real
application, recoverable to the seed's account — and this mode additionally
captures `deviceScreens` from the emulator's event log, which is a record of
what the device _displayed_.

What it still is not: a Secure Element. Speculos faithfully emulates the app and
the protocol; it does not reproduce hardware isolation, and it runs on a
published test seed. So the adapter reports `signatureType: "REAL"` **and**
`emulated: true`.

A screen capture taken with `SPECULOS_AUTO_APPROVE=1` proves what was shown, not
that a person agreed to it — the capture carries the auto-approval flag for
exactly that reason.

**Proves:** Arx speaks the real app's protocol correctly, and what the review
screens contained.
**Proves nothing about:** hardware isolation, or human presence under
auto-approval.

See §7 to run it. **It has not been run here** — see §8.

### `dmk` — a physical Ledger

The first-party path: `@ledgerhq/device-management-kit` with
`@ledgerhq/device-signer-kit-ethereum` over node-HID. The key never leaves the
Secure Element, the transaction is reviewed on the Trusted Display, and a human
presses the button. `emulated: false`.

This is the only mode in which a signature, combined with the device
confirmation, supports the strong claim: a person approved this transaction on
hardware they hold.

**It has never been executed.** There is no device here. The packages are
deliberately _not_ dependencies — they pull a native HID binding that cannot
install without one, and a failed install would stop the service booting — so
everything is reached through a lazy dynamic `import()`, and the module always
loads and reports itself unavailable. See §8.

### `privy`

A stub that reports unavailable, owned by the integrations layer rather than
this boundary. It exists so the mode is a named branch instead of an accidental
fallthrough to `mock`. Its declared `signatureType` is `REAL` because it would
be a real signer if it were implemented — it simply never signs, and
`getStatus()` reports `available: false` with the reason.

---

## 4. Transports

### REST (`SPECULOS_TRANSPORT=http`)

`POST /apdu` with `{"data":"<hex>"}`; the reply is `{"data":"<hex>"}` where the
hex **includes** the trailing status word. Verified against Speculos' own
OpenAPI document (its example is request `e0c0000004`, response
`105e441f9000`):
<https://github.com/LedgerHQ/speculos/blob/master/speculos/api/static/swagger/swagger.json>

Every exchange has an explicit `AbortSignal.timeout`. A stalled emulator must
not hold an approval open indefinitely.

### Raw socket (`SPECULOS_TRANSPORT=tcp`, port 9999)

Verified against Speculos' socket server, not assumed:
<https://github.com/LedgerHQ/speculos/blob/master/speculos/mcu/apdu.py>

```
request : uint32 BE length | APDU bytes
response: uint32 BE length | payload | SW1 SW2
                 ^ EXCLUDES the 2-byte status word
```

`forward_to_client` computes `size = (len(packet) - 2)` and sends
`size.to_bytes(4,"big") + packet`. **This asymmetry is the trap in the
protocol**: reading only `length` bytes after the prefix silently truncates the
status word, so every reply would look like a reply with no status at all. The
transport reads `length + 2`.

TCP is a byte stream, so frames are accumulated and completed only when all
their bytes have arrived, and exchanges are serialised — the socket has no
request identifiers, so two in-flight commands would produce two
indistinguishable replies. Both behaviours are covered by tests that run a
local stand-in server which deliberately splits every frame in two.

---

## 5. The signing sequence

```
NormalizedTransaction (canonical, hashed, approval-bound)
   │
   ├─ serializeUnsigned()            viem: 0x02 || rlp([...]) for EIP-1559
   ├─ unsignedTransactionDigest()    keccak256 of exactly those bytes
   │
   ├─ GET ETH PUBLIC ADDRESS         device reports its address (display: false)
   │     └─ optional pin: config.signerAddress mismatch → SIGNER_ADDRESS_MISMATCH
   │
   ├─ DELETE /events                 scope the screen capture to this transaction
   ├─ POST /automation               only when SPECULOS_AUTO_APPROVE=1
   │
   ├─ SIGN ETH TRANSACTION           chunked; first chunk carries the path
   │     └─ device returns v | r | s, or 0x6985 if the human declines
   │
   ├─ deriveYParity()                typed → the byte IS the parity
   │                                 legacy → replay the EIP-155 byte overflow
   ├─ serializeSigned()              broadcastable RLP
   ├─ GET /events                    capture what the device displayed
   │
   └─ SignerService.sign()
         recoverAddress(digest, {r, s, yParity}) == device address ?
            no → SIGNATURE_VERIFICATION_FAILED     (never a success)
            yes → verified: true
```

### Chunking

One APDU carries at most 255 data bytes — `Lc` is a single byte, and the
specification says the RLP is "streamed to the device in 255 bytes maximum data
chunks". The first chunk is `pathPrefix || payloadStart`, later chunks are
payload only, `P1` switching `0x00 → 0x80`.

For **legacy** transactions the boundary is a correctness concern, not just
throughput: an EIP-155 payload ends with the `v`/`r`/`s` slots, and a boundary
landing just before them can make the app read a partial RLP as a complete
transaction. `chunkSignPayload` shrinks the chunk size until the final chunk is
longer than that trailing triple — a faithful port of
`safeChunkTransaction`:
<https://github.com/LedgerHQ/ledger-live/blob/develop/libs/ledgerjs/packages/hw-app-eth/src/utils.ts>

(The Device Management Kit uses a more conservative 150-byte chunk internally.
255 is what the specification permits and what `hw-app-eth` uses.)

### `v` and `yParity`

Do **not** assume the legacy EIP-155 encoding for a typed transaction.

- **Typed (EIP-1559/2930/4844/7702):** the device's single `v` byte _is_ the
  y-parity, `0` or `1`. Anything else is rejected.
- **Legacy:** the device has folded `chainId * 2 + 35 + parity` into one byte,
  which overflows for all but tiny chain IDs. `deriveYParity` replays that
  overflow for both candidate parities and matches against the returned byte;
  no match is an error, never a guess.

viem's legacy serializer reads `signature.v`, not `yParity`, so
`serializeSigned` passes the full EIP-155 `v` for legacy and `yParity` for
typed. (This was a real bug found by running the code — see §8.)

### Signature verification — the load-bearing step

`SignerService.sign()` recomputes the digest from the canonical transaction
**itself** and recovers the signer with viem's `recoverAddress`. It never trusts
a digest reported by the adapter: otherwise a compromised adapter could return a
signature over different bytes together with a digest that made it look right.
A mismatch is `SIGNATURE_VERIFICATION_FAILED` and never a success. This is what
turns invariant 3 (_the transaction signed is byte-identical to the transaction
approved_) into a checked property.

---

## 6. Device-screen evidence

Two different claims, kept in two different places on purpose:

|                       | What it is                                                                                                                       | Where                                         |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| `deviceScreens`       | **What the device displayed.** Captured from Speculos' event log, scoped to the transaction by a `DELETE /events` beforehand.    | `speculos-control.ts` → `readDeviceScreens()` |
| `clearSigningPreview` | **What a device _would_ display**, computed locally from ERC-7730 descriptors. Tagged `renderedBy: "arx-clear-signing-preview"`. | `clear-signing.ts` → `renderDeviceScreens()`  |

`deviceScreens` carries `emulated: true` and states whether auto-approval was
on, because a capture taken with automation active proves what was _shown_, not
that a person agreed to it. Line grouping into screens is a documented
heuristic (a `y` that does not advance starts a new screen); `lines` is the
authoritative record.

`GET /screenshot` returns a PNG of the current screen and is exposed as
`SpeculosSignerAdapter.getScreenshot()`.

### Clear signing (ERC-7730)

Descriptors follow the real format — Ledger's v2 schema and registry:

- spec: <https://github.com/LedgerHQ/clear-signing-erc7730-registry/blob/master/specs/erc-7730.md>
- registry: <https://github.com/LedgerHQ/clear-signing-erc7730-registry/tree/master/registry>

Bundled:

- `USDT_DESCRIPTOR` — copied verbatim from `registry/tether/calldata-usdt.json`,
  including the 6-decimal token metadata and the `approve` threshold that
  renders an effectively-unlimited allowance as "Unlimited USDT".
- `ERC20_TEMPLATE_DESCRIPTOR` — Arx-authored template, `deployments: []`, so it
  never matches a lookup. Bind it with `erc20DescriptorFor()`.

Fail-closed rules:

- A descriptor applies only when it is bound to **this address on this chain**.
  An unbound descriptor still renders, but `clearSigned: false` and a warning
  says its labels are not trustworthy.
- No matching descriptor → `intent: "Blind sign"`, `clearSigned: false`, and the
  human is told they are approving undecoded calldata.
- Field paths resolve using the **descriptor's own** parameter names (the
  registry's USDT entry uses `#._to`/`#._value`), not a hardcoded ABI.
- `addressName` shows the raw checksummed address. Arx never invents a name;
  ENS lives behind the `NameResolver` seam.

---

## 7. Running Speculos

```bash
scripts/speculos-up.sh               # preflight, fetch + verify the app, start, wait
export SIGNER_MODE=speculos
export SPECULOS_TRANSPORT=http       # or tcp
export SPECULOS_AUTO_APPROVE=1       # demo only — see the warning below
bun run dev
curl -s localhost:3000/signer | jq
```

Other entry points:

| Command                               | What it does                                           |
| ------------------------------------- | ------------------------------------------------------ |
| `scripts/speculos-up.sh --fetch-only` | Fetch and verify the app binary. **No Docker needed.** |
| `scripts/speculos-up.sh --down`       | Stop and remove the container                          |
| `scripts/speculos-up.sh --logs`       | Tail the container logs                                |
| `scripts/speculos-up.sh --help`       | The usage block                                        |

### Preflight

Docker absence is the most common reason this path cannot run — it is why the
emulator was never started while this repository was written — so it is checked
first and named precisely. The script distinguishes the two cases, because they
have different fixes: `docker` missing from `PATH`, and `docker info` failing
because the daemon is not running. Either way it exits non-zero with the
remedies, including the offline alternatives (`SIGNER_MODE=sim`, `mock`) and
`--fetch-only`.

### Ports, model and seed

Ports: **5000** REST API, **9999** raw APDU. Both are Speculos' own defaults
(`--api-port 5000`, `--apdu-port 9999` in `speculos/main.py`) and are mapped 1:1
so `SPECULOS_API_URL` and `SPECULOS_APDU_PORT` need no translation.

Models are the keys of `MODELS` in `speculos/mcu/struct.py`: `nanox`, `nanosp`,
`stax`, `flex`, `apex_p`. `SPECULOS_MODEL` defaults to `nanosp`. Note that the
original Nano S is no longer among them; `nanosp` is the Nano S+.

The model must match the app binary's build target, and the two naming schemes
differ — the Nano S+ is `nanosp` to the emulator and `nanos2` to the build
system. `speculos-up.sh` maps between them:

| `SPECULOS_MODEL` | Release asset target |
| ---------------- | -------------------- |
| `nanosp`         | `nanos2`             |
| `nanox`          | `nanox`              |
| `flex`           | `flex`               |
| `stax`           | `stax`               |
| `apex_p`         | `apex_p`             |

The seed is pinned to Speculos' published default 24-word mnemonic, taken
verbatim from `DEFAULT_SEED` in `speculos/main.py`, so `44'/60'/0'/0/0` derives
**0xDad77910DbDFdE764fC21FCD4E74D71bBACA6D8D** on every machine. It is a public
test seed: never fund it. Override with `SPECULOS_SEED` if you need a different
account.

`command` in the compose file is a YAML **list**, not a string: the seed
contains spaces, and Compose re-splits a string command, which would deliver the
mnemonic as 24 separate arguments.

Neither `SPECULOS_MODEL` nor `ARX_ETH_APP_ELF` has a compose-level default. Both
use `${VAR:?message}` so that running the compose file by hand without them
fails with an instruction rather than booting something arbitrary.

### On `SPECULOS_AUTO_APPROVE=1`

It presses the device's confirm buttons for you, which is the only way a
scripted demo gets past a confirmation prompt. It also defeats the
human-in-the-loop gate entirely. A signature produced under it proves the device
signed; it does not prove a person agreed. The screen capture records that
auto-approval was active so the two claims cannot be conflated later. Leave it
off for anything you intend to cite as human approval.

### Where the Ethereum app binary comes from — the honest answer

The Speculos Docker image **ships no Ethereum app.** Its `apps/` directory
contains only `boil.elf` and a Nano X variant — Speculos' own test binaries
(<https://github.com/LedgerHQ/speculos/tree/master/apps>). This matters more than
it sounds: `boil.elf` is not the Ethereum app, so an emulator booted on it
starts, serves the REST API, passes a naive health check, and answers **none** of
the `app-ethereum` APDUs. It looks like a working emulator and is not one. The
compose file therefore refuses to start without an explicit app path, and the
healthcheck comment says outright that a green check does not prove the app is
`app-ethereum`.

Ledger also states plainly that production apps installed on a physical device
cannot be extracted as runnable `.elf` files
(<https://github.com/LedgerHQ/speculos/blob/master/docs/user/getting_an_app.md>).

You do **not** have to build it, though. `LedgerHQ/app-ethereum` attaches
prebuilt per-model `.elf` artifacts to each GitHub release, and `speculos-up.sh`
downloads the one matching your model.

**Provenance and licence.** The source is Ledger's own release artifacts on
`LedgerHQ/app-ethereum`, licensed **Apache-2.0**. Arx redistributes nothing:
`.elf` files are gitignored (`data/ledger-apps/.gitignore`) and fetched at run
time. What the repository ships is the _digests_.

**Digest pinning.** Every download is verified against
`data/ledger-apps/CHECKSUMS.sha256` before the container starts, and an existing
cached file is re-verified on each run. A mismatch aborts with both digests
printed and leaves the file in place for inspection; it does not warn and
continue. A version with no pinned digest is refused unless
`ARX_ETH_APP_ALLOW_UNPINNED=1` is set explicitly. The reason is narrow and
concrete: in this mode the binary is what signs, so "which app ran" has to be a
checkable statement rather than "whatever the URL served today".

Recorded on 2026-09-12 by downloading each 1.22.3 asset and hashing it. All five
are `ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked,
not stripped`:

| Asset                   | Bytes   | SHA-256                                                            |
| ----------------------- | ------- | ------------------------------------------------------------------ |
| `app-1.22.3-nanos2.elf` | 282,928 | `d8631ab43961928851e66175bef6d0157e5c516389b8b61bdb3c239a8125944e` |
| `app-1.22.3-nanox.elf`  | 283,080 | `47705998a0419df75959f46faf2c4a214846f61943fd15d3708b92caf2a3559f` |
| `app-1.22.3-flex.elf`   | 364,664 | `88ce93fe2b982c05f37aef108c1ea40f251ae394c25bb8232eb6a8adb3feaa5d` |
| `app-1.22.3-stax.elf`   | 364,552 | `80703bf391b6e0ee9fca7e042b8f04b9b61068330111030c8458639e94e774fd` |
| `app-1.22.3-apex_p.elf` | 366,796 | `d55b73fa82a1ab8b63d9d57a6e4993e6236b8eb7f6dce78c5437e225e783b88d` |

Binaries are named per version and per model on disk —
`data/ledger-apps/app-1.22.3-nanos2.elf`, not `app-ethereum.elf` — because one
fixed filename silently reuses the previous model's binary when
`SPECULOS_MODEL` changes, which presents as an emulator that boots and then
behaves inexplicably.

If you would rather build from source — to run an unreleased commit, or to avoid
trusting a release artifact:

```bash
git clone https://github.com/LedgerHQ/app-ethereum && cd app-ethereum
docker run --rm -it -v "$(pwd)":/app \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest
# inside: make BOLOS_SDK=$NANOS2_SDK     (or $NANOX_SDK, $FLEX_SDK, ...)
# output: build/<target>/bin/app.elf
```

Then put it in `data/ledger-apps/` and point `ARX_ETH_APP_FILE` at the filename.
A local build will not match a pinned digest, so either add its digest to
`CHECKSUMS.sha256` or set `ARX_ETH_APP_ALLOW_UNPINNED=1` — the script will say
`sha256 NOT VERIFIED` when you do.

---

## 8. Verified vs unverified

### Verified by execution

- **The codec.** 43 tests in `tests/ledger-apdu.test.ts`, all passing, asserting
  exact bytes: BIP32 encodings, APDU framing (`e006000000`,
  `e002000015 05 8000002c…`, `e004000002dead` / `e004800002beef`), status-word
  parsing and mapping, and the 255-byte refusal.
- **Signature recovery.** A known private key signs the digest; the signature
  recovers back to that key's address. Mismatched addresses and
  signatures-over-a-different-transaction both fail to verify. Legacy and
  EIP-1559 both covered.
- **Signed-transaction assembly.** Round-tripped through viem's
  `parseTransaction` for both types, asserting the legacy `v` is the EIP-155
  value and not the bare parity.
- **The Speculos TCP framing**, against a local stand-in server that implements
  the documented protocol and splits every frame in two so partial reads are
  really exercised — including that the status word survives the
  length-excludes-SW asymmetry, and that concurrent exchanges serialise.
- **The full signer path end-to-end**, against a throwaway stand-in that speaks
  the documented Speculos REST API and the documented app-ethereum APDUs backed
  by a real secp256k1 key. 32 checks passed, covering: `getStatus`,
  single-chunk EIP-1559, a 4-chunk 900-byte-calldata transaction (first chunk
  `P1=00`, rest `P1=80`, every `Lc ≤ 255`), legacy EIP-155 `v`, screen capture
  and grouping, automation install, `0x6985` → `SIGNER_REJECTED_BY_USER`, a
  pinned-address mismatch → `SIGNER_ADDRESS_MISMATCH`, and an adapter that
  reports a false signer address → `SIGNATURE_VERIFICATION_FAILED`.
  **Two real bugs were found and fixed this way**: viem's legacy serializer
  needs `v` rather than `yParity`, and ERC-7730 field paths must resolve against
  the descriptor's own parameter names.
- **`SIGNER_MODE=sim` end to end**, through the production codec. Two runs, both
  executed here:
  `tests/end-to-end.test.ts` sets `SIGNER_MODE=sim` for the HTTP suite, and
  `SIGNER_MODE=sim bun run scripts/demo.ts` drives all 14 adversarial scenarios
  — 14 passed, 0 failed, exit 0 — with the server reporting
  `adapter: "speculos-sim"`, `signatureType: "REAL"`, `emulated: true`,
  `appVersion: "1.22.3"` and address
  `0xDad77910DbDFdE764fC21FCD4E74D71bBACA6D8D`. Every signature on that path is
  recovered from the digest Arx recomputed and compared to the reported address
  before it is called verified. (`bun run demo` on its own defaults to
  `SIGNER_MODE=mock`; pass `sim` explicitly to exercise real cryptography.)
- **The app-binary fetch and digest pinning**, executed on 2026-09-12. All five
  1.22.3 release assets were downloaded and hashed; the digests in
  `data/ledger-apps/CHECKSUMS.sha256` are those measurements, and every asset is
  an `ELF 32-bit LSB executable, ARM, EABI5`. `scripts/speculos-up.sh
--fetch-only` was then run against two different models (`nanosp` → 282,928
  bytes, `flex` → 364,664 bytes) and both verified.
- **`scripts/speculos-up.sh`'s fail-closed paths**, each executed and each
  exiting non-zero with a specific message:
  Docker absent from `PATH`; an unknown `SPECULOS_MODEL`; a version with no
  pinned digest; and a cached binary whose digest no longer matches (a byte was
  appended to a good file, and the mismatch was caught with both digests
  printed). A cached file is re-verified on every run, not only on download.

### Not verified

- **No live Speculos run.** Docker is not available in the environment this was
  written in — `command -v docker` finds nothing on this machine. The emulator
  container has never been started here, so the REST and TCP transports have
  been exercised only against stand-ins that implement the documented protocol —
  faithfully, but written by the same hand. The two live tests in
  `tests/ledger-apdu.test.ts` probe the API in `beforeAll` and **skip** when it
  is absent; they never fail the suite and never silently pass (a console line
  says they were skipped, not passed).

  Concretely unexercised as a result: the `docker compose up` path in
  `scripts/speculos-up.sh`; Compose's interpolation of `SPECULOS_MODEL`,
  `SPECULOS_SEED` and `ARX_ETH_APP_ELF`; the container healthcheck; the 1:1 port
  publishing; the readiness loop; `--down` and `--logs`; and whether the pinned
  1.22.3 binary boots cleanly under this Speculos image at all. The compose file
  parses as valid YAML and its flags and defaults were checked line by line
  against `speculos/main.py`, `speculos/mcu/struct.py` and Speculos' own
  OpenAPI document — but a file that parses is not a container that runs, and
  the difference is exactly what has not been closed. Anyone with Docker can
  close it in one command; do not take the Speculos path on trust until someone
  has.

- **No physical Ledger.** `src/signer/dmk-signer.ts` has never been executed.
  Package names and versions were checked against the npm registry
  (`@ledgerhq/device-management-kit` 1.9.0,
  `@ledgerhq/device-signer-kit-ethereum` 1.18.0,
  `@ledgerhq/device-transport-kit-node-hid` 1.0.1) and the call shapes follow
  the published docs and current source (`SignerEthBuilder` takes
  `{ dmk, sessionId }` — the README's `{ sdk, sessionId }` is stale). The
  packages are **deliberately not dependencies**: they pull a native HID
  binding that cannot install without a device, and a failed install would stop
  the service booting. Everything is reached through a lazy dynamic `import()`,
  so the module always loads and reports itself unavailable. **Treat this
  adapter as untested until someone runs it with hardware.**
- **The demo seed's derived address** (`0xDad7…6D8D`) was computed with viem
  from Speculos' documented default mnemonic. Standard BIP39/BIP32 says the
  emulator will agree; that has not been observed.
- **`SIGNER_MODE=privy`** is a stub that reports unavailable. It is owned by the
  integrations layer, not this boundary.
- **`SIGNER_MODE=sim`'s agreement with the real app.** The simulator reproduces
  the protocol as documented and as Arx's codec implements it, and it derives the
  same address the emulator should. Whether Ledger's binary agrees with it on
  every edge — an unusual RLP shape, a rejected transaction type, an unexpected
  chunk boundary — has not been observed, because that comparison needs
  Speculos. `sim` is evidence that the codec is self-consistent and
  cryptographically correct, not that it matches the app byte for byte.
- **Clear-signing on the device.** The token and plugin provisioning APDUs are
  not implemented, so the device itself will blind-sign an ERC-20 transfer.
  `clearSigningPreview` is Arx's own render and is labelled as a preview
  everywhere it appears.

### A note on `signatureType: "REAL"` for Speculos

A Speculos signature _is_ a real secp256k1 signature over the real digest,
produced by the real Ledger application binary, recoverable to the seed's
account. What is not real is the hardware: an emulator with a published seed and
no secure element. So the adapter reports `signatureType: "REAL"` **and**
`emulated: true`, and names itself `speculos`. The mock signer is the only
`"MOCK"`, and it cannot be confused with either: `0xmock_`-prefixed output that
is not valid RLP, and an `r` that is the literal ASCII bytes of "mock".
