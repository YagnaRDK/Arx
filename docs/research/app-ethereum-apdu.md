# Ledger Ethereum app (app-ethereum) APDU protocol — byte-level reference

> Compiled 2026-09-12 by a research agent that verified each claim against
> primary sources (npm tarballs, app source, official docs). Facts carry their
> source URL. Anything unverified is listed explicitly at the end — treat that
> section as unknown, not as true.

## Summary

I verified every byte-level detail against primary sources: the official spec (`doc/ethapp.adoc` on branch `master` — note `develop` is gone, that raw URL 404s), the app's own C source at tag 1.22.3, the `@ledgerhq/hw-app-eth@7.8.18` compiled source, LedgerHQ/device-sdk-ts, LedgerHQ/speculos source (swagger.yaml, api/apdu.py, mcu/apdu.py, client.py), and both official Speculos transports (`hw-transport-node-speculos` TCP + `-http`).

Key results. CLA is always 0xE0. GET ETH PUBLIC ADDRESS = INS 0x02, P1 0x00 (silent) / 0x01 (confirm on device), P2 0x00 / 0x01 (chain code); data = `nElems(1) || uint32BE × n` plus an OPTIONAL 8-byte big-endian chainId; response = `65 || pubkey(65) || 40 || address-ASCII(40) [|| chainCode(32)]` — the address is 40 hex chars, EIP-55 checksummed (EIP-1191 only for chainId 30/31), no `0x`. SIGN = INS 0x04, P1 0x00 first chunk / 0x80 following, P2 0x00 (basic). **Max chunk is 255 bytes, not 150** — the 150 figure only appears in hw-app-eth's `signPersonalMessage`/EIP-712 helpers. First-chunk data = packed BIP32 path immediately followed by the RLP payload. For EIP-2718 typed txs **the type byte IS included** (`cmd_sign_tx.c` reads `payload[offset]`, and if `<= 0x7f` treats it as the type, hashing it and accepting only 0x01/0x02/0x04). I proved byte-for-byte that viem's `serializeTransaction(unsignedTx)` output is exactly the payload the Ledger ragger test suite streams — including the legacy EIP-155 preimage `rlp([...,chainId,0x80,0x80])`. Response is `v(1) || r(32) || s(32)`: for typed txs v is the raw yParity 0/1; for legacy it is `(chainId*2+35+parity) mod 256` (single-byte overflow you must undo).

Speculos: TCP 9999 uses a 4-byte BE length prefix; **outbound frames set that length to `len(response)-2`, excluding the SW, so you must read `length+2` bytes**. HTTP 5000: `POST /apdu {"data":hex}` → `{"data": hex-including-SW}`, and it **blocks until the user approves**, so buttons must be driven concurrently. Prebuilt ELFs ARE published on app-ethereum GitHub releases (no build needed).

## Verified facts

### Spec location

doc/ethapp.adoc exists only on branch `master` (default branch). The `develop` branch raw URL returns 404 / a 14-byte error body. Correct URL: https://raw.githubusercontent.com/LedgerHQ/app-ethereum/master/doc/ethapp.adoc (74146 bytes, 1855 lines).

Source: https://raw.githubusercontent.com/LedgerHQ/app-ethereum/master/doc/ethapp.adoc

### CLA

`#define CLA 0xE0`. main.c handleApdu: `if (cmd->cla != CLA) return SWO_INVALID_CLA;` (0x6E00).

Source: https://github.com/LedgerHQ/app-ethereum/blob/1.22.3/src/apdu_constants.h

### INS list

GET_PUBLIC_KEY=0x02, SIGN=0x04, GET_APP_CONFIGURATION=0x06, SIGN_PERSONAL_MESSAGE=0x08, PROVIDE_ERC20_TOKEN_INFORMATION=0x0A, SIGN_EIP_712_MESSAGE=0x0C, SET_EXTERNAL_PLUGIN=0x12, PROVIDE_NFT_INFORMATION=0x14, SET_PLUGIN=0x16, EIP712_STRUCT_DEF=0x1A, EIP712_STRUCT_IMPL=0x1C, EIP712_FILTERING=0x1E, GET_CHALLENGE=0x20, PROVIDE_TRUSTED_NAME=0x22, PROVIDE_NETWORK_CONFIGURATION=0x30, PROVIDE_TX_SIMULATION=0x32, SIGN_EIP7702_AUTHORIZATION=0x34, PROVIDE_SAFE_ACCOUNT=0x36, PROVIDE_GATING=0x38.

Source: https://github.com/LedgerHQ/app-ethereum/blob/1.22.3/src/apdu_constants.h

### GET ETH PUBLIC ADDRESS — P1/P2

Spec: "CLA E0 | INS 02 | P1 00 : return address / 01 : display address and confirm before returning | P2 00 : do not return the chain code / 01 : return the chain code". Source enforces: `P1_CONFIRM 0x01`, `P1_NON_CONFIRM 0x00`, `P2_NO_CHAINCODE 0x00`, `P2_CHAINCODE 0x01`; any other value → SWO_WRONG_P1_P2 (0x6B00).

Source: https://github.com/LedgerHQ/app-ethereum/blob/1.22.3/src/features/get_public_key/cmd_get_public_key.c

### BIP32 path encoding

Spec input data: "Number of BIP 32 derivations to perform (max 10) — 1 byte; First derivation index (big endian) — 4; ...; Last derivation index (big endian) — 4; Chain ID (big endian) (optional) — 8". Source `parseBip32()` in main.c reads `bip32->length = *dataBuffer` then `bip32->length * sizeof(uint32_t)` bytes. hw-app-eth: `buffer[0] = paths.length; paths.forEach((el,i)=>buffer.writeUInt32BE(el, 1+4*i))`. Hardened segments add 0x80000000.

Source: https://github.com/LedgerHQ/app-ethereum/blob/1.22.3/src/main.c

### GET ETH PUBLIC ADDRESS — optional chainId

After the path, the app accepts an optional 8-byte big-endian chainId: `if (dataLength >= sizeof(chain_id)) { chain_id = u64_from_BE(dataBuffer, 8); ... }` and rejects any leftover bytes with SWO_INCORRECT_DATA (0x6A80). It is used only for display on Stax/Flex and for the EIP-1191 checksum decision. Omitting it is fine.

Source: https://github.com/LedgerHQ/app-ethereum/blob/1.22.3/src/features/get_public_key/cmd_get_public_key.c

### GET ETH PUBLIC ADDRESS — response layout

`set_result_get_publicKey()`: byte0 = CX_SECP256_PUB_KEY_SIZE (65), then 65 bytes uncompressed pubkey (0x04-prefixed), then a literal `40` length byte, then 40 ASCII hex chars of the address, then 32 bytes chain code if P2=0x01. Total 107 bytes (139 with chain code), plus the 2-byte SW.

Source: https://github.com/LedgerHQ/app-ethereum/blob/1.22.3/src/features/get_public_key/get_public_key.c

### Address format returned

The address is 40 ASCII hex chars WITHOUT a `0x` prefix and IS mixed-case EIP-55 checksummed. `getEthAddressStringFromBinary()` uses plain EIP-55 keccak(lowercase-hex); EIP-1191 (prefixing `<chainId>0x`) is used ONLY for chainId 30 and 31 (RSK). hw-app-eth prepends the literal string "0x".

Source: https://github.com/LedgerHQ/ethereum-plugin-sdk/blob/master/src/common_utils.c

### Example GET ADDRESS APDU

For m/44'/60'/0'/0/0 the data is `058000002c8000003c800000000000000000000000` (21 bytes). Full APDU silent: `e002000015058000002c8000003c800000000000000000000000`. With display+confirm: `e002010015...`. With 8-byte chainId=1 appended: `e00200001d058000002c8000003c8000000000000000000000000000000000000001`.

Source: https://github.com/LedgerHQ/app-ethereum/blob/1.22.3/tests/ragger/client/command_builder.py

### SIGN ETH TRANSACTION — P1/P2

Spec: "CLA E0 | INS 04 | P1 00 : first transaction data block / 80 : subsequent transaction data block | P2 00 : process & start flow / 01 : store only / 02 : start flow". Source enum: SIGN_MODE_BASIC=0, SIGN_MODE_STORE=1, SIGN_MODE_START_FLOW=2. Use P2=0x00. hw-app-eth: `P1_FIRST_CHUNK = 0 (224=CLA, 4=INS), P1_FOLLOWING_CHUNK = 128, P2 = 0`.

Source: https://github.com/LedgerHQ/app-ethereum/blob/1.22.3/src/features/sign_tx/cmd_sign_tx.c

### SIGN max chunk size = 255 (NOT 150)

hw-app-eth `safeChunkTransaction`: `const maxChunkSize = 255;`. app-ethereum ragger command_builder.sign(): `payload[:0xff]` then `payload = payload[0xff:]`. The 150-byte figure appears ONLY in hw-app-eth's `signPersonalMessage` (`const maxChunkSize = offset === 0 ? 150 - 1 - paths.length*4 - 4 : 150`) and the EIP-712 helpers — not for INS 0x04. 255 is also the hard APDU limit since Lc is one byte.

Source: https://unpkg.com/@ledgerhq/hw-app-eth@7.8.18/lib-es/utils.js

### SIGN first-chunk payload

Spec: first block = "Number of BIP 32 derivations (max 10) | indices | RLP transaction chunk"; subsequent blocks = "RLP transaction chunk" only. hw-app-eth: `payload = Buffer.concat([derivationPathBuff, rawTx])` then split into 255-byte chunks — so the path is NOT repeated and the split can fall mid-path-free, i.e. the path only occupies the head of chunk 0.

Source: https://raw.githubusercontent.com/LedgerHQ/app-ethereum/master/doc/ethapp.adoc

### EIP-2718 type byte IS included

`handle_first_sign_chunk()`: after parseBip32, `tx_type = payload[*offset]; if (tx_type <= MAX_TX_TYPE) { switch(tx_type){case EIP1559: case EIP2930: case EIP7702: break; default: return SWO_MEMORY_WRITE_ERROR;} cx_hash(...,&tx_type,1,...); txContext.txType = tx_type; *offset += 1; } else { txContext.txType = LEGACY; }`. MAX_TX_TYPE = 0x7f; LEGACY = 0xc0 ("Legacy tx are greater than or equal to 0xc0"). So the discriminator is the first payload byte after the path.

Source: https://github.com/LedgerHQ/app-ethereum/blob/1.22.3/src/features/sign_tx/cmd_sign_tx.c

### Supported tx types

`typedef enum { EIP2930 = 0x01, EIP1559 = 0x02, EIP7702 = 0x04, LEGACY = 0xc0 } txType_e;`. Any other type byte <= 0x7f returns 0x6501 ("TransactionType not supported") — the source currently returns SWO_MEMORY_WRITE_ERROR which is 0x6501. NOTE: a stale comment in hw-app-eth/utils.js says "EIP-7702: 0x05" — that is wrong; the app uses 0x04.

Source: https://github.com/LedgerHQ/app-ethereum/blob/1.22.3/src/features/sign_tx/eth_ustream.h

### Exact RLP payload (VERIFIED byte-for-byte against viem)

app-ethereum's own test client builds the payload as: typed → `type_byte || rlp([unsigned fields])`; legacy → `rlp([nonce, gasPrice, gasLimit, to, value, data, chainId, b'', b''])` (the EIP-155 preimage with two empty items). I ran viem 2.56.3 `serializeTransaction()` with no signature arg on the same inputs and got IDENTICAL hex: eip1559 → `0x02f00115843b9aca008504a817c800825208940011223344556677889900112233445566778899880de0b6b3a764000080c0`; legacy → `0xec158504a817c800825208940011223344556677889900112233445566778899880de0b6b3a764000080018080`. Conclusion: pass `serializeTransaction(unsignedTx)` straight through.

Source: https://github.com/LedgerHQ/app-ethereum/blob/1.22.3/tests/ragger/client/client.py

### SIGN response layout

Spec output data: "v — 1 | r — 32 | s — 32". `ECDSA_SIGNATURE_LENGTH 65  // Total ECDSA signature size: v (1) + r (32) + s (32)`. `io_seproxyhal_send_status(SWO_SUCCESS, ECDSA_SIGNATURE_LENGTH, ...)`. r is written at G_io_tx_buffer+1, s at +1+32, both fixed 32 bytes big-endian. Ragger parser asserts `len(data) == 1+32+32`.

Source: https://github.com/LedgerHQ/app-ethereum/blob/1.22.3/src/features/sign_tx/ui_common_sign_tx.c

### v byte for typed (EIP-1559/2930/7702) transactions

`if (txContext.txType == EIP1559 || EIP2930 || EIP7702) { G_io_tx_buffer[0] = (info & CX_ECCINFO_PARITY_ODD) ? 1 : 0; }`. So byte 0 IS the yParity, literally 0x00 or 0x01. Do NOT add 27 and do NOT apply EIP-155. hw-app-eth agrees: `getParity` returns vFromDevice unchanged when transactionType is truthy, and getV returns `padHexString(parity.toString(16))`.

Source: https://github.com/LedgerHQ/app-ethereum/blob/1.22.3/src/features/sign_tx/ui_common_sign_tx.c

### v byte for legacy transactions

Else-branch: if the streamed RLP had NO chainId field (`vLength == 0`) byte0 = ETHEREUM_SIGNATURE_V_BASE = 27; otherwise `v = u64_from_BE(txContent.v, MIN(4, vLength))` and `G_io_tx_buffer[0] = (v * 2) + 35`. Then `if (info & CX_ECCINFO_PARITY_ODD) buffer[0]++;` and `if (info & CX_ECCINFO_xGTn) buffer[0] += 2;`. Because it is one byte this wraps mod 256 — the source comment says "Note that this is wrong for a large v, but ledgerjs will recover."

Source: https://github.com/LedgerHQ/app-ethereum/blob/1.22.3/src/features/sign_tx/ui_common_sign_tx.c

### Legacy v recovery algorithm (host side)

hw-app-eth `getParity`: `chainIdUint32 = first 4 bytes of the minimal BE encoding of chainId`; `chainIdWithEIP155 = chainIdUint32*2 + 35`; `if (chainIdWithEIP155 % 256 === vFromDevice) parity = 0; else if ((chainIdWithEIP155+1) % 256 === vFromDevice) parity = 1; else throw new Error("Invalid v value")`. Then `v = chainId*2 + 35 + parity` (full precision BigNumber). Verified: chainId 1 → device sends 0x25/0x26; chainId 137 → device sends 53/54 and real v is 309/310.

Source: https://unpkg.com/@ledgerhq/hw-app-eth@7.8.18/lib-es/utils.js

### Legacy chunk-boundary hazard

`safeChunkTransaction` special-cases legacy: it RLP-decodes the last 3 elements (v,r,s), encodes them back, and if a naive 255-byte split would leave a final chunk shorter than that tail it shrinks the chunk size until it does not — because the device's streaming parser can consider the RLP complete early. For typed txs (`if (transactionType)`) it just splits at 255 with no adjustment.

Source: https://unpkg.com/@ledgerhq/hw-app-eth@7.8.18/lib-es/utils.js

### GET APP CONFIGURATION

CLA E0, INS 06, P1 00, P2 00, Lc 00, Le 04. Wire bytes as actually sent: `e006000000` (ledgerjs and ragger both append a 0x00 length byte). Response 4 bytes: [0]=flags, [1]=major, [2]=minor, [3]=patch.

Source: https://github.com/LedgerHQ/app-ethereum/blob/1.22.3/src/features/get_app_configuration/cmd_get_app_configuration.c

### GET APP CONFIGURATION flag bits (current)

`APP_FLAG_DATA_ALLOWED 0x01` (blind signing / arbitrary data enabled by user), `APP_FLAG_EXTERNAL_TOKEN_NEEDED 0x02` (always OR-ed in unconditionally), `APP_FLAG_TX_CHECKS_ENABLE 0x10`, `APP_FLAG_TX_CHECKS_OPT_IN 0x20`. hw-app-eth still decodes 0x04 as `starkEnabled` and 0x08 as `starkv2Supported` — those bits are dead in current firmware; do not copy that mapping.

Source: https://github.com/LedgerHQ/app-ethereum/blob/1.22.3/src/apdu_constants.h

### Status words — full spec list

0x6001 Mode check fail; 0x6501 TransactionType not supported; 0x6502 Output buffer too small for chainId conversion; 0x68xx Internal error; 0x6982 Security status not satisfied (Canceled by user); 0x6983 Wrong Data length; 0x6984 Plugin not installed; 0x6985 Condition not satisfied; 0x6A00 Error without info; 0x6A80 Invalid data; 0x6A84 Insufficient memory; 0x6A88 Data not found; 0x6B00 Incorrect parameter P1 or P2; 0x6D00 Incorrect parameter INS; 0x6E00 Incorrect parameter CLA; 0x6Fxx Technical problem; 0x9000 Normal ending of the command; 0x911C Command code not supported (Ledger-PKI not yet available).

Source: https://raw.githubusercontent.com/LedgerHQ/app-ethereum/master/doc/ethapp.adoc

### Status words — extra ones the app actually emits

App source also returns: 0x6980 SWO_COMMAND_NOT_ALLOWED (wrong app state, e.g. P1=0x80 without a prior first chunk, or a second GET ADDRESS mid-flow), 0x6800 SWO_NOT_SUPPORTED_ERROR_NO_INFO, 0x6807 EXCEPTION_OVERFLOW (per ragger StatusWord enum), 0x6A86/0x6A87 from the SDK. USER REJECTION of both GET ADDRESS confirm and SIGN returns SWO_CONDITIONS_NOT_SATISFIED = 0x6985 (io_seproxyhal_touch_tx_cancel / io_seproxyhal_touch_address_cancel). Ragger's own test asserts `e.status == StatusWord.CONDITION_NOT_SATISFIED` on reject.

Source: https://github.com/LedgerHQ/ledger-secure-sdk/blob/master/include/status_words.h

### 0x6A80 on sign = blind signing disabled

hw-app-eth `remapTransactionRelatedErrors`: `if (e.statusCode === 0x6a80) throw new EthAppPleaseEnableContractData("Please enable Blind signing or Contract data in the Ethereum app Settings")`. Confirmed device-side: `if (tmpContent.txContent.dataPresent && !N_storage.dataAllowed) { report_finalize_error(); ui_error_blind_signing(); }`.

Source: https://unpkg.com/@ledgerhq/hw-app-eth@7.8.18/lib-es/Eth.js

### Blind signing defaults to OFF on a fresh Speculos instance

`storage_init()`: `explicit_bzero(&storage, sizeof(storage)); storage.initialized = true; nvm_write(&N_storage, &storage, ...)` — every other field including `dataAllowed` is zeroed. `dataPresent` is set true only when a non-empty data field is parsed (`currentFieldLength != 0`). So value-only transfers with `data: '0x'` sign fine with no settings change; any calldata needs blind signing ON or clear-signing metadata.

Source: https://github.com/LedgerHQ/app-ethereum/blob/1.22.3/src/main.c

### Speculos raw TCP protocol, port 9999

Default `--apdu-port 9999`, bound to 0.0.0.0 (`ApduServer(host="0.0.0.0", port=args.apdu_port)`). Host→device: `recv_packet()` reads exactly 4 bytes, `size = int.from_bytes(data, byteorder="big")`, then reads `size` bytes = the raw APDU (CLA INS P1 P2 Lc data). Device→host: `size = (len(packet) - 2) & 0xFFFFFFFF; packet = size.to_bytes(4,"big") + packet` — the 4-byte length EXCLUDES the 2-byte status word, so the reader must consume length+2 bytes. Ledger's own transport does exactly this: `const size = dataLength + 2; // size does not include the status code so we add 2`.

Source: https://github.com/LedgerHQ/speculos/blob/master/speculos/mcu/apdu.py

### Speculos TCP server accepts only one client

`ApduServer.can_read()` does `c,_ = self.file.accept(); self.client = ApduClient(c)` — a new connection silently replaces the previous one (`self.client` is a single slot, not a list). Keep exactly one long-lived socket.

Source: https://github.com/LedgerHQ/speculos/blob/master/speculos/mcu/apdu.py

### Speculos REST API: POST /apdu

Swagger: request `{"data": "e0c0000004"}`, response `{"data": "105e441f9000"}`; schema `Apdu = {data: string, pattern ^([0-9a-fA-F]{2})+$}` required. The response `data` is the response payload WITH the 2-byte SW appended (speculos' own client does `status = int.from_bytes(data[-2:], "big")`). An optional `tick_timeout` number is also accepted (default 5*60*10 = 3000 ticks); on timeout the streamed body is cut, surfacing as a chunked-encoding error.

Source: https://github.com/LedgerHQ/speculos/blob/master/speculos/api/swagger.yaml

### POST /apdu BLOCKS until the device replies

`APDUBridge.exchange()` is a Flask generator: it yields b"" to flush headers, takes `endpoint_lock`, calls `self._seph.to_app(data)`, then `while self.response is None: self.response_condition.wait(0.1)`. For INS 0x04's last chunk and for INS 0x02 with P1=0x01 the app sets IO_ASYNCH_REPLY and does not answer until the UI is approved. So the HTTP POST hangs until you press buttons — buttons must be driven concurrently (different Flask resource, not blocked by endpoint_lock) or pre-armed via /automation.

Source: https://github.com/LedgerHQ/speculos/blob/master/speculos/api/apdu.py

### Speculos REST API port

`--api-port` default 5000 ("0 disables it"), served by Flask with `app.run(host="0.0.0.0", port=self._port, threaded=True)`. Base URL in swagger: http://127.0.0.1:5000. `--apdu-port` default 9999.

Source: https://github.com/LedgerHQ/speculos/blob/master/speculos/main.py

### POST /button/{button}

button ∈ {left, right, both}. Body `{"action": "press"|"release"|"press-and-release", "delay": <float, default 0.1>}`; `action` required, additionalProperties false. For press-and-release the handler presses ([1] left / [2] right / [1,2] both), waits `delay`, releases, then waits `delay` AGAIN ("Some app tests rely on this delay"). Returns `{}` with 200, or `{"error": ...}` with 400 on schema violation.

Source: https://github.com/LedgerHQ/speculos/blob/master/speculos/api/button.py

### GET /events

Query params: `stream` (bool, default false) and `currentscreenonly` (bool, default false). Non-stream returns JSON `{"events": [{...}, ...]}` with 200. Each event object is the TextEvent dataclass: `{text, x, y, w, h, clear}` (all fields present; `w`/`h`/`clear` are NOT in the swagger example but ARE in the payload). With `stream=true` the content-type is text/event-stream and each event is emitted as `data: {json}\n\n`. `currentscreenonly=true` returns only the current screen's accumulated text. `DELETE /events` clears the accumulated event list and returns `{}`/200.

Source: https://github.com/LedgerHQ/speculos/blob/master/speculos/api/events.py

### POST /automation

Body is the automation JSON document: `{"version": 1, "rules": [ {optional text|regexp|x|y|conditions, actions: [...] } ]}`. Actions: `["button", num, pressed]` (num=1 left, 2 right; pressed bool), `["finger", x, y, touched]`, `["setbool", varname, value]`, `["exit"]`. Only the FIRST matching rule's actions run. Returns 200. Working example from swagger: `{"version":1,"rules":[{"text":"Approve","actions":[["button",1,true],["button",2,true],["button",1,false],["button",2,false]]}]}`.

Source: https://github.com/LedgerHQ/speculos/blob/master/docs/user/automation.md

### GET /screenshot and POST /finger

`GET /screenshot` → 200, content-type image/png, binary body. `POST /finger` (Stax/Flex/Apex only) body `{"action":"press-and-release","x":10,"y":25,"delay":0.5}`; x/y/action required. Speculos' own client also sends optional `x2`/`y2` for swipes.

Source: https://github.com/LedgerHQ/speculos/blob/master/speculos/api/swagger.yaml

### Prebuilt Ethereum app ELFs ARE published

GitHub releases on LedgerHQ/app-ethereum attach one ELF per target. Latest at time of check: tag 1.22.3 (published 2026-08-26) with app-1.22.3-nanos2.elf (282928 B), -nanox.elf (283080 B), -flex.elf, -stax.elf, -apex_p.elf. I downloaded app-1.22.3-nanos2.elf unauthenticated: 282928 bytes, `ELF 32-bit LSB executable, ARM, EABI5, statically linked, not stripped`. `nanos2` is the Nano S+ target.

Source: https://github.com/LedgerHQ/app-ethereum/releases/download/1.22.3/app-1.22.3-nanos2.elf

### The speculos Docker image does NOT ship an Ethereum app

The repo's apps/ directory contains only `boil.elf` and `nanox#boil#2.1.0.elf`. Docs: "These binaries are old and exist for Speculos' own tests. Do not use them to validate a real integration." You must mount your own ELF via `-v`.

Source: https://github.com/LedgerHQ/speculos/blob/master/docs/user/getting_an_app.md

### Speculos docker image identity

`ghcr.io/ledgerhq/speculos` — only non-sha tag is `latest`. Manifest is an OCI image index with linux/amd64 AND linux/arm64, so it runs natively on Apple Silicon. Dockerfile: `WORKDIR /speculos`, `ENTRYPOINT ["python", "./speculos.py"]`, EXPOSE 1234 1236 9999 40000 41000 42000 (note: 5000 is NOT in EXPOSE, but -p still works).

Source: https://github.com/LedgerHQ/speculos/blob/master/Dockerfiles/Dockerfile

### Speculos --model values

`MODELS = {"nanox", "nanosp", "stax", "flex", "apex_p"}` — `nanos` has been REMOVED. Model is auto-detected from the ELF: `args.model = "nanosp" if binary.sections.target == "nanos2" else binary.sections.target`, so `--model nanosp` matches the `-nanos2.elf` asset and is optional.

Source: https://github.com/LedgerHQ/speculos/blob/master/speculos/mcu/struct.py

### Speculos --seed semantics and default

`-s/--seed`, help: 'BIP39 mnemonic or hex seed. Default to mnemonic: to use a hex seed, prefix it with "hex:"'. Implementation: `seed = mnemonic.Mnemonic.to_seed(args.seed)` (empty passphrase) then exported as `SPECULOS_SEED` hex. DEFAULT_SEED = "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin".

Source: https://github.com/LedgerHQ/speculos/blob/master/speculos/main.py

### Expected address for the default Speculos seed

I derived with eth-account 0.14.0 from the default mnemonic: m/44'/60'/0'/0/0 → 0xDad77910DbDFdE764fC21FCD4E74D71bBACA6D8D; m/44'/60'/0'/0/1 → 0xd692Cb1346262F584D17B4B470954501f6715a82; m/44'/60'/1'/0/0 → 0x463e4e114AA57F54f2Fd2C3ec03572C6f75d84C2. Cross-check: `Dad77910DbDFdE764fC21FCD4E74D71bBACA6D8D` appears verbatim as the expected device address in app-ethereum/tests/ragger/test_gcs.py.

Source: https://github.com/LedgerHQ/app-ethereum/blob/1.22.3/tests/ragger/test_gcs.py

### Nano S+ button sequence to enable Blind signing

From `get_settings_moves()` for nano devices, settings order is [BLIND_SIGNING, NONCE, VERBOSE_EIP712, DEBUG_DATA, EIP7702, DISPLAY_HASH]; moves are `[RIGHT, BOTH]` to enter Settings, then for each setting `BOTH` if toggling plus `RIGHT` to advance, then a final `BOTH` for Back. To toggle only BLIND_SIGNING from the app home screen: right, both, both, right, right, right, right, right, right, both.

Source: https://github.com/LedgerHQ/app-ethereum/blob/1.22.3/tests/ragger/client/settings.py

### PROVIDE NETWORK INFORMATION is optional for common chains

app-ethereum's own sign tests only call `provide_network_information` when the chainId is in DYNAMIC_ICONS (3 Ropsten, 5 Goerli, 56 BSC, 137 Polygon) — chainId 1 is absent, so mainnet needs nothing. For any other chain the app falls back to its built-in list / a generic display and still signs.

Source: https://github.com/LedgerHQ/app-ethereum/blob/1.22.3/tests/ragger/dynamic_networks_cfg.py

### device-sdk-ts agrees on the APDU headers

GetAddressCommand: `cla: 0xe0, ins: 0x02, p1: checkOnDevice ? 0x01 : 0x00, p2: returnChainCode ? 0x01 : 0x00`. SignTransactionCommand: `cla: 0xe0, ins: 0x04, p1: isFirstChunk ? 0x00 : 0x80, p2: 0x00`. GetAppConfigurationCommand: `cla: 0xe0, ins: 0x06, p1: 0x00, p2: 0x00`.

Source: https://github.com/LedgerHQ/device-sdk-ts/blob/develop/packages/signer/signer-eth/src/internal/app-binder/command/SignTransactionCommand.ts

### SIGN ETH PERSONAL MESSAGE (bonus, for eth_sign support)

CLA E0, INS 08, P1 0x00 first / 0x80 subsequent, P2 0x00. First block data = `nPathElems(1) || uint32BE*n || messageLength(4, big endian) || message chunk`; subsequent = raw message chunk. Response `v(1) || r(32) || s(32)` where v is 27/28 directly (hw-app-eth does `const v = response[0]` with no transformation).

Source: https://unpkg.com/@ledgerhq/hw-app-eth@7.8.18/lib-es/Eth.js

## Code and commands

### Speculos HTTP transport (port 5000) — exact request/response shapes

Verified against speculos/api/apdu.py + swagger.yaml. The returned `data` hex INCLUDES the 2-byte SW, which you must split off. This call BLOCKS until the app answers, so for confirm/sign APDUs you must drive buttons concurrently — see the next snippet.

```typescript
export type ApduResult = { data: Buffer; sw: number };

export class SpeculosHttp {
  constructor(private base = "http://127.0.0.1:5000") {}

  /** POST /apdu {"data":"<hex>"} -> {"data":"<responsehex+SW>"} */
  async exchangeRaw(apdu: Buffer, tickTimeout?: number): Promise<ApduResult> {
    const body: Record<string, unknown> = { data: apdu.toString("hex") };
    if (tickTimeout !== undefined) body.tick_timeout = tickTimeout; // default 3000 ticks
    const res = await fetch(`${this.base}/apdu`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`POST /apdu -> HTTP ${res.status}: ${await res.text()}`);
    const json = (await res.json()) as { data: string };
    const buf = Buffer.from(json.data, "hex");
    if (buf.length < 2) throw new Error(`APDU response shorter than 2 bytes: ${json.data}`);
    return { data: buf.subarray(0, buf.length - 2), sw: buf.readUInt16BE(buf.length - 2) };
  }

  /** POST /button/{left|right|both} {"action":"press-and-release","delay":0.1} */
  async button(which: "left" | "right" | "both", delay = 0.1): Promise<void> {
    const res = await fetch(`${this.base}/button/${which}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ action: "press-and-release", delay }),
    });
    if (!res.ok) throw new Error(`POST /button/${which} -> HTTP ${res.status}`);
  }

  /** GET /events?currentscreenonly=true -> {"events":[{text,x,y,w,h,clear}, ...]} */
  async currentScreen(): Promise<{ text: string; x: number; y: number }[]> {
    const res = await fetch(`${this.base}/events?currentscreenonly=true`);
    if (!res.ok) throw new Error(`GET /events -> HTTP ${res.status}`);
    return ((await res.json()) as { events: any[] }).events;
  }

  /** DELETE /events -> {} */
  async clearEvents(): Promise<void> {
    await fetch(`${this.base}/events`, { method: "DELETE" });
  }

  /** POST /automation — arm button rules BEFORE a blocking APDU */
  async setAutomation(rules: unknown): Promise<void> {
    const res = await fetch(`${this.base}/automation`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(rules),
    });
    if (!res.ok) throw new Error(`POST /automation -> HTTP ${res.status}`);
  }

  /** GET /screenshot -> image/png bytes */
  async screenshot(): Promise<Buffer> {
    const res = await fetch(`${this.base}/screenshot`);
    if (!res.ok) throw new Error(`GET /screenshot -> HTTP ${res.status}`);
    return Buffer.from(await res.arrayBuffer());
  }

  async waitReady(timeoutMs = 30_000): Promise<void> {
    const t0 = Date.now();
    for (;;) {
      try { await this.currentScreen(); return; } catch {
        if (Date.now() - t0 > timeoutMs) throw new Error("speculos not ready");
        await new Promise(r => setTimeout(r, 200));
      }
    }
  }
}
```

### Speculos raw TCP transport (port 9999) — correct 4-byte framing

CRITICAL and easy to get wrong: the outbound 4-byte BE length is len(response)-2, i.e. it EXCLUDES the status word, so you must read length+2 bytes. Ledger's own hw-transport-node-speculos assumes one TCP 'data' event per response, which breaks on segmentation — this version accumulates. Speculos keeps only ONE client socket, so hold a single long-lived connection.

```typescript
import net from "node:net";

export class SpeculosTcp {
  private sock!: net.Socket;
  private rx = Buffer.alloc(0);
  private queue: { resolve: (r: { data: Buffer; sw: number }) => void; reject: (e: Error) => void }[] = [];

  static connect(port = 9999, host = "127.0.0.1"): Promise<SpeculosTcp> {
    return new Promise((resolve, reject) => {
      const t = new SpeculosTcp();
      t.sock = net.createConnection({ port, host }, () => resolve(t));
      t.sock.on("error", reject);
      t.sock.on("data", (chunk) => t.onData(chunk));
    });
  }

  private onData(chunk: Buffer) {
    this.rx = Buffer.concat([this.rx, chunk]);
    for (;;) {
      if (this.rx.length < 4) return;
      const dataLen = this.rx.readUInt32BE(0);   // EXCLUDES the 2-byte SW
      const frameLen = 4 + dataLen + 2;          // ...so add 2
      if (this.rx.length < frameLen) return;
      const payload = this.rx.subarray(4, frameLen);
      this.rx = this.rx.subarray(frameLen);
      const w = this.queue.shift();
      w?.resolve({
        data: payload.subarray(0, payload.length - 2),
        sw: payload.readUInt16BE(payload.length - 2),
      });
    }
  }

  exchangeRaw(apdu: Buffer): Promise<{ data: Buffer; sw: number }> {
    return new Promise((resolve, reject) => {
      this.queue.push({ resolve, reject });
      const len = Buffer.alloc(4);
      len.writeUInt32BE(apdu.length, 0);        // inbound length = exact APDU length
      this.sock.write(Buffer.concat([len, apdu]));
    });
  }

  close() { this.sock.destroy(); }
}
```

### BIP32 path packing + APDU framing

Matches app-ethereum parseBip32() and hw-app-eth splitPath() exactly. Max 10 derivations. Note hw-app-eth's splitPath silently SKIPS non-numeric segments (so a leading "m" is dropped) — this version strips it explicitly and throws on garbage instead.

```typescript
export function packBip32Path(path: string): Buffer {
  const segs = path.replace(/^m\//, "").split("/").filter(Boolean);
  if (segs.length === 0 || segs.length > 10) throw new Error(`bad path: ${path}`);
  const out = Buffer.alloc(1 + segs.length * 4);
  out[0] = segs.length;
  segs.forEach((s, i) => {
    const hardened = s.endsWith("'") || s.endsWith("h") || s.endsWith("H");
    const n = Number.parseInt(s.replace(/['hH]$/, ""), 10);
    if (!Number.isInteger(n) || n < 0 || n > 0x7fffffff) throw new Error(`bad segment: ${s}`);
    out.writeUInt32BE((n + (hardened ? 0x80000000 : 0)) >>> 0, 1 + 4 * i);
  });
  return out;
}

/** Case-1..4 APDU: CLA INS P1 P2 Lc [data] — Lc is always emitted, even as 0x00. */
export function buildApdu(cla: number, ins: number, p1: number, p2: number, data: Buffer = Buffer.alloc(0)): Buffer {
  if (data.length > 255) throw new Error(`APDU data too long: ${data.length}`);
  return Buffer.concat([Buffer.from([cla, ins, p1, p2, data.length]), data]);
}
```

### GET ETH PUBLIC ADDRESS (INS 0x02) — request + response parsing

Response is 65||pubkey(65)||40||ascii(40)[||chainCode(32)]. The ASCII address is EIP-55 mixed case with no 0x — normalise through viem getAddress() so downstream comparisons don't fail on case. Example wire bytes for m/44'/60'/0'/0/0: e002000015058000002c8000003c800000000000000000000000

```typescript
import { getAddress, type Address, type Hex } from "viem";

export const ETH_CLA = 0xe0;
export const INS_GET_PUBLIC_KEY = 0x02;

export async function getEthAddress(
  t: { exchangeRaw(a: Buffer): Promise<{ data: Buffer; sw: number }> },
  path: string,
  opts: { display?: boolean; chainCode?: boolean; chainId?: bigint } = {},
): Promise<{ publicKey: Hex; address: Address; chainCode?: Hex }> {
  let data = packBip32Path(path);
  if (opts.chainId !== undefined) {
    const cid = Buffer.alloc(8);
    cid.writeBigUInt64BE(opts.chainId, 0);   // 8-byte big-endian, optional
    data = Buffer.concat([data, cid]);
  }
  const { data: r, sw } = await t.exchangeRaw(
    buildApdu(ETH_CLA, INS_GET_PUBLIC_KEY, opts.display ? 0x01 : 0x00, opts.chainCode ? 0x01 : 0x00, data),
  );
  if (sw !== 0x9000) throw new LedgerEthError(sw, "getAddress");

  let o = 0;
  const pkLen = r[o++];                       // 65
  const publicKey = r.subarray(o, o + pkLen); o += pkLen;
  const addrLen = r[o++];                     // 40
  const ascii = r.subarray(o, o + addrLen).toString("ascii"); o += addrLen;
  const chainCode = opts.chainCode ? r.subarray(o, o + 32) : undefined;

  return {
    publicKey: `0x${publicKey.toString("hex")}`,
    address: getAddress(`0x${ascii}`),        // device already checksums; re-normalise anyway
    chainCode: chainCode ? `0x${chainCode.toString("hex")}` : undefined,
  };
}
```

### GET APP CONFIGURATION (INS 0x06)

Wire bytes are exactly `e006000000` (5 bytes; the trailing 0x00 is Lc). Bit mapping taken from the CURRENT app source, not from hw-app-eth (whose 0x04/0x08 stark bits are dead).

```typescript
export async function getAppConfiguration(
  t: { exchangeRaw(a: Buffer): Promise<{ data: Buffer; sw: number }> },
) {
  const { data, sw } = await t.exchangeRaw(buildApdu(0xe0, 0x06, 0x00, 0x00));
  if (sw !== 0x9000) throw new LedgerEthError(sw, "getAppConfiguration");
  if (data.length < 4) throw new Error("short app config response");
  const flags = data[0];
  return {
    flags,
    blindSigningEnabled: (flags & 0x01) !== 0,   // APP_FLAG_DATA_ALLOWED
    erc20ProvisioningNecessary: (flags & 0x02) !== 0, // always set by firmware
    txChecksEnabled: (flags & 0x10) !== 0,       // APP_FLAG_TX_CHECKS_ENABLE
    txChecksOptIn: (flags & 0x20) !== 0,         // APP_FLAG_TX_CHECKS_OPT_IN
    version: `${data[1]}.${data[2]}.${data[3]}`,
  };
}
```

### SIGN ETH TRANSACTION (INS 0x04) — chunking, payload, v/r/s

The payload is literally viem's serializeTransaction(unsignedTx) with 0x stripped — I verified byte-for-byte equality with app-ethereum's own test-suite serializer for both legacy and EIP-1559. Type byte IS included for typed txs. Max chunk 255. deviceVToParity undoes the device's single-byte overflow for legacy.

```typescript
import { serializeTransaction, hexToBytes, type TransactionSerializable } from "viem";

const MAX_CHUNK = 255;
export const INS_SIGN = 0x04;
export const P1_FIRST = 0x00, P1_MORE = 0x80, P2_BASIC = 0x00;

/** Mirrors hw-app-eth safeChunkTransaction(): typed -> plain 255 split; legacy -> avoid
 *  a boundary that would leave the trailing (chainId,0,0) alone in the last chunk. */
export function chunkSignPayload(pathBuf: Buffer, tx: Buffer, isTyped: boolean): Buffer[] {
  const payload = Buffer.concat([pathBuf, tx]);
  if (payload.length <= MAX_CHUNK) return [payload];

  let size = MAX_CHUNK;
  if (!isTyped) {
    const VRS_TAIL_MAX = 35; // 1B list hdr + up to 32B v + 1B r + 1B s
    const last = payload.length % MAX_CHUNK;
    if (!(last === 0 || last > VRS_TAIL_MAX)) {
      for (let i = 1; i <= MAX_CHUNK; i++) {
        const l = payload.length % (MAX_CHUNK - i);
        if (l === 0 || l > VRS_TAIL_MAX) { size = MAX_CHUNK - i; break; }
      }
    }
  }
  const n = Math.ceil(payload.length / size);
  return Array.from({ length: n }, (_, i) => payload.subarray(i * size, (i + 1) * size));
}

/** Legacy: device v = (chainId*2+35+parity) mod 256. Recover parity, rebuild full v. */
export function deviceVToParity(vByte: number, chainId: bigint, txType: number): number {
  if (txType !== 0) return vByte;                 // typed: byte IS yParity (0|1)
  if (chainId === 0n) return vByte - 27;          // pre-EIP-155: device returns 27/28
  const chainIdU32 = Number(chainId & 0xffffffffn);
  const base = chainIdU32 * 2 + 35;
  if (base % 256 === vByte) return 0;
  if ((base + 1) % 256 === vByte) return 1;
  throw new Error(`cannot recover parity from device v=0x${vByte.toString(16)} (chainId ${chainId})`);
}

export async function signTransaction(
  t: { exchangeRaw(a: Buffer): Promise<{ data: Buffer; sw: number }> },
  path: string,
  unsigned: TransactionSerializable,
): Promise<{ r: `0x${string}`; s: `0x${string}`; v: bigint; yParity: number }> {
  // >>> This single line IS the exact payload the device expects. <<<
  const serialized = serializeTransaction(unsigned);          // no signature arg
  const txBytes = Buffer.from(hexToBytes(serialized));
  const typeByte = txBytes[0];
  const txType = typeByte <= 0x7f ? typeByte : 0;             // 0x01/0x02/0x04, else legacy
  if (txType !== 0 && ![0x01, 0x02, 0x04].includes(txType)) {
    throw new Error(`tx type 0x${txType.toString(16)} unsupported by the ETH app (expect SW 0x6501)`);
  }

  const chunks = chunkSignPayload(packBip32Path(path), txBytes, txType !== 0);
  let last!: { data: Buffer; sw: number };
  for (let i = 0; i < chunks.length; i++) {
    last = await t.exchangeRaw(
      buildApdu(ETH_CLA, INS_SIGN, i === 0 ? P1_FIRST : P1_MORE, P2_BASIC, chunks[i]),
    );
    if (last.sw !== 0x9000) throw new LedgerEthError(last.sw, "signTransaction");
  }
  if (last.data.length !== 65) throw new Error(`expected 65-byte signature, got ${last.data.length}`);

  const chainId = BigInt((unsigned as { chainId?: number | bigint }).chainId ?? 0);
  const yParity = deviceVToParity(last.data[0], chainId, txType);
  const v = txType === 0
    ? (chainId === 0n ? BigInt(27 + yParity) : chainId * 2n + 35n + BigInt(yParity))
    : BigInt(27 + yParity); // typed txs: pass yParity to viem, v is informational only

  return {
    r: `0x${last.data.subarray(1, 33).toString("hex")}`,
    s: `0x${last.data.subarray(33, 65).toString("hex")}`,
    v,
    yParity,
  };
}

/** Reassemble the broadcastable raw tx. */
export function toRawTransaction(unsigned: TransactionSerializable, sig: { r: `0x${string}`; s: `0x${string}`; v: bigint; yParity: number }) {
  const typed = (unsigned as { type?: string }).type && (unsigned as { type?: string }).type !== "legacy";
  return typed
    ? serializeTransaction(unsigned, { r: sig.r, s: sig.s, yParity: sig.yParity })
    : serializeTransaction(unsigned, { r: sig.r, s: sig.s, v: sig.v });
}
```

### Status word map + typed error

Merged from doc/ethapp.adoc's Status Words table, ledger-secure-sdk/include/status_words.h, device-sdk-ts ETH_APP_ERRORS, and the SWs the 1.22.3 handlers actually return. 0x6985 is what BOTH a rejected address confirmation and a rejected signature return.

```typescript
export const ETH_SW: Record<number, string> = {
  0x9000: "Success",
  0x6001: "Mode check fail",
  0x6501: "TransactionType not supported",
  0x6502: "Output buffer too small for chainId conversion",
  0x6800: "Not supported / internal error (no info)",
  0x6807: "Exception overflow",
  0x6980: "Command not allowed (wrong app state — e.g. P1=0x80 with no prior first chunk)",
  0x6982: "Security status not satisfied (cancelled by user)",
  0x6983: "Wrong data length",
  0x6984: "Plugin not installed / referenced data blocked",
  0x6985: "Condition not satisfied — USER DENIED / REJECTED",
  0x6a00: "Error without info",
  0x6a80: "Invalid data (often: blind signing / contract data not enabled in app settings)",
  0x6a84: "Insufficient memory",
  0x6a86: "Incorrect P1/P2",
  0x6a87: "Wrong data length",
  0x6a88: "Referenced data not found",
  0x6b00: "Incorrect parameter P1 or P2",
  0x6d00: "Incorrect parameter INS (wrong instruction / app not open?)",
  0x6e00: "Incorrect parameter CLA (wrong app is open)",
  0x6f00: "Technical problem (internal error)",
  0x911c: "Command code not supported (Ledger-PKI not available)",
};

export class LedgerEthError extends Error {
  constructor(public readonly sw: number, op: string) {
    const hex = `0x${sw.toString(16).padStart(4, "0")}`;
    let msg = ETH_SW[sw];
    if (!msg) {
      if ((sw & 0xff00) === 0x6800) msg = "Internal error (please report)";
      else if ((sw & 0xff00) === 0x6f00) msg = "Technical problem (please report)";
      else msg = "Unknown status word";
    }
    super(`${op} failed: SW=${hex} — ${msg}`);
  }
  get userRejected() { return this.sw === 0x6985 || this.sw === 0x6982; }
  get blindSigningRequired() { return this.sw === 0x6a80; }
}
```

### Driving the UI: pre-arm automation, or press buttons while /apdu blocks

POST /apdu does not return until the app answers, and for the last SIGN chunk the app sets IO_ASYNCH_REPLY. Approach A (automation) is race-free and preferred for CI. Approach B works because /button is a separate Flask resource and is not held by APDUBridge's endpoint_lock.

```typescript
// --- Approach A: pre-arm automation rules once, then just call signTransaction() ---
// Nano S+ review flow ends on an "Accept and send"/"Sign transaction" screen.
await sp.setAutomation({
  version: 1,
  rules: [
    // advance every review page
    { regexp: "^(Review|Amount|Address|Max fees|Network|Nonce|From|To)", actions: [["button", 2, true], ["button", 2, false]] },
    // confirm
    { regexp: "Accept|Approve|Sign",  actions: [["button", 1, true], ["button", 2, true], ["button", 1, false], ["button", 2, false]] },
  ],
});

// --- Approach B: manual, concurrent with the blocking POST ---
async function approveWhile<T>(sp: SpeculosHttp, p: Promise<T>, maxPresses = 40): Promise<T> {
  let done = false;
  p.finally(() => { done = true; });
  for (let i = 0; i < maxPresses && !done; i++) {
    await new Promise(r => setTimeout(r, 150));
    if (done) break;
    const screen = (await sp.currentScreen().catch(() => [])).map(e => e.text).join(" ");
    if (/Accept|Approve|Sign transaction|and send/i.test(screen)) await sp.button("both");
    else await sp.button("right");
  }
  return p;
}

// usage
const sig = await approveWhile(sp, signTransaction(sp, "44'/60'/0'/0/0", unsignedTx));

// --- Enable Blind signing on Nano S+ from the app home screen (needed only for calldata) ---
// order derived from app-ethereum tests/ragger/client/settings.py
async function enableBlindSigningNanoSP(sp: SpeculosHttp) {
  await sp.button("right"); // home -> Settings
  await sp.button("both");  // enter Settings (cursor on "Blind signing")
  await sp.button("both");  // toggle Blind signing
  for (let i = 0; i < 6; i++) await sp.button("right"); // walk past the 6 settings entries
  await sp.button("both");  // Back
}
```

### Fetch the Ethereum app ELF for Speculos

Verified: app-1.22.3-nanos2.elf downloads unauthenticated (282928 bytes, ARM EABI5 ELF). `nanos2` is the Nano S+ target and maps to Speculos `--model nanosp`. No build, no ledger-app-builder needed.

```bash
mkdir -p apps && cd apps

VER=1.22.3   # latest release as of 2026-09; check `gh release list -R LedgerHQ/app-ethereum`

# Nano S+  (target name in the asset is "nanos2"; speculos model is "nanosp")
curl -fL -o eth-nanosp.elf \
  "https://github.com/LedgerHQ/app-ethereum/releases/download/${VER}/app-${VER}-nanos2.elf"

# other targets if you want them
# curl -fL -o eth-nanox.elf  ".../app-${VER}-nanox.elf"
# curl -fL -o eth-flex.elf   ".../app-${VER}-flex.elf"
# curl -fL -o eth-stax.elf   ".../app-${VER}-stax.elf"
# curl -fL -o eth-apexp.elf  ".../app-${VER}-apex_p.elf"

file eth-nanosp.elf
# => ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, not stripped

# List every available asset/version programmatically:
# gh api repos/LedgerHQ/app-ethereum/releases --jq '.[]|.tag_name,(.assets[]|"  "+.name+"  "+.browser_download_url)'
```

### Docker run: Speculos + Ethereum app, API 5000 + APDU 9999

Verified against the repo Dockerfile (WORKDIR /speculos, ENTRYPOINT ["python","./speculos.py"]) and main.py (--api-port default 5000, --apdu-port default 9999, both bound to 0.0.0.0 so -p works). Image is multi-arch amd64+arm64, so it runs natively on Apple Silicon. Only the `latest` tag exists (plus sha- tags).

```bash
docker pull ghcr.io/ledgerhq/speculos:latest

SEED="glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"

docker run --rm -d --name speculos-eth \
  -v "$PWD/apps:/speculos/apps" \
  -p 5000:5000 \
  -p 9999:9999 \
  -e SPECULOS_APPNAME=Ethereum:1.22.3 \
  ghcr.io/ledgerhq/speculos:latest \
    --model nanosp \
    --display headless \
    --api-port 5000 \
    --apdu-port 9999 \
    --seed "$SEED" \
    apps/eth-nanosp.elf

# wait until the API answers
until curl -sf 'http://127.0.0.1:5000/events?currentscreenonly=true' >/dev/null; do sleep 0.3; done

# --- smoke tests (all verified byte sequences) ---

# GET APP CONFIGURATION -> {"data":"<flags><maj><min><patch>9000"}
curl -s -X POST http://127.0.0.1:5000/apdu \
  -H 'content-type: application/json' \
  -d '{"data":"e006000000"}'

# GET ETH PUBLIC ADDRESS, m/44'/60'/0'/0/0, silent, no chain code
# expected address for the default seed: 0xDad77910DbDFdE764fC21FCD4E74D71bBACA6D8D
curl -s -X POST http://127.0.0.1:5000/apdu \
  -H 'content-type: application/json' \
  -d '{"data":"e002000015058000002c8000003c800000000000000000000000"}'

# SIGN, EIP-1559 chainId=1 (blocks until approved -> press buttons in another shell)
# payload = path(21B) || 0x02 || rlp([...])
curl -s -X POST http://127.0.0.1:5000/apdu \
  -H 'content-type: application/json' \
  -d '{"data":"e004000047058000002c8000003c80000000000000000000000002f00115843b9aca008504a817c800825208940011223344556677889900112233445566778899880de0b6b3a764000080c0"}' &
sleep 0.5
for i in 1 2 3 4 5 6 7 8; do curl -s -X POST http://127.0.0.1:5000/button/right -H 'content-type: application/json' -d '{"action":"press-and-release"}'; done
curl -s -X POST http://127.0.0.1:5000/button/both -H 'content-type: application/json' -d '{"action":"press-and-release"}'
wait

# raw TCP smoke test: 4-byte BE length prefix + APDU
printf '\x00\x00\x00\x05\xe0\x06\x00\x00\x00' | nc 127.0.0.1 9999 | xxd
# => 00000000: 0000 0004 02xx xxxx 9000   (len=4 EXCLUDES the 9000 SW)

docker logs -f speculos-eth   # shows 'apdu: >' / 'apdu: <' traces
docker rm -f speculos-eth
```

### docker compose variant

Equivalent to the docker run above. Ports 5000 and 9999 published; the ELF comes from ./apps.

```yaml
services:
  speculos:
    image: ghcr.io/ledgerhq/speculos:latest
    container_name: speculos-eth
    volumes:
      - ./apps:/speculos/apps
    ports:
      - "5000:5000"   # REST API
      - "9999:9999"   # raw APDU TCP
    environment:
      SPECULOS_APPNAME: "Ethereum:1.22.3"
    command:
      - "--model"
      - "nanosp"
      - "--display"
      - "headless"
      - "--api-port"
      - "5000"
      - "--apdu-port"
      - "9999"
      - "--seed"
      - "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"
      - "apps/eth-nanosp.elf"
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request;urllib.request.urlopen('http://127.0.0.1:5000/events?currentscreenonly=true')"]
      interval: 2s
      timeout: 2s
      retries: 30
```

### Fallback: build the ELF yourself with ledger-app-builder

Only needed if you want an unreleased commit. The prebuilt release ELFs above are simpler. SDK env vars inside the container: $NANOX_SDK, $NANOS2_SDK (Nano S+), $FLEX_SDK, $STAX_SDK. Output lands at build/<target>/bin/app.elf on the host.

```bash
git clone https://github.com/LedgerHQ/app-ethereum.git
cd app-ethereum

docker pull ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest

docker run --rm -v "$(realpath .):/app" \
  ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest \
  bash -lc 'make BOLOS_SDK=$NANOS2_SDK -j'

ls -la build/nanos2/bin/app.elf   # feed this to speculos
```

## Unverified — do not rely on these

- I could NOT execute anything end-to-end: `docker` is not installed on this machine and the `speculos` Python package is not importable. Every APDU byte string I give is derived from source reading plus local reimplementation of the encoders, not from a live device round-trip. To verify: install Docker (or `pipx install speculos`), run the docker command in the snippets, and execute the three curl smoke tests. Specifically unverified-by-execution: the exact number of right-button presses in the Nano S+ EIP-1559 review flow (the nanosp snapshot dir for test_sign_simple holds 7 PNGs, suggesting ~7 screens for a legacy transfer, but screen count varies by tx type and app version) — use the screen-text-driven loop or automation regexps rather than a hard-coded press count.
- Whether app-ethereum 1.22.3 requires a Ledger-PKI certificate exchange (INS 0x20 GET CHALLENGE + the PKI cert APDUs) before a plain GET ADDRESS / SIGN on Speculos. The 1.22.x source gained `src/ledger_pki.c` and a `dbg_no_checks` build variant (`BYPASS_SIGNATURES=1 CHALLENGE_NO_CHECK=1`), and the released ELFs are the production variant. Basic sign/getAddress code paths contain no PKI gate that I could find, but I did not run it. If you hit 0x911c on a basic call, drop to an older release (e.g. 1.22.0) or build the dbg_no_checks variant.
- Whether the HAVE_TRANSACTION_CHECKS / tx-simulation feature (flags 0x10/0x20) is compiled into the Nano S+ release ELF and whether it can block signing. It is opt-in and I saw no blocking path for nanosp, but I did not confirm by running GET APP CONFIGURATION against the real ELF. Read byte 0 of the config response at startup and log it.
- The exact behaviour of the `xGTn` case in the legacy v byte (`if (info & CX_ECCINFO_xGTn) G_io_tx_buffer[0] += 2;`). hw-app-eth's getParity does NOT account for the +2, so a signature where x > n would make getParity throw "Invalid v value". This is astronomically rare (probability ~2^-128) and every Ledger host library ignores it; I did not find any handling for it anywhere. Treat a thrown "cannot recover parity" as retryable.
- For chainIds larger than 2^32, the device truncates to the top 4 bytes of the minimal big-endian encoding (`MIN(4, vLength)` device-side, `chainIdBuff.subarray(0,4)` host-side). I reproduced the host algorithm but did not test a >2^32 chainId against the device. Unlikely to matter for your use case.
- Whether Speculos persists the app's NVRAM (the Blind signing toggle) across container restarts. I found no `--nvram` style flag in main.py's argument list, which implies NVRAM is in-process and resets on every start — so you must re-toggle Blind signing after each restart. I did not exhaustively read every CLI flag, so a persistence option may exist.
- `GET /events` with `stream=true` is documented as text/event-stream emitting `data: {json}\n\n`. I read the generator that produces it but did not consume a live stream, so I cannot confirm whether keep-alive/comment lines appear between events. Ledger's own SpeculosHttpTransport just filters lines starting with `data: `, which is the safe parse.
- The `POST /apdu` `tick_timeout` unit. It is a number of emulated ticks with a default of `5 * 60 * 10` = 3000, compared against `seph.get_tick_count()` deltas. The wall-clock equivalent depends on the tick rate, which I did not trace. Prefer omitting it and enforcing your own timeout with AbortController.

## Requires a human: accounts, keys, faucets

- Install Docker Desktop / Colima on this Mac — `docker` is currently not on PATH, so I could not start Speculos or validate a single APDU round-trip. This is the one blocker to end-to-end verification.
- Run the ELF download yourself if you need it inside the repo: `curl -fL -o apps/eth-nanosp.elf https://github.com/LedgerHQ/app-ethereum/releases/download/1.22.3/app-1.22.3-nanos2.elf`. (I already fetched a copy to the scratchpad at /private/tmp/claude-501/-Users-uday-Projects-Yagna/71783018-32e1-44a2-8503-e408ac74efe6/scratchpad/eth-nanos2.elf — 282928 bytes — you can just move it.)
- Decide and record the test mnemonic. If you use the Speculos default seed, the signer's address is 0xDad77910DbDFdE764fC21FCD4E74D71bBACA6D8D at m/44'/60'/0'/0/0 — fund THAT address on whatever testnet Arx targets. If you pass your own `--seed`, derive and fund the corresponding address instead.
- Fund the derived address with testnet ETH from a faucet if any test broadcasts a transaction (signing itself needs no funds).
- No API keys, accounts, or signups are needed for anything else here: the app-ethereum release ELFs and ghcr.io/ledgerhq/speculos are both public and pull anonymously (I verified both unauthenticated).

## Recommendations

- Use the HTTP transport on port 5000, not the raw TCP on 9999. The TCP framing has a genuine foot-gun (the 4-byte length excludes the SW, so you must read length+2) and Speculos holds only one client socket, while the HTTP endpoint is a plain fetch with the SW already in the hex. Highest value per line of code by a wide margin.
- Build the SIGN payload with exactly one line: `serializeTransaction(unsignedTx)` from viem, no signature argument, 0x stripped. I proved byte-for-byte equality with app-ethereum's own test-suite serializer for both legacy (EIP-155 preimage `rlp([...,chainId,0x80,0x80])`) and EIP-1559 (`0x02 || rlp([...])`). Do NOT hand-roll RLP — that is where a 24-hour build loses hours.
- Use 255 as the chunk size, not 150. The 150 you were told about only applies to `signPersonalMessage`/EIP-712 in hw-app-eth. Using 150 for INS 0x04 still works (it is just more APDUs) but would be needlessly slow; using >255 is impossible since Lc is a single byte.
- If Arx only ever signs EIP-1559 (type 2) transactions, skip the legacy branch entirely: chunking is a plain 255-byte split, the type byte prefix is already in viem's output, and the v byte IS the yParity with no arithmetic. That removes the whole EIP-155 overflow-recovery code path — the single largest source of subtle bugs here.
- Pre-arm `POST /automation` once at startup instead of polling screens. `POST /apdu` blocks until the user approves, so a naive await deadlocks. One automation document with a regexp rule for review pages (right button) and one for the confirm screen (both buttons) makes `signTransaction()` a normal awaitable with no orchestration. Keep the screen-text-polling loop only as a debug fallback.
- Keep transactions calldata-free where you can (`data: '0x'`). Blind signing (`N_storage.dataAllowed`) defaults to OFF on every fresh Speculos start, and the app returns 0x6A80 for any non-empty data field. If Arx must sign contract calls, call `enableBlindSigningNanoSP()` once after the container is ready (right, both, both, right×6, both) and assert `getAppConfiguration().blindSigningEnabled === true` before proceeding — that assertion will save you from a confusing 0x6A80.
- Normalise the returned address through viem's `getAddress()`. The device returns 40 mixed-case EIP-55 ASCII chars with no 0x, so a naive string compare against a lowercase address will silently fail.
- Pin the app version in both the download and the container name (e.g. 1.22.3). The releases move weekly; a floating `latest` for the ELF would make your test suite nondeterministic. Pin `ghcr.io/ledgerhq/speculos` by sha digest too if reproducibility matters, since only `latest` is tagged.
- Assert the smoke-test invariants in a single startup check: GET APP CONFIGURATION returns 4 bytes and a version string; GET ADDRESS at m/44'/60'/0'/0/0 returns 0xDad77910DbDFdE764fC21FCD4E74D71bBACA6D8D under the default seed. Both are non-interactive (no button presses) and catch a wrong ELF, wrong model, wrong seed, or wrong APDU encoding in one second.
- Implement `LedgerEthError` with the `userRejected` (0x6985/0x6982) and `blindSigningRequired` (0x6A80) helpers from the snippet. Those two SWs account for essentially every failure you will actually hit, and mapping them to clear messages is worth far more than covering the long tail.
- Skip `PROVIDE NETWORK INFORMATION` (INS 0x30), plugins, ERC-20 token info, EIP-712, and Ledger-PKI for now. app-ethereum's own sign tests provide network info only for chainIds 3/5/56/137, and never for mainnet; everything else is cosmetic display metadata. Signing works without any of it.
- Do NOT build the ELF with ledger-app-builder. The GitHub release assets are prebuilt for all five targets and download unauthenticated in under a second — the Docker build route costs you tens of minutes for zero benefit unless you need an unreleased commit.
- Run the container detached with a readiness loop (`until curl -sf .../events?currentscreenonly=true`), not a fixed sleep. Speculos takes a variable second or two to come up and a fixed sleep is the classic flaky-CI cause.
- If you do keep the TCP transport, accumulate into a buffer as in my snippet rather than copying Ledger's `decodeAPDUPayload`, which assumes one socket 'data' event per response and throws "Expected payload of length N but got M" on segmentation — a real bug for the 107-byte GET ADDRESS response over a slow link.
