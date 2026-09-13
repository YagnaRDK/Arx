# The Ledger Key Ring and the capability broker

An operator runbook for `src/broker/`. It covers why an agent must never hold a
credential, how to provision the Ledger Key Ring, how Arx seals and unseals,
how to run the broker on a host with no USB port, and — stated plainly, because
the whole value here is a trust claim — exactly what the local development
fallback does and does not give you.

Run the demonstration first; it takes a few seconds and needs no hardware:

```bash
bun run scripts/keyring-demo.ts
```

It seals a fake upstream API key, issues a scoped token, lets an agent complete
a real authorized action without ever receiving the secret, and then shows four
ways that same token stops working. It prints the Key Ring status either way and
says loudly when it fell back to the local seal. The exit code is the contract.

---

## 1. Why the agent must not hold the credential

An agent given an API key holds it for as long as the key lives. Everything that
can read the agent's process — its memory, its environment, its logs, its
transcript, its prompt context — gets the key too. That is true before you add
any adversary.

Then add one. Prompt injection turns "the agent can call the API" into "whoever
wrote the text in the agent's context can call the API", and — worse — into
"whoever wrote that text can ask the agent to print the key". The agent is not
malfunctioning when it complies. It was convinced. This is the lethal trifecta:
untrusted input, autonomous execution, and access to real resources, in one
process.

You cannot fix this by making the agent more careful, because the agent is the
part that can be talked into things. You fix it by not giving it the credential.

So Arx holds the secret sealed, issues the agent a **scoped capability token**
instead, and — when the agent wants the secret _used_ — unseals just-in-time,
performs the authorized action inside Arx's own stack frame, and returns only
the result. The agent cannot disclose what it does not have. The blast radius of
a fully compromised agent shrinks from _"the credential"_ to _"the actions its
token currently authorizes"_, which is a bounded, revocable, expiring set.

Ledger's Track 01 brief names this pattern verbatim: _"Agents that use secrets
they cannot leak: a broker hands out scoped capabilities, never the API key."_

### Where the Key Ring comes in

Sealing with a passphrase that lives next to the ciphertext moves the problem
rather than solving it: whatever can read the sealed file can usually read the
passphrase. The **Ledger Key Ring (LKRP)** roots the unseal in a trustchain the
agent process cannot reconstruct on its own, so an attacker with Arx's disk
still has nothing usable.

And one property of it makes the whole deployment story work, so it deserves to
be stated before anything else:

> After `ring init`, `ring encrypt` and `ring decrypt` need **network access**
> to restore the trustchain, but they do **not** need the device.

Provision once, with a device, by hand. Then decrypt on a VPS, a CI runner, or
a hosted agent that has no USB port and never will. That is §4.

---

## 2. Provisioning: the exact `ring init` sequence

`ring init` is an **operator** action. Arx never attempts it, and an agent must
never drive it. Two independent reasons: it requires a physically attached,
unlocked device, and it requires a password that — per Ledger's own guidance —
an agent must not choose, type, or handle.

### 2.1 Store the ring password in your OS keychain first

Do this **before** any agent or script touches the CLI.

```bash
# macOS — prompts for the password, stores it, prints nothing back
security add-generic-password -a default -s ledger-wallet-cli -w

# Linux
secret-tool store --label="ledger-wallet-cli" service ledger-wallet-cli account default
```

Then inject it by **command substitution only**, never as a literal:

```bash
# macOS
WALLET_PASS=$(security find-generic-password -a default -s ledger-wallet-cli -w) \
  bunx @ledgerhq/wallet-cli@2.1.0 ring init --name arx-broker-laptop

# Linux
WALLET_PASS=$(secret-tool lookup service ledger-wallet-cli account default) \
  bunx @ledgerhq/wallet-cli@2.1.0 ring init --name arx-broker-laptop
```

The `ring` commands read the password from `WALLET_PASS` whenever there is no
interactive terminal — which is the case in CI and whenever an agent runs the
command.

**Never write the password literally.** `WALLET_PASS=hunter2 wallet-cli …` leaks
into shell history, `ps` output, CI logs, and, when an agent runs it, the agent
transcript. This applies to throwaway test passwords too, because the same
command shape gets reused with a real one.

`ring init --unsecure-no-password` exists. Ledger's own documentation says not
to use it for anything holding real data, and Arx's guidance is the same: a ring
with no password is not a boundary, it is a filename.

### 2.2 What `ring init` needs

| Requirement | Detail                                                                                                                                                                                                        |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Device      | A physically attached, unlocked Ledger. USB.                                                                                                                                                                  |
| Device app  | The ring is provisioned "via the Ledger Sync app" per Ledger's own CLI skill. If it is not installed, expect `ring init` to fail.                                                                             |
| Password    | From the environment (`WALLET_PASS`), provided by a human.                                                                                                                                                    |
| Network     | Yes — the trustchain lives on Ledger's LKRP backend.                                                                                                                                                          |
| TTY         | Not required once `WALLET_PASS` is set.                                                                                                                                                                       |
| Sandbox     | The official skill requires `dangerouslyDisableSandbox: true` for `ring` commands: `encrypt`/`decrypt`/`keys`/`destroy` are blocked by OS keychain restrictions, and `init` additionally by USB restrictions. |

`--name <host>` labels this machine as a ring member. Name it after the host, not
the person: you will read this list later when deciding what to remove.

**Never run two device commands in parallel.** They fail with `[object Object]`
or a garbled APDU. Run them sequentially.

### 2.3 Confirm it worked

```bash
bunx @ledgerhq/wallet-cli@2.1.0 ring keys --output json
```

and then, from Arx:

```bash
curl -s localhost:3000/broker/status | jq
```

`keyRing.initialized` must be `true` and `hardwareRooted` must be `true`. If
`hardwareRooted` is `false`, Arx is using the local development seal — see §5.

---

## 3. How Arx seals and unseals

Three files, each with one job:

| File                                | Role                                                                            |
| ----------------------------------- | ------------------------------------------------------------------------------- |
| `src/broker/ring-cli.ts`            | The `wallet-cli ring` subprocess wrapper. Reports availability, seals, unseals. |
| `src/broker/sealed-secret-store.ts` | Where sealed secrets live, and which backend sealed each one.                   |
| `src/broker/capability-broker.ts`   | Issues, validates and revokes scoped tokens; performs the brokered action.      |

### 3.1 Sealing

```
operator → POST /broker/secrets {name, secret}      (admin credential required)
             │
             ├─ activeBackend()
             │     ring keys → initialized ? "ledger-keyring" : "local-dev"
             │
             ├─ ledger-keyring : ring encrypt --key arx-broker-<name>
             │  local-dev      : scrypt(N=16384,r=8,p=1) → AES-256-GCM
             │
             └─ store { name, backend, ciphertext, plaintextDigest, keyName }
```

The response deliberately returns neither the plaintext nor the ciphertext —
only the name, the backend, `hardwareRooted`, the ring key name and a timestamp.

`keyName` defaults to `arx-broker-<name>`, and the Key Ring derives a distinct
AES-256-GCM key per name (HKDF-SHA256 from the LKRP root). That is what scopes a
seal: a secret sealed for one purpose cannot be unsealed by a broker configured
for another. `--key` is mandatory and must match exactly at decrypt time.

`plaintextDigest` is a SHA-256 of the plaintext. It is stored so that an unseal
can be _checked_ without keeping the plaintext anywhere: after decrypting, Arx
re-digests and compares. A mismatch is an error, never a silently wrong secret.

### 3.2 Unsealing, just-in-time

```
agent → "use the invoice API for INV-2026-0912" + bearer token
          │
      broker.verify(bearer, capability)        ← nine checks, all fail-closed
          │
      token.grants.includes(secretName) ?      ← no → FORBIDDEN
          │
      secrets.unseal(secretName)               ← ring decrypt, or local unseal
          │
      use(plaintext)  ───────────────────────→ the upstream call
          │                                      (inside Arx's stack frame)
      return { result, provenance }            ← the agent sees only this
```

`verify()` refuses on all of: a malformed bearer, an unknown token id, a bad
checksum (compared in constant time), a signature that does not verify against
Arx's authorization key, expiry, a capability-id mismatch, an agent-id mismatch,
a capability that is not `ACTIVE`, and a policy hash that no longer matches the
capability. Defaults deny throughout.

`provenance` records which secret was used, by which token, under which backend,
and whether that backend was hardware-rooted. It is written to the broker's
history and carries no secret material.

**An accepted limitation, stated because it is real rather than overlooked:**
there is no way to wipe a JavaScript string. The design constraint is therefore
that the plaintext never escapes the `use` callback's scope and is never
persisted or logged — not that it is scrubbed from memory afterwards. On a host
where an attacker can read Arx's process memory at will, the Key Ring's
guarantee is about the sealed file, not about that moment.

### 3.3 Why tokens die when the policy changes

A token carries `policyHash` — a digest of the authority-bearing fields of the
capability as they stood at issue time. `verify()` recomputes it from the
capability in force and refuses on any difference.

So narrowing a policy invalidates every token minted under the looser one.
Authority cannot outlive the justification for it, and the operator does not
have to hunt down outstanding tokens.

Cosmetic fields are excluded from the hash on purpose — relabelling a capability
grants exactly the same authority, so live tokens survive the edit. Anything
that changes what is permitted does not.

Two more bounds worth knowing:

- TTL is capped at 3600s and defaults to 300s. The natural state of a capability
  token is "about to expire".
- `expiresAt` is `min(now + ttl, capability.expiresAt)`. A token can never
  outlive the capability that justified it.

---

## 4. The USB-less host: provision on a laptop, decrypt on a VPS

This is Ledger's other stated direction — _"Bring the Key Ring to hosts with no
USB port: enroll a VPS, a CI runner, or a hosted agent"_ — and it works because
of the property in §1: after `ring init`, `encrypt`/`decrypt` need network but
not the device.

### On the laptop, with the device attached — once, by a human

```bash
# 1. Password into the keychain (once, ever).
security add-generic-password -a default -s ledger-wallet-cli -w

# 2. Provision this machine as a ring member. Confirm on the device.
WALLET_PASS=$(security find-generic-password -a default -s ledger-wallet-cli -w) \
  bunx @ledgerhq/wallet-cli@2.1.0 ring init --name arx-broker-laptop

# 3. Seal the upstream credential. Output goes to a FILE, never to the terminal.
printf '%s' "$UPSTREAM_API_KEY" > /dev/shm/upstream.key
WALLET_PASS=$(security find-generic-password -a default -s ledger-wallet-cli -w) \
  bunx @ledgerhq/wallet-cli@2.1.0 ring encrypt --key arx-broker-invoice-api-key \
    -i /dev/shm/upstream.key -o upstream.key.enc
shred -u /dev/shm/upstream.key 2>/dev/null || rm -f /dev/shm/upstream.key

# 4. upstream.key.enc is safe to commit, or to hand to a deploy pipeline.
```

### On the VPS or CI runner — no device, ever

The host needs two things and neither is hardware:

1. **Network access** to Ledger's LKRP backend, so the trustchain can be
   restored on each invocation.
2. **The ring password**, delivered the way you already deliver secrets — a
   GitHub Actions secret, a systemd credential, Doppler, Vault. Read it into
   `WALLET_PASS` by substitution, never as a literal.

```bash
WALLET_PASS="$(cat /run/credentials/arx.service/wallet-pass)" \
  bunx @ledgerhq/wallet-cli@2.1.0 ring decrypt --key arx-broker-invoice-api-key \
    -i upstream.key.enc -o /dev/shm/upstream.key
```

Then start Arx, which seals it into its own store and brokers it from there.

**The honest framing of what this buys you.** The Key Ring removes the need to
host the _secrets_. It does not remove the need to deliver the ring _password_.
You have replaced "N long-lived credentials distributed to N hosts" with "one
password per host, and ciphertext that is useless without it, revocable by
removing that host from the ring". That is a genuine and large improvement. It
is not "no secret on the host", and anyone who tells you it is has skipped a
step.

### Removing a host, and the rotation trap

Removing a ring member **rotates** the LKRP root key. That is the point — it is
how you de-authorize a compromised VPS. But it has a consequence that will
otherwise surprise you at the worst possible moment:

> After a rotation, data encrypted **before** it can no longer be decrypted.

Decrypt fails with _"wrong key name, corrupted data, or the Ledger Key Ring
rotated"_ and the CLI prints `⚠ Ledger Key Ring rotated`. **Re-encrypt every
sealed secret after removing a member**, from a machine that is still a ring
member, and redistribute the new ciphertext. Put that in your runbook next to
"revoke the host", not in a footnote.

`ring destroy` tears down the remote LKRP application _and_ wipes local member
credentials. It aborts with no changes on a wrong password, and also if
`WALLET_PASS` is set but empty — an empty value is treated as a failed keychain
lookup rather than a skip, so it cannot orphan the remote ring by accident.

---

## 5. The local development fallback, frankly

With no Key Ring provisioned, `activeBackend()` returns `local-dev` and the seal
becomes scrypt (N=16384, r=8, p=1) plus AES-256-GCM from
`ARX_LOCAL_SEAL_PASSPHRASE`.

### What it gives you

- The broker's controls in full: scoping, expiry, policy binding, revocation,
  just-in-time unsealing, and the property that the agent never receives the
  secret. Those are the parts `tests/capability-broker.test.ts` and
  `scripts/keyring-demo.ts` exercise, and they are backend-independent.
- A clone that runs with no hardware and no accounts, so nothing about the
  demonstration depends on owning a Ledger.
- Real authenticated encryption. The ciphertext is not obfuscation.

### What it does not give you

- **Any hardware root.** The key is derived from a passphrase in the
  environment. Whatever can read the sealed store can very often read that
  passphrase too, and then the seal is decoration.
- Trustchain-based revocation. You cannot de-authorize a host by removing it
  from a ring, because there is no ring.
- Any claim that a Ledger was involved. It was not.

### How you can tell, always

`hardwareRooted: false`, everywhere and without exception:

- in `UnsealResult`, on every unseal;
- in `BrokeredUse` provenance, on every brokered action, and therefore in the
  broker's history;
- in `GET /broker/status` and in `GET /integrations`;
- in `POST /broker/secrets` responses, per sealed secret;
- on screen in `scripts/keyring-demo.ts`, in amber, twice.

This is deliberate and it is the most important line in the module. A seal whose
provenance is unclear is worse than no seal at all, because it invites exactly
the misplaced trust that a security boundary exists to prevent. Arx would rather
say "this is a development seal" ten times than let one reader assume hardware.

If `ARX_LOCAL_SEAL_PASSPHRASE` is unset and no Key Ring is provisioned, sealing
**fails** rather than falling back to something weaker again. There is no third
backend.

---

## 6. Scripting the CLI: exit codes, streams, and flags

Anyone automating `wallet-cli ring` will hit these. They were observed by
running the real CLI, not read from documentation — the transcripts below are
verbatim from `@ledgerhq/wallet-cli@2.1.0` on macOS (arm64) on 2026-09-12, on a
host with no ring provisioned.

### 6.1 Failures exit 1 — but "command not found" exits 0

```console
$ bunx @ledgerhq/wallet-cli@2.1.0 ring keys --output json
{"ok":false,"error":{"command":"ring keys","message":"Ledger Key Ring not initialized. Run `wallet-cli ring init` first."}}
$ echo $?
1
```

```console
$ bunx @ledgerhq/wallet-cli@2.1.0 ring keys --help
{
  "ok": false,
  "error": {
    "kind": "command-not-found",
    "message": "Command 'ring keys --help' not found. Did you mean 'ring'?",
    ...
  }
}
$ echo $?
0
```

Two things there. First, `--help` is not supported on a subcommand — it is
parsed as _part of the command name_. Use bare `wallet-cli ring`, which prints
the subcommand help as JSON. Second, and more dangerous: that failure **exits
0**, so a script that trusts the exit status treats a typo'd command as success.

The defensive rule, and what `ring-cli.ts` does: **parse the JSON body and
branch on `ok`.** Never branch on the exit status alone, in either direction.

> Note on earlier notes: this repository's `FEEDBACK.md` and the header comment
> in `src/broker/ring-cli.ts` state that `ring keys` exits 0 on failure and
> prints a human tip line before its JSON under `--output json`. Neither
> reproduced on 2.1.0 in the run above: `ring keys` exited 1 and stdout was pure
> JSON. The exit-0-on-failure behaviour is real, but it belongs to
> `command-not-found`. The code is correct either way, because it does not trust
> the exit status; the prose is being corrected rather than quietly kept.

### 6.2 Which stream the error lands on depends on `--output`

```console
$ bunx @ledgerhq/wallet-cli@2.1.0 ring keys          # human mode (the default)
# stdout: empty
# stderr: the error, pretty-printed JSON
$ echo $?
1
```

Under `--output json` the error JSON goes to **stdout**, compact. In human mode
stdout is **empty** and the error goes to **stderr**, indented. So a wrapper has
to read both streams; reading only stdout in the default mode gets you an empty
string and no reason.

### 6.3 `--output json` and `ring encrypt` are mutually exclusive on stdout

```console
$ printf 'hello' | bunx @ledgerhq/wallet-cli@2.1.0 ring encrypt --key arx-test --output json
{"ok":false,"error":{"command":"ring encrypt","message":"--output json requires --out <file>: binary ciphertext cannot be written as JSON to stdout."}}
$ echo $?
1
```

That message is also the clearest statement anywhere of an important fact: **the
ciphertext is binary**, not armoured text. Plan for bytes. Both `-o` and `--out`
are accepted.

### 6.4 `--key` is mandatory; unknown flags are ignored

```console
$ printf 'hello' | bunx @ledgerhq/wallet-cli@2.1.0 ring encrypt
# stderr, exit 1:
#   "kind": "validation", "name": "BunliValidationError",
#   "message": "Invalid option 'key': Invalid input: expected string, received undefined"
```

```console
$ printf 'hello' | bunx @ledgerhq/wallet-cli@2.1.0 ring encrypt --key arx-test --bogus
# --bogus is silently accepted; the command proceeds to the ring check.
```

A misspelled flag is therefore not an error. It is a missing behaviour with no
warning, which is worse. Validate your own arguments before handing them over.

### 6.5 Never let a decrypt reach a terminal

`ring decrypt` emits the secret. Sent to stdout in an agent or CI context it
lands in the transcript, the logs and the scrollback, and any one of those
outlives the process. Always use `-o <file>`, or pipe it straight into the
consuming process. Arx reads it over a pipe into memory and never writes it
down.

### 6.6 Summary of the operational quirks

| Quirk                                         | Consequence for a caller                                      |
| --------------------------------------------- | ------------------------------------------------------------- |
| `command-not-found` exits 0                   | Branch on the JSON `ok` field, not on the exit status         |
| Error stream depends on `--output`            | Read stdout _and_ stderr                                      |
| `ring encrypt --output json` requires `--out` | Ciphertext is binary; do not expect text                      |
| Unknown flags silently ignored                | Validate arguments yourself                                   |
| `--help` unsupported per subcommand           | Use bare `wallet-cli ring`                                    |
| Ring commands need keychain access            | The official skill requires `dangerouslyDisableSandbox: true` |
| Two device commands in parallel               | Fail with `[object Object]`; serialise them                   |
| Removing a member rotates the root            | Re-encrypt everything sealed before the rotation              |
| `ring keys` is a local cache                  | It lists keys _this machine_ used, and needs no network       |

---

## 7. Configuration

| Variable                    | Meaning                                                                                                                                                                         |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ARX_SEALED_SECRETS_PATH`   | Where the sealed store lives. Written `0600`. Default `./data/sealed-secrets.json`.                                                                                             |
| `ARX_LOCAL_SEAL_PASSPHRASE` | Passphrase for the local development seal. Used **only** when no Key Ring is provisioned. Unset means local sealing fails rather than weakening.                                |
| `ARX_WALLET_CLI_PACKAGE`    | The pinned CLI, default `@ledgerhq/wallet-cli@2.1.0`. Pinned deliberately: an unpinned `bunx` would let a future release change the seal format underneath existing ciphertext. |
| `WALLET_PASS`               | The ring password. Provided by a human, by command substitution from a keychain. Never by an agent, never as a literal.                                                         |

The store is cached in memory and reloaded from disk at construction. A corrupt
store file raises rather than becoming an empty one — a missing secret must not
be indistinguishable from a secret that was never configured.

---

## 8. Verified, and not verified

### Verified by execution, on this machine

- **The broker's controls.** `tests/capability-broker.test.ts` — sealing without
  retaining plaintext, round-tripping, the `hardwareRooted: false` label, tokens
  containing no secret material, refusing an ungranted secret, and nine
  fail-closed validation paths including expiry, revocation, policy narrowing,
  agent mismatch and a tampered checksum.
- **The demonstration.** `bun run scripts/keyring-demo.ts` — 18/18 checks, exit
  0, on a host with no device. Each of the four refusals asserts a specific
  `DecisionCode` and message, not merely that something was thrown; flipping one
  expected code to a wrong value was confirmed to produce exit 1 and to name the
  mismatch.
- **The CLI's real behaviour**, in §6: every transcript there was produced by
  running `@ledgerhq/wallet-cli@2.1.0` on this machine.
- **The fallback path.** With no ring provisioned, `activeBackend()` reports
  `local-dev` with the CLI's own reason string attached, and every downstream
  field says `hardwareRooted: false`.

### Not verified — no device was available

- **`ring init` has never been run.** It requires a physically attached Ledger.
  Everything in §2 comes from Ledger's documentation and the official
  `wallet-cli` agent skill installed at `.claude/skills/ledger-wallet-cli/`, not
  from execution. Treat the sequence as documented-and-plausible, not proven.
- **`ring encrypt` / `ring decrypt` have never succeeded**, because they need a
  provisioned ring. Only their failure paths were exercised. So
  `SealedSecretStore` has never actually sealed anything under
  `ledger-keyring` — the branch is written and type-checked, and its inputs and
  outputs are asserted, but it has not produced a hardware-rooted seal here.
- **The device-less decrypt on a USB-less host** (§4) — the property that makes
  it possible is documented by Ledger and is strongly corroborated by the CLI's
  own requirement table, but the end-to-end walkthrough has not been run.
- **Whether `ring init` works against Speculos.** Everything available points to
  real USB hardware, which would mean the ring half of a demo cannot be
  emulated. Not confirmed either way.
- **The programmatic path.**
  `@ledgerhq/device-trusted-app-kit-ledger-keyring-protocol@0.5.0` exposes
  `authenticate()` with an optional `sessionId` when a `trustchainId` is
  supplied — the typed, device-less form of the same idea. Arx uses the
  subprocess CLI instead, deliberately: the package's npm README is an empty
  skeleton, the `applicationId` value to use is undocumented, and a demo should
  not rest on a signature read out of a `.d.ts`. See `FEEDBACK.md`.

### One known defect in the hardware path

`RingCli.transform()` collects the CLI's stdout as a UTF-8 string
(`Buffer.concat(stdout).toString("utf8")`) and the store then base64-encodes
that string. §6.3 establishes that `ring encrypt` writes **binary** ciphertext,
and binary decoded as UTF-8 does not survive: invalid sequences become U+FFFD
and the bytes are lost.

The consequence is bounded but real. It cannot corrupt a secret silently —
`unseal()` re-digests the plaintext and compares against `plaintextDigest`, so a
mangled round-trip surfaces as an error, not as a wrong secret. But it does mean
the `ledger-keyring` path would be expected to _fail_ on a host that has a ring,
rather than work. The fix is to keep the child's stdout as a `Buffer` end to
end, or to use `--out <file>` and read the file back as bytes.

It is recorded here rather than patched because `src/broker/ring-cli.ts` is not
this document's to change, and because a defect that cannot be exercised on the
development machine should be written down where an operator will see it before
it is quietly edited.

---
