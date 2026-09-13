# Ledger device app binaries

This directory is the Speculos app mount. `docker-compose.speculos.yml` mounts
it at `/speculos/apps` **read-only**, so nothing Arx does can modify the binary
that signs.

## What goes here

`scripts/speculos-up.sh` downloads the Ethereum app for your `SPECULOS_MODEL`
from the [`LedgerHQ/app-ethereum` releases](https://github.com/LedgerHQ/app-ethereum/releases)
and verifies its SHA-256 against [`CHECKSUMS.sha256`](CHECKSUMS.sha256) before
the emulator is started. A mismatch aborts; it does not warn and continue.

```bash
scripts/speculos-up.sh --fetch-only   # fetch + verify only, no Docker needed
scripts/speculos-up.sh                # preflight, fetch + verify, start, wait
```

To re-check a binary by hand at any time:

```bash
cd data/ledger-apps && shasum -a 256 -c --ignore-missing CHECKSUMS.sha256
```

`--ignore-missing` is needed because only the asset for your own
`SPECULOS_MODEL` is normally present; without it the other four report as
failures, which is an absent file rather than a bad digest.

Files are named per version and per model — `app-1.22.3-nanos2.elf`, not
`app-ethereum.elf` — because a single fixed name silently reuses the previous
model's binary when `SPECULOS_MODEL` changes.

| `SPECULOS_MODEL` | Release asset target |
|---|---|
| `nanosp` | `nanos2` (the Nano S+ is `nanosp` to the emulator, `nanos2` to the build system) |
| `nanox` | `nanox` |
| `flex` | `flex` |
| `stax` | `stax` |
| `apex_p` | `apex_p` |

## Provenance and licence

- **Source:** GitHub release artifacts published by Ledger on
  `LedgerHQ/app-ethereum`. Pinned version: **1.22.3** (the current release as of
  2026-09-12).
- **Licence:** Apache-2.0, per
  [`LedgerHQ/app-ethereum`](https://github.com/LedgerHQ/app-ethereum/blob/master/LICENSE).
- **Redistribution:** none. `.elf` files are gitignored (see
  [`.gitignore`](.gitignore)) and fetched at run time. This repository ships the
  digests, not the binaries.
- **Verified here:** each of the five 1.22.3 assets was downloaded and hashed on
  2026-09-12; all five are `ELF 32-bit LSB executable, ARM, EABI5 version 1
  (SYSV), statically linked, not stripped`. The digests are in
  `CHECKSUMS.sha256`.

## The Speculos image ships no Ethereum app

Worth stating plainly, because the failure is quiet. The
`ghcr.io/ledgerhq/speculos` image carries only Speculos' own test binaries —
[`boil.elf` and a Nano X variant](https://github.com/LedgerHQ/speculos/tree/master/apps).
`boil.elf` is not the Ethereum app: an emulator booted on it starts, serves the
REST API, passes a naive health check, and answers **none** of the
`app-ethereum` APDUs. That looks like a working emulator and is not one.

Ledger also documents that a production app installed on a physical device
[cannot be extracted as a runnable `.elf`](https://github.com/LedgerHQ/speculos/blob/master/docs/user/getting_an_app.md),
so the release artifact (or a local build) is the only route.

See `docs/LEDGER.md` §7 for the full explanation, the build-from-source
alternative, and what the Speculos path has and has not been verified to do.
