# Ledger device app binaries

`scripts/speculos-up.sh` downloads `app-ethereum.elf` here from the
[`LedgerHQ/app-ethereum` releases](https://github.com/LedgerHQ/app-ethereum/releases)
and `docker-compose.speculos.yml` mounts this directory into the emulator at
`/speculos/apps` (read-only).

The Speculos image ships no Ethereum app; see `docs/LEDGER.md` §6 for the full
explanation and the build-from-source alternative.
