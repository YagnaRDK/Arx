#!/usr/bin/env bash
#
# Starts Speculos with the real Ledger Ethereum app for the Arx signer demo.
#
# Where does the Ethereum app binary come from?
#
#   The Speculos Docker image does NOT ship an Ethereum app. It carries only a
#   couple of tiny demo binaries for its own tests (apps/boil.elf), and Ledger's
#   own documentation is explicit that production apps installed on a physical
#   device cannot be extracted as runnable .elf files.
#   https://github.com/LedgerHQ/speculos/blob/master/docs/user/getting_an_app.md
#
#   The honest good news: you do not have to build it. `LedgerHQ/app-ethereum`
#   attaches prebuilt per-model .elf artifacts to each GitHub release — for
#   1.22.3 those are app-1.22.3-{nanos2,nanox,flex,stax,apex_p}.elf. This script
#   downloads the one matching your model.
#
#   If you would rather build it yourself (to run an unreleased commit, or if
#   you do not want to trust a release artifact), use Ledger's toolchain image:
#
#     git clone https://github.com/LedgerHQ/app-ethereum
#     cd app-ethereum
#     docker run --rm -it -v "$(pwd)":/app \
#       ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest
#     # inside: make BOLOS_SDK=$NANOS2_SDK   (or $NANOX_SDK, $FLEX_SDK, ...)
#     # output: build/<target>/bin/app.elf
#
#   Either way, put the result at data/ledger-apps/app-ethereum.elf.

set -euo pipefail

cd "$(dirname "$0")/.."

APP_VERSION="${ARX_ETH_APP_VERSION:-1.22.3}"
MODEL="${SPECULOS_MODEL:-nanosp}"
APP_DIR="data/ledger-apps"
APP_PATH="${APP_DIR}/app-ethereum.elf"
API_URL="${SPECULOS_API_URL:-http://127.0.0.1:5000}"

# Speculos model names and app-ethereum release-asset suffixes differ: the
# Nano S+ is `nanosp` to the emulator and `nanos2` to the build system.
case "${MODEL}" in
  nanosp) ASSET_TARGET="nanos2" ;;
  nanox)  ASSET_TARGET="nanox" ;;
  flex)   ASSET_TARGET="flex" ;;
  stax)   ASSET_TARGET="stax" ;;
  apex_p) ASSET_TARGET="apex_p" ;;
  *)
    echo "Unknown SPECULOS_MODEL '${MODEL}'. Valid: nanosp nanox flex stax apex_p" >&2
    exit 1
    ;;
esac

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required but was not found on PATH." >&2
  exit 1
fi

mkdir -p "${APP_DIR}"

if [[ ! -f "${APP_PATH}" ]]; then
  ASSET="app-${APP_VERSION}-${ASSET_TARGET}.elf"
  URL="https://github.com/LedgerHQ/app-ethereum/releases/download/${APP_VERSION}/${ASSET}"

  echo "Fetching the Ethereum app binary for ${MODEL} (${ASSET})..."
  echo "  ${URL}"

  if ! curl -fsSL --retry 3 -o "${APP_PATH}.tmp" "${URL}"; then
    rm -f "${APP_PATH}.tmp"
    echo "" >&2
    echo "Download failed. Either the release/asset name changed, or you are offline." >&2
    echo "Check https://github.com/LedgerHQ/app-ethereum/releases for the current" >&2
    echo "asset names, or build the app yourself (see the comment at the top of" >&2
    echo "this script) and place it at ${APP_PATH}." >&2
    exit 1
  fi

  mv "${APP_PATH}.tmp" "${APP_PATH}"
  echo "Saved ${APP_PATH} ($(wc -c <"${APP_PATH}" | tr -d ' ') bytes)"
else
  echo "Using the existing app binary at ${APP_PATH}"
fi

COMPOSE=(docker compose)
if ! docker compose version >/dev/null 2>&1; then
  if command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
  else
    echo "Neither 'docker compose' nor 'docker-compose' is available." >&2
    exit 1
  fi
fi

echo "Starting Speculos (model ${MODEL})..."
SPECULOS_MODEL="${MODEL}" "${COMPOSE[@]}" -f docker-compose.speculos.yml up -d

printf "Waiting for the Speculos API at %s" "${API_URL}"
for _ in $(seq 1 40); do
  if curl -fsS --max-time 2 "${API_URL}/events?currentscreenonly=true" >/dev/null 2>&1; then
    echo " — ready."

    cat <<'NEXT'

Speculos is up. Point Arx at it:

  export SIGNER_MODE=speculos
  export SPECULOS_API_URL=http://127.0.0.1:5000
  export SPECULOS_TRANSPORT=http        # or 'tcp' for the raw APDU socket on 9999
  export SPECULOS_AUTO_APPROVE=1        # demo only: presses the device buttons
  bun run dev

Then check the boundary:

  curl -s localhost:3000/signer | jq

Watch the device:  http://127.0.0.1:5000  (headless web display)
Stop it:           docker compose -f docker-compose.speculos.yml down

The pinned seed is Speculos' own published default mnemonic, so 44'/60'/0'/0/0
derives 0xDad77910DbDFdE764fC21FCD4E74D71bBACA6D8D. It is a public test seed:
never send real funds to it.
NEXT
    exit 0
  fi

  printf "."
  sleep 2
done

echo ""
echo "Speculos did not answer on ${API_URL} in time. Container logs:" >&2
"${COMPOSE[@]}" -f docker-compose.speculos.yml logs --tail 50 speculos >&2
exit 1
