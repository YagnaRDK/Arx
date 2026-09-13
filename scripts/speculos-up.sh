#!/usr/bin/env bash
#
# Brings up Speculos running the real Ledger Ethereum app, for SIGNER_MODE=speculos.
#
#   scripts/speculos-up.sh              preflight, fetch+verify the app, start, wait
#   scripts/speculos-up.sh --fetch-only fetch+verify the app binary only (no Docker)
#   scripts/speculos-up.sh --down       stop and remove the container
#   scripts/speculos-up.sh --logs       tail the container logs
#
# ─────────────────────────────────────────────────────────────────────────────
# Where does the Ethereum app binary come from?
#
#   The Speculos Docker image does NOT ship an Ethereum app. Its `apps/`
#   directory contains only `boil.elf` and `nanox#boil#2.1.0.elf` — tiny demo
#   binaries for Speculos' own tests. `boil.elf` is not the Ethereum app and
#   answers none of the app-ethereum APDUs, so pointing Speculos at it gets you
#   a running emulator that cannot sign.
#     https://github.com/LedgerHQ/speculos/tree/master/apps
#
#   Ledger's own documentation is explicit that a production app installed on a
#   physical device cannot be extracted as a runnable .elf.
#     https://github.com/LedgerHQ/speculos/blob/master/docs/user/getting_an_app.md
#
#   The honest good news: you do not have to build it. LedgerHQ/app-ethereum
#   attaches prebuilt per-model .elf artifacts to each GitHub release. This
#   script downloads the one matching your model and verifies its SHA-256
#   against data/ledger-apps/CHECKSUMS.sha256.
#
#   Licence: app-ethereum is Apache-2.0. The binary is fetched at run time and
#   gitignored — this repository redistributes nothing.
#
#   To build it yourself instead (an unreleased commit, or if you would rather
#   not trust a release artifact), use Ledger's toolchain image:
#
#     git clone https://github.com/LedgerHQ/app-ethereum && cd app-ethereum
#     docker run --rm -it -v "$(pwd)":/app \
#       ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest
#     # inside: make BOLOS_SDK=$NANOS2_SDK   (or $NANOX_SDK, $FLEX_SDK, ...)
#     # output: build/<target>/bin/app.elf
#
#   Then place it in data/ledger-apps/ and point ARX_ETH_APP_FILE at it.
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

cd "$(dirname "$0")/.."

APP_VERSION="${ARX_ETH_APP_VERSION:-1.22.3}"
MODEL="${SPECULOS_MODEL:-nanosp}"
APP_DIR="data/ledger-apps"
CHECKSUMS="${APP_DIR}/CHECKSUMS.sha256"
API_URL="${SPECULOS_API_URL:-http://127.0.0.1:5000}"
COMPOSE_FILE="docker-compose.speculos.yml"

MODE="up"

for argument in "$@"; do
  case "${argument}" in
    --fetch-only) MODE="fetch" ;;
    --down)       MODE="down" ;;
    --logs)       MODE="logs" ;;
    -h|--help)
      # BSD sed has no \s, so the comment prefix is stripped the portable way.
      sed -n '3,8p' "$0" | sed -e 's/^# \{0,1\}//' -e 's/^#$//'
      exit 0
      ;;
    *)
      echo "Unknown argument '${argument}'. Try --help." >&2
      exit 2
      ;;
  esac
done

die() {
  echo "" >&2
  echo "$*" >&2
  exit 1
}

# Speculos model names and app-ethereum release-asset targets differ: the
# Nano S+ is `nanosp` to the emulator and `nanos2` to the build system. Getting
# this wrong boots a binary built for another screen and another SDK.
#
# Model keys are speculos/mcu/struct.py MODELS. Note that the original Nano S is
# not among them any more.
case "${MODEL}" in
  nanosp) ASSET_TARGET="nanos2" ;;
  nanox)  ASSET_TARGET="nanox" ;;
  flex)   ASSET_TARGET="flex" ;;
  stax)   ASSET_TARGET="stax" ;;
  apex_p) ASSET_TARGET="apex_p" ;;
  *)
    die "Unknown SPECULOS_MODEL '${MODEL}'. Valid: nanosp nanox flex stax apex_p"
    ;;
esac

ASSET="app-${APP_VERSION}-${ASSET_TARGET}.elf"
# Named per version and per model on purpose. A single fixed `app-ethereum.elf`
# means switching SPECULOS_MODEL silently reuses the previous model's binary.
APP_FILE="${ARX_ETH_APP_FILE:-${ASSET}}"
APP_PATH="${APP_DIR}/${APP_FILE}"

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    die "Neither 'docker compose' nor 'docker-compose' is available."
  fi
}

# ── Preflight ────────────────────────────────────────────────────────────────
#
# Docker absence is the single most common reason this script cannot run, and it
# was the reason the Speculos path is not verified end-to-end in this repository
# (see docs/LEDGER.md §8). So it is checked first and named precisely: the CLI
# missing and the daemon being down are different problems with different fixes.
preflight_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    die "$(cat <<'MSG'
Docker is required to run Speculos, and `docker` is not on PATH.

Speculos is distributed only as a container image; there is no host build that
Arx uses. Without Docker you cannot run SIGNER_MODE=speculos.

What to do:
  • Install Docker Desktop (macOS/Windows) or the Docker Engine (Linux):
      https://docs.docker.com/get-started/get-docker/
  • Or run the rest of Arx without it. Every offline path still works:
      SIGNER_MODE=sim    real secp256k1 over real RLP through the real APDU
                         codec, in-process. No Secure Element, no Trusted
                         Display — see docs/LEDGER.md §3.
      SIGNER_MODE=mock   a labelled placeholder, never a real signature.
  • To fetch and verify the app binary anyway (no Docker needed):
      scripts/speculos-up.sh --fetch-only
MSG
)"
  fi

  if ! docker info >/dev/null 2>&1; then
    die "$(cat <<'MSG'
The `docker` CLI is installed but the daemon is not answering.

  docker info

failed. Start Docker Desktop (or `systemctl start docker`) and run this again.
MSG
)"
  fi
}

# ── Fetch and verify the app binary ──────────────────────────────────────────
#
# The digest check is the point of this function, not the download. In
# SIGNER_MODE=speculos this binary is what signs, so "which app ran" has to be
# a verifiable statement.
fetch_app() {
  mkdir -p "${APP_DIR}"

  local expected=""

  if [[ -f "${CHECKSUMS}" ]]; then
    expected="$(awk -v want="${ASSET}" '$2 == want { print $1 }' "${CHECKSUMS}" | head -n 1)"
  fi

  if [[ -z "${expected}" && "${ARX_ETH_APP_ALLOW_UNPINNED:-0}" != "1" ]]; then
    die "$(cat <<MSG
No SHA-256 is pinned for ${ASSET} in ${CHECKSUMS}.

Arx refuses to boot an unpinned signing app: on this path the binary is what
produces the signature. Either

  • use a pinned version (currently pinned: $(awk '/^[0-9a-f]{64}/ { print $2 }' "${CHECKSUMS}" 2>/dev/null | tr '\n' ' ')), or
  • record the digest yourself after checking the release, then add it to
    ${CHECKSUMS}, or
  • set ARX_ETH_APP_ALLOW_UNPINNED=1 to proceed knowingly unverified.
MSG
)"
  fi

  if [[ -f "${APP_PATH}" ]]; then
    echo "Using the existing app binary at ${APP_PATH}"
  else
    local url="https://github.com/LedgerHQ/app-ethereum/releases/download/${APP_VERSION}/${ASSET}"

    echo "Fetching the Ledger Ethereum app for ${MODEL} (${ASSET})"
    echo "  ${url}"
    echo "  licence: Apache-2.0, LedgerHQ/app-ethereum"

    if ! curl -fsSL --retry 3 -o "${APP_PATH}.tmp" "${url}"; then
      rm -f "${APP_PATH}.tmp"
      die "$(cat <<MSG
Download failed. Either you are offline, or the release/asset name changed.

Check https://github.com/LedgerHQ/app-ethereum/releases for the current asset
names, or build the app from source (see the comment at the top of this script)
and place the result at ${APP_PATH}.
MSG
)"
    fi

    mv "${APP_PATH}.tmp" "${APP_PATH}"
  fi

  if [[ -n "${expected}" ]]; then
    local actual
    actual="$(shasum -a 256 "${APP_PATH}" | awk '{ print $1 }')"

    if [[ "${actual}" != "${expected}" ]]; then
      # Left in place deliberately: deleting the evidence makes the mismatch
      # harder to investigate than it makes the next run safer.
      die "$(cat <<MSG
SHA-256 mismatch for ${APP_PATH}.

  expected  ${expected}
  actual    ${actual}

This is not a transient error. Either the file is a local build or a different
version, or the release asset changed. Speculos was NOT started. Remove the file
to re-download, or reconcile ${CHECKSUMS} against the release you intend to run.
MSG
)"
    fi

    echo "  sha256 ${actual} — matches ${CHECKSUMS}"
  else
    echo "  sha256 NOT VERIFIED (ARX_ETH_APP_ALLOW_UNPINNED=1)"
  fi

  echo "  $(wc -c <"${APP_PATH}" | tr -d ' ') bytes"
}

case "${MODE}" in
  fetch)
    fetch_app
    echo ""
    echo "Fetched only. Start the emulator with: scripts/speculos-up.sh"
    exit 0
    ;;
  down)
    preflight_docker
    compose -f "${COMPOSE_FILE}" down
    exit 0
    ;;
  logs)
    preflight_docker
    compose -f "${COMPOSE_FILE}" logs -f speculos
    exit 0
    ;;
esac

preflight_docker
fetch_app

echo "Starting Speculos (model ${MODEL}, app ${APP_FILE})..."

# The container sees the app under /speculos/apps; the compose file mounts
# data/ledger-apps there read-only.
SPECULOS_MODEL="${MODEL}" \
ARX_ETH_APP_ELF="apps/${APP_FILE}" \
  compose -f "${COMPOSE_FILE}" up -d

printf "Waiting for the Speculos API at %s" "${API_URL}"

for _ in $(seq 1 40); do
  if curl -fsS --max-time 2 "${API_URL}/events?currentscreenonly=true" >/dev/null 2>&1; then
    echo " — ready."

    cat <<NEXT

Speculos is up. Point Arx at it:

  export SIGNER_MODE=speculos
  export SPECULOS_API_URL=${API_URL}
  export SPECULOS_TRANSPORT=http        # or 'tcp' for the raw APDU socket on 9999
  export SPECULOS_AUTO_APPROVE=1        # demo only: presses the device buttons
  bun run dev

Then check the boundary:

  curl -s localhost:3000/signer | jq

Watch the device:  ${API_URL}  (headless web display)
Logs:              scripts/speculos-up.sh --logs
Stop it:           scripts/speculos-up.sh --down

SPECULOS_AUTO_APPROVE=1 presses confirm for you. It defeats the human-in-the-loop
gate, so a signature produced under it proves the device signed — not that a
person agreed. Leave it off for anything you intend to cite as human approval.

The seed is pinned to Speculos' own published default 24-word mnemonic, so
44'/60'/0'/0/0 derives 0xDad77910DbDFdE764fC21FCD4E74D71bBACA6D8D. It is a public
test seed: never send real funds to it.
NEXT
    exit 0
  fi

  printf "."
  sleep 2
done

echo ""
echo "Speculos did not answer on ${API_URL} within ~80s. Container logs:" >&2
compose -f "${COMPOSE_FILE}" logs --tail 50 speculos >&2
echo "" >&2
echo "Most common cause: the app binary is not one this Speculos model can run." >&2
echo "Check that SPECULOS_MODEL=${MODEL} matches the asset target ${ASSET_TARGET}." >&2
exit 1
