#!/usr/bin/env bash
# setup-so-node.sh — one-shot SecurityOnion-side installer for dshield_vector_analysis.
#
# Idempotent. Safe to re-run. Requires root (or sudo).
#
# Prerequisites BEFORE running:
#   1. This repo is on the SO box (any path; the script will rsync to INSTALL_DIR).
#   2. config/local.yaml (or local.yml) is filled in with your LLM + ES settings.
#   3. .env is filled in with ES credentials.
#   4. The GPU-side LLM server is reachable from this box (Ollama / LM Studio).
#
# Steps performed (each is a no-op if already done):
#   A. Sanity checks (root, python>=3.11, source files present, .env + local config present)
#   B. Create system user + state directory
#   C. Rsync source -> INSTALL_DIR
#   D. Create venv + pip install -e .
#   E. Run healthcheck (fails loudly if ES/LLM unreachable)
#   F. Run init-index (creates the enrichment index if missing)
#   G. Install + enable systemd service + timer
#
# Skipped on purpose:
#   - First enrichment run. Trigger manually with:
#       sudo -u "${SERVICE_USER}" "${INSTALL_DIR}/.venv/bin/python" \
#         -m dshield_vector_analysis.cli enrich --dry-run
#       sudo -u "${SERVICE_USER}" "${INSTALL_DIR}/.venv/bin/python" \
#         -m dshield_vector_analysis.cli enrich
#
# Usage:
#   sudo bash scripts/setup-so-node.sh [--no-systemd] [--skip-healthcheck]
#

set -euo pipefail

# ---- configurable ----------------------------------------------------------

SERVICE_USER="${SERVICE_USER:-dshield_vector_analysis}"
INSTALL_DIR="${INSTALL_DIR:-/opt/dshield_vector_analysis}"
STATE_DIR="${STATE_DIR:-/var/lib/dshield_vector_analysis}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

INSTALL_SYSTEMD=1
RUN_HEALTHCHECK=1
RUN_INIT_INDEX=1

# ---- argv ------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-systemd)       INSTALL_SYSTEMD=0 ;;
        --skip-healthcheck) RUN_HEALTHCHECK=0 ;;
        --skip-init-index)  RUN_INIT_INDEX=0 ;;
        -h|--help)
            sed -n '1,40p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "unknown arg: $1" >&2
            exit 2
            ;;
    esac
    shift
done

# ---- helpers ---------------------------------------------------------------

GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
RESET='\033[0m'

log()  { echo -e "${GREEN}==>${RESET} $*"; }
warn() { echo -e "${YELLOW}WARN:${RESET} $*" >&2; }
die()  { echo -e "${RED}ERROR:${RESET} $*" >&2; exit 1; }

trap 'die "command failed at line ${LINENO}: ${BASH_COMMAND}"' ERR

# Resolve the directory containing this script's parent (the repo root).
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

# ---- A. sanity checks -------------------------------------------------------

log "Sanity checks"

if [[ "${EUID}" -ne 0 ]]; then
    die "This script must run as root (use sudo)."
fi

# Python >= 3.11
if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
    die "${PYTHON_BIN} not found in PATH. Install Python 3.9+ first."
fi
PY_VER="$("${PYTHON_BIN}" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PY_MAJOR="${PY_VER%%.*}"
PY_MINOR="${PY_VER##*.}"
if (( PY_MAJOR < 3 )) || { (( PY_MAJOR == 3 )) && (( PY_MINOR < 9 )); }; then
    die "Python ${PY_VER} too old; need >= 3.9."
fi
log "  python: ${PY_VER}"

# Required files in source dir
for required in \
    "${SRC_DIR}/pyproject.toml" \
    "${SRC_DIR}/src/dshield_vector_analysis/cli.py" \
    "${SRC_DIR}/config/default.yaml" \
    "${SRC_DIR}/es-mappings/dshield-cowrie-enrichment-mapping.json" \
    "${SRC_DIR}/systemd/dshield_vector_analysis.service" \
    "${SRC_DIR}/systemd/dshield_vector_analysis.timer"
do
    [[ -f "${required}" ]] || die "Missing source file: ${required}"
done

# .env present + non-empty
if [[ ! -s "${SRC_DIR}/.env" ]]; then
    die "Missing or empty .env at ${SRC_DIR}/.env. Copy .env.example and fill it in."
fi
# basic sanity: must contain either ES_API_KEY or both ES_USERNAME + ES_PASSWORD
if ! grep -qE '^(ES_API_KEY|ES_USERNAME)=' "${SRC_DIR}/.env"; then
    die ".env must define ES_API_KEY or ES_USERNAME/ES_PASSWORD."
fi

# Local config present (yaml or yml)
LOCAL_CFG=""
for f in "${SRC_DIR}/config/local.yaml" "${SRC_DIR}/config/local.yml"; do
    [[ -f "${f}" ]] && LOCAL_CFG="${f}" && break
done
if [[ -z "${LOCAL_CFG}" ]]; then
    die "No config/local.yaml or config/local.yml. Copy config/local.yaml.example and edit."
fi
log "  local config: ${LOCAL_CFG}"

# Refuse the placeholder default
if grep -q 'CHANGE_ME' "${SRC_DIR}/config/default.yaml" "${LOCAL_CFG}" 2>/dev/null \
   && ! grep -qE '^[^#]*base_url:' "${LOCAL_CFG}"; then
    die "llm.base_url not set in ${LOCAL_CFG} (still 'CHANGE_ME')."
fi

# rsync available
command -v rsync >/dev/null 2>&1 || die "rsync not found; please install it."

# ---- B. user + state dir ---------------------------------------------------

log "Service user: ${SERVICE_USER}"
if id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    log "  user already exists"
else
    useradd --system --home "${INSTALL_DIR}" --shell /usr/sbin/nologin "${SERVICE_USER}"
    log "  user created"
fi

log "State directory: ${STATE_DIR}"
mkdir -p "${STATE_DIR}"
chown "${SERVICE_USER}:${SERVICE_USER}" "${STATE_DIR}"
chmod 750 "${STATE_DIR}"

# ---- C. deploy source ------------------------------------------------------

log "Deploying source to ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"

# rsync excludes: anything generated locally we don't want to ship.
# Keep .env and config/local.yaml so the install dir is self-sufficient.
rsync -a --delete \
    --exclude='.venv/' \
    --exclude='__pycache__/' \
    --exclude='*.egg-info/' \
    --exclude='*.pyc' \
    --exclude='.git/' \
    "${SRC_DIR}/" "${INSTALL_DIR}/"

chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}"
chmod 600 "${INSTALL_DIR}/.env" 2>/dev/null || true
chmod 600 "${INSTALL_DIR}/config/local.yaml" 2>/dev/null || true
chmod 600 "${INSTALL_DIR}/config/local.yml"  2>/dev/null || true

# ---- D. venv + install -----------------------------------------------------

VENV="${INSTALL_DIR}/.venv"
if [[ -x "${VENV}/bin/python" ]]; then
    log "Reusing existing venv at ${VENV}"
else
    log "Creating venv at ${VENV}"
    sudo -u "${SERVICE_USER}" "${PYTHON_BIN}" -m venv "${VENV}"
fi

log "Installing project (pip install -e .)"
sudo -u "${SERVICE_USER}" "${VENV}/bin/pip" install --quiet --upgrade pip
sudo -u "${SERVICE_USER}" "${VENV}/bin/pip" install --quiet -e "${INSTALL_DIR}"

# Sanity: import works
if ! sudo -u "${SERVICE_USER}" "${VENV}/bin/python" -c \
    'import dshield_vector_analysis, sys; print(dshield_vector_analysis.__version__)' >/dev/null 2>&1
then
    die "Post-install import failed. Check pip output above."
fi

# ---- E. healthcheck --------------------------------------------------------

# Helper: run the CLI as the service user with the right env + cwd. We use
# `env` because `sudo -u` doesn't pass DSHIELD_VECTOR_ANALYSIS_ENV through.
run_cli() {
    sudo -u "${SERVICE_USER}" env \
        DSHIELD_VECTOR_ANALYSIS_ENV="${INSTALL_DIR}/.env" \
        "${VENV}/bin/python" -m dshield_vector_analysis.cli \
        --config "${INSTALL_DIR}/config/default.yaml" "$@"
}

if (( RUN_HEALTHCHECK )); then
    log "Running healthcheck"
    set +e
    ( cd "${INSTALL_DIR}" && run_cli healthcheck )
    HC_RC=$?
    set -e
    if (( HC_RC != 0 )); then
        die "Healthcheck failed (rc=${HC_RC}). Fix the failures above before continuing. Re-run this script when ready, or pass --skip-healthcheck."
    fi
else
    warn "Skipping healthcheck (--skip-healthcheck)"
fi

# ---- F. init-index ---------------------------------------------------------

if (( RUN_INIT_INDEX )); then
    log "Running init-index (idempotent)"
    ( cd "${INSTALL_DIR}" && run_cli init-index )
else
    warn "Skipping init-index (--skip-init-index)"
fi

# ---- G. systemd ------------------------------------------------------------

if (( INSTALL_SYSTEMD )); then
    log "Syncing systemd units"

    # Install unit only if missing or content differs from source. Track which
    # units changed so we can daemon-reload + restart the timer exactly once
    # when needed (and skip churn when nothing changed).
    UNITS_CHANGED=0
    for unit in dshield_vector_analysis.service dshield_vector_analysis.timer; do
        src="${INSTALL_DIR}/systemd/${unit}"
        dst="${SYSTEMD_DIR}/${unit}"
        if [[ ! -f "${dst}" ]]; then
            log "  ${unit}: installing (missing)"
            install -m 0644 "${src}" "${dst}"
            UNITS_CHANGED=1
        elif ! cmp -s "${src}" "${dst}"; then
            log "  ${unit}: updating (outdated)"
            install -m 0644 "${src}" "${dst}"
            UNITS_CHANGED=1
        else
            log "  ${unit}: up-to-date"
        fi
    done

    if (( UNITS_CHANGED )); then
        log "Reloading systemd"
        systemctl daemon-reload
        # Re-enable in case unit content changed enable behavior; --now is a no-op if already active.
        systemctl enable --now dshield_vector_analysis.timer
        # Bounce timer so new OnCalendar/Unit settings take effect immediately.
        systemctl restart dshield_vector_analysis.timer
    else
        # Still ensure timer is enabled + active on first run after a no-change re-deploy.
        systemctl enable --now dshield_vector_analysis.timer
    fi

    log "Timer status:"
    systemctl --no-pager list-timers dshield_vector_analysis.timer || true
else
    warn "Skipping systemd install (--no-systemd)"
fi

# ---- done ------------------------------------------------------------------

cat <<EOF

${GREEN}Setup complete.${RESET}

Manual first run (recommended before relying on the timer):

  sudo -u ${SERVICE_USER} ${VENV}/bin/python -m dshield_vector_analysis.cli enrich --dry-run
  sudo -u ${SERVICE_USER} ${VENV}/bin/python -m dshield_vector_analysis.cli enrich

Tail the timer-driven runs:

  journalctl -fu dshield_vector_analysis.service

Re-running this script is safe — every step is idempotent.
EOF
