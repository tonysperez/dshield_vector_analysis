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
#   A. Sanity checks (root, python>=3.9, source files present, .env + local config present)
#   B. Create system user + state directory
#   C. Rsync source -> INSTALL_DIR
#   D. Create venv + pip install (base package + [cluster] extra for HDBSCAN / numpy)
#   E. Run healthcheck
#   F. Run init-index for the enrichment index and the clusters index
#   G. Install + enable systemd units:
#        dshield_vector_analysis.timer        — hourly enrich
#        dshield_vector_analysis_cluster.timer — 6-hourly cluster + escalate
#
# Skipped on purpose:
#   - First enrichment run. Trigger manually:
#       sudo -u "${SERVICE_USER}" "${INSTALL_DIR}/.venv/bin/python" \
#         -m dshield_vector_analysis.cli enrich --dry-run
#       sudo -u "${SERVICE_USER}" "${INSTALL_DIR}/.venv/bin/python" \
#         -m dshield_vector_analysis.cli enrich
#   - First cluster run. Run after the first successful enrich:
#       sudo -u "${SERVICE_USER}" "${INSTALL_DIR}/.venv/bin/python" \
#         -m dshield_vector_analysis.cli cluster
#
# Usage:
#   sudo bash scripts/setup-so-node.sh [--no-systemd] [--skip-healthcheck] [--skip-init-index]
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
            sed -n '1,45p' "$0" | sed 's/^# \{0,1\}//'
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

# Python >= 3.9
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
    "${SRC_DIR}/es-mappings/dshield-cowrie-clusters-mapping.json" \
    "${SRC_DIR}/systemd/dshield_vector_analysis.service" \
    "${SRC_DIR}/systemd/dshield_vector_analysis.timer" \
    "${SRC_DIR}/systemd/dshield_vector_analysis_cluster.service" \
    "${SRC_DIR}/systemd/dshield_vector_analysis_cluster.timer"
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

log "Installing project (base package)"
sudo -u "${SERVICE_USER}" "${VENV}/bin/pip" install --quiet --upgrade pip
sudo -u "${SERVICE_USER}" "${VENV}/bin/pip" install --quiet -e "${INSTALL_DIR}"

log "Installing cluster deps (numpy + scikit-learn for HDBSCAN)"
sudo -u "${SERVICE_USER}" "${VENV}/bin/pip" install --quiet -e "${INSTALL_DIR}[cluster]"

# Sanity: import works
if ! sudo -u "${SERVICE_USER}" "${VENV}/bin/python" -c \
    'import dshield_vector_analysis' >/dev/null 2>&1
then
    die "Post-install import failed. Check pip output above."
fi
if ! sudo -u "${SERVICE_USER}" "${VENV}/bin/python" -c \
    'from sklearn.cluster import HDBSCAN' >/dev/null 2>&1
then
    die "Cluster deps import failed (sklearn.cluster.HDBSCAN not found)."
fi

# Helper: run the CLI as the service user with the right env + cwd.
run_cli() {
    sudo -u "${SERVICE_USER}" env \
        DSHIELD_VECTOR_ANALYSIS_ENV="${INSTALL_DIR}/.env" \
        "${VENV}/bin/python" -m dshield_vector_analysis.cli \
        --config "${INSTALL_DIR}/config/default.yaml" "$@"
}

# ---- E. healthcheck --------------------------------------------------------

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

# ---- F. init indexes -------------------------------------------------------

if (( RUN_INIT_INDEX )); then
    log "Creating enrichment index (idempotent)"
    ( cd "${INSTALL_DIR}" && run_cli init-index )

    # Derive the clusters index name from the config using the same logic as the
    # Python code so they are guaranteed to match.
    log "Deriving clusters index name from config"
    CLUSTERS_IDX=$(
        cd "${INSTALL_DIR}" && \
        sudo -u "${SERVICE_USER}" env \
            DSHIELD_VECTOR_ANALYSIS_ENV="${INSTALL_DIR}/.env" \
            "${VENV}/bin/python" -c "
from dshield_vector_analysis.config import load_config
from dshield_vector_analysis.cluster import get_clusters_index
cfg = load_config('${INSTALL_DIR}/config/default.yaml')
print(get_clusters_index(cfg))
"
    )
    log "Creating clusters index: ${CLUSTERS_IDX} (idempotent)"
    ( cd "${INSTALL_DIR}" && run_cli init-index \
        --mapping "${INSTALL_DIR}/es-mappings/dshield-cowrie-clusters-mapping.json" \
        --index "${CLUSTERS_IDX}" )
else
    warn "Skipping init-index (--skip-init-index)"
fi

# ---- G. systemd ------------------------------------------------------------

if (( INSTALL_SYSTEMD )); then
    log "Syncing systemd units"

    UNITS_CHANGED=0
    for unit in \
        dshield_vector_analysis.service \
        dshield_vector_analysis.timer \
        dshield_vector_analysis_cluster.service \
        dshield_vector_analysis_cluster.timer
    do
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
    fi

    # Enable + activate both timers.
    systemctl enable --now dshield_vector_analysis.timer
    systemctl enable --now dshield_vector_analysis_cluster.timer
    if (( UNITS_CHANGED )); then
        systemctl restart dshield_vector_analysis.timer
        systemctl restart dshield_vector_analysis_cluster.timer
    fi

    log "Timer status:"
    systemctl --no-pager list-timers \
        dshield_vector_analysis.timer \
        dshield_vector_analysis_cluster.timer || true
else
    warn "Skipping systemd install (--no-systemd)"
fi

# ---- done ------------------------------------------------------------------

cat <<EOF

${GREEN}Setup complete.${RESET}

First enrichment run (recommended before relying on the timer):

  sudo -u ${SERVICE_USER} ${VENV}/bin/python -m dshield_vector_analysis.cli enrich --dry-run
  sudo -u ${SERVICE_USER} ${VENV}/bin/python -m dshield_vector_analysis.cli enrich

First cluster run (run after the first successful enrich; subsequent runs are timer-driven):

  sudo -u ${SERVICE_USER} ${VENV}/bin/python -m dshield_vector_analysis.cli cluster
  sudo -u ${SERVICE_USER} ${VENV}/bin/python -m dshield_vector_analysis.cli escalate

Tail timer-driven runs:

  journalctl -fu dshield_vector_analysis.service          # hourly enrich
  journalctl -fu dshield_vector_analysis_cluster.service  # 6-hourly cluster + escalate

Re-running this script is safe — every step is idempotent.
EOF
