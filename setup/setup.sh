#!/usr/bin/env bash
# setup.sh — one-shot Security Onion-side installer for enrich.
#
# Idempotent. Safe to re-run on a fresh node OR an existing deploy to upgrade.
# Requires root (or sudo).
#
# Prerequisites BEFORE running:
#   1. This repo is on the SO box (any path; the script will rsync to INSTALL_DIR).
#   2. config/local.yaml (or local.yml) is filled in with your LLM + ES settings.
#   3. .env is filled in with ES credentials (and optionally ANTHROPIC_API_KEY).
#   4. The GPU-side LLM server is reachable from this box (Ollama / LM Studio).
#
# Steps performed (each is a no-op if already done):
#   A. Sanity checks (root, python >= 3.9, source files, .env + local config)
#   B. Create system user + state directory
#   C. Rsync source → INSTALL_DIR
#   D. Create venv + pip install (base package + [cluster] extra)
#   E. Apply ES templates + ingest pipelines + raw data stream from setup/:
#        prism.raw index template (data stream + ILM for raw event store)
#        prism.cowrie.session ingest pipeline (ECS normalization + reroute)
#        prism.raw.cowrie.session data stream (pre-created empty so the
#          healthcheck's raw-index existence check passes on first deploy)
#   F. Init project-owned processed indices, additive-mapping safe:
#        cowrie    (commands, sessions, ips + their cluster centroids + campaigns)
#        intel     (prism.intel.{ip,url} — populated by `intel refresh`)
#        findings  (prism.finding — populated by `mine findings`)
#   G. Run healthcheck (ES + local LLM + SQLite + cloud connectivity)
#   H. Install + enable systemd timers:
#        dshield_prism-forward.timer
#          → healthcheck + enrich + rollup sessions + rollup ips
#            (every 30 min; watermark-driven forward pass)
#        dshield_prism-backward.timer
#          → re-enrich-stale + reembed + reset rollup watermarks
#            + re-rollup + cluster commands/sessions/ips
#            + escalate + name playbooks + name ip-clusters
#            + mine campaigns + intel refresh
#            (every 6h; full-corpus backward pass)
#        dshield_prism-mine-findings.timer
#          → mine findings  (hourly; one card per playbook + campaign)
#        All three serialise on /var/lib/dshield_prism/.lock via flock.
#
# Skipped on purpose (first run can take hours on a backlog):
#   - Initial enrichment + clustering pass. Trigger manually after setup:
#       sudo systemctl start dshield_prism-forward.service
#       sudo systemctl start dshield_prism-backward.service
#     Or via the CLI:
#       sudo -u "${SERVICE_USER}" "${INSTALL_DIR}/.venv/bin/python" \
#         -m enrich.cli enrich
#
# Usage:
#   sudo bash setup/setup.sh [--no-systemd] [--skip-healthcheck] [--skip-init-index]
#
# Environment overrides:
#   SERVICE_USER   default: dshield_prism
#   INSTALL_DIR    default: /opt/dshield_prism
#   STATE_DIR      default: /var/lib/dshield_prism
#   LOG_DIR        default: /var/log/dshield_prism
#   SYSTEMD_DIR    default: /etc/systemd/system
#   PYTHON_BIN     default: python3

set -euo pipefail

# ---- configurable ----------------------------------------------------------

SERVICE_USER="${SERVICE_USER:-dshield_prism}"
INSTALL_DIR="${INSTALL_DIR:-/opt/dshield_prism}"
STATE_DIR="${STATE_DIR:-/var/lib/dshield_prism}"
LOG_DIR="${LOG_DIR:-/var/log/dshield_prism}"
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
            sed -n '1,55p' "$0" | sed 's/^# \{0,1\}//'
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

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

# ---- A. sanity checks -------------------------------------------------------

log "Sanity checks"

if [[ "${EUID}" -ne 0 ]]; then
    die "This script must run as root (use sudo)."
fi

# Create the log dir + start teeing stdout/stderr into it as early as
# possible (right after the root check, before any heavier work). The
# tee lives via a file-redirection process-substitution so all
# subsequent log/warn/die output is captured. Use --append so re-running
# setup.sh appends to a single audit-trail log file rather than
# truncating each invocation.
mkdir -p "${LOG_DIR}"
chmod 750 "${LOG_DIR}"
exec > >(tee -a "${LOG_DIR}/setup.log") 2>&1
log "Tee'ing output to ${LOG_DIR}/setup.log"

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

REQUIRED_FILES=(
    "${SRC_DIR}/pyproject.toml"
    "${SRC_DIR}/src/enrich/cli.py"
    "${SRC_DIR}/src/enrich/sources/cowrie/commands.py"
    "${SRC_DIR}/src/enrich/sources/cowrie/sessions.py"
    "${SRC_DIR}/src/enrich/sources/cowrie/ips.py"
    "${SRC_DIR}/config/default.yaml"
    "${SRC_DIR}/config/prompts/command_enrichment.txt"
    "${SRC_DIR}/config/prompts/command_deep_dive.txt"
    "${SRC_DIR}/config/prompts/playbook_name.txt"
    "${SRC_DIR}/setup/es-mappings/cowrie/commands.json"
    "${SRC_DIR}/setup/es-mappings/cowrie/command_clusters.json"
    "${SRC_DIR}/setup/es-mappings/cowrie/sessions.json"
    "${SRC_DIR}/setup/es-mappings/cowrie/session_clusters.json"
    "${SRC_DIR}/setup/es-mappings/cowrie/ips.json"
    "${SRC_DIR}/setup/es-mappings/cowrie/ip_clusters.json"
    "${SRC_DIR}/setup/es-mappings/cowrie/campaigns.json"
    "${SRC_DIR}/setup/es-mappings/intel/ip.json"
    "${SRC_DIR}/setup/es-mappings/intel/url.json"
    "${SRC_DIR}/setup/es-mappings/findings/default.json"
    "${SRC_DIR}/setup/prism.raw_template.yaml"
    "${SRC_DIR}/setup/es-pipelines/cowrie-pipeline.yml"
    "${SRC_DIR}/systemd/dshield_prism-forward.service"
    "${SRC_DIR}/systemd/dshield_prism-forward.timer"
    "${SRC_DIR}/systemd/dshield_prism-backward.service"
    "${SRC_DIR}/systemd/dshield_prism-backward.timer"
    "${SRC_DIR}/systemd/dshield_prism-mine-findings.service"
    "${SRC_DIR}/systemd/dshield_prism-mine-findings.timer"
)
for required in "${REQUIRED_FILES[@]}"; do
    [[ -f "${required}" ]] || die "Missing source file: ${required}"
done

if [[ ! -s "${SRC_DIR}/.env" ]]; then
    die "Missing or empty .env at ${SRC_DIR}/.env. Copy .env.example and fill it in."
fi
if ! grep -qE '^(ES_API_KEY|ES_USERNAME)=' "${SRC_DIR}/.env"; then
    die ".env must define ES_API_KEY or ES_USERNAME/ES_PASSWORD."
fi

LOCAL_CFG=""
for f in "${SRC_DIR}/config/local.yaml" "${SRC_DIR}/config/local.yml"; do
    [[ -f "${f}" ]] && LOCAL_CFG="${f}" && break
done
if [[ -z "${LOCAL_CFG}" ]]; then
    die "No config/local.yaml or config/local.yml. Copy config/local.yaml.example and edit."
fi
log "  local config: ${LOCAL_CFG}"

if grep -q 'CHANGE_ME' "${SRC_DIR}/config/default.yaml" "${LOCAL_CFG}" 2>/dev/null \
   && ! grep -qE '^[^#]*base_url:' "${LOCAL_CFG}"; then
    die "llm.base_url not set in ${LOCAL_CFG} (still 'CHANGE_ME')."
fi

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
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${STATE_DIR}"
chmod 750 "${STATE_DIR}"

# Now that the service user exists, hand the log dir over so the CLI
# (running as that user under systemd) can rotate cli.log there.
# setup.log itself stays root-owned — root wrote it via tee — but the
# group is set to the service user so the CLI can append if needed.
log "Log directory: ${LOG_DIR}"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${LOG_DIR}"
chmod 750 "${LOG_DIR}"

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

log "Installing project (base package + [cluster] extra)"
sudo -u "${SERVICE_USER}" "${VENV}/bin/pip" install --quiet --upgrade pip
sudo -u "${SERVICE_USER}" "${VENV}/bin/pip" install --quiet -e "${INSTALL_DIR}[cluster]"

if ! sudo -u "${SERVICE_USER}" "${VENV}/bin/python" -c \
    'import enrich' >/dev/null 2>&1
then
    die "Post-install import failed. Check pip output above."
fi
if ! sudo -u "${SERVICE_USER}" "${VENV}/bin/python" -c \
    'from sklearn.cluster import HDBSCAN' >/dev/null 2>&1
then
    die "Cluster deps import failed (sklearn.cluster.HDBSCAN not found)."
fi
if ! sudo -u "${SERVICE_USER}" "${VENV}/bin/python" -c \
    'from enrich.sources.cowrie import commands, sessions, ips' >/dev/null 2>&1
then
    die "Cowrie source modules failed to import. Check pip output above."
fi

# Helper: run the CLI as the service user with the right env + cwd.
run_cli() {
    sudo -u "${SERVICE_USER}" env \
        PRISM_ENV="${INSTALL_DIR}/.env" \
        "${VENV}/bin/python" -m enrich.cli \
        --config "${INSTALL_DIR}/config/default.yaml" "$@"
}

# ---- E. bootstrap ES (templates + ingest pipelines + raw data stream) ------

if (( RUN_INIT_INDEX )); then
    # Apply project-owned templates, ingest pipelines, and the
    # `prism.raw.cowrie.session` data stream BEFORE healthcheck so the
    # post-install checks (which expect the raw index to exist) pass on
    # a fresh deploy too. Idempotent: PUTs on templates + pipelines
    # overwrite; data-stream creation hits a "resource_already_exists"
    # branch that's treated as a no-op.
    log "Applying ES templates + ingest pipelines from setup/"
    ( cd "${INSTALL_DIR}" && run_cli bootstrap-es )
else
    warn "Skipping bootstrap-es (--skip-init-index)"
fi

# ---- F. init project-owned processed indices -------------------------------

if (( RUN_INIT_INDEX )); then
    # Idempotent across all three sources: creates missing indexes, additive
    # mapping update on existing ones. Order matters when an index doesn't
    # exist yet — cowrie indexes are read by the intel + findings miners,
    # so we init the source-of-truth indexes first.
    log "Initializing cowrie indexes (commands, sessions, ips, clusters, campaigns)"
    ( cd "${INSTALL_DIR}" && run_cli init-indexes --update-mapping --source cowrie )
    log "Initializing intel indexes (prism.intel.ip, prism.intel.url)"
    ( cd "${INSTALL_DIR}" && run_cli init-indexes --update-mapping --source intel )
    log "Initializing findings index (prism.finding)"
    ( cd "${INSTALL_DIR}" && run_cli init-indexes --update-mapping --source findings )
else
    warn "Skipping init-indexes (--skip-init-index)"
fi

# ---- G. healthcheck --------------------------------------------------------
# Moved after bootstrap-es + init-indexes so the raw-index existence check
# (hard-fails when the data stream is missing — every other invocation, in
# production, the raw stream needs to be there) passes on a fresh deploy.

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

# ---- H. systemd ------------------------------------------------------------

if (( INSTALL_SYSTEMD )); then
    log "Syncing systemd units"

    # Best-effort cleanup of the prior ingest+analytics units. Idempotent —
    # silently ignores absence on a fresh box.
    for legacy in dshield_prism-ingest dshield_prism-analytics; do
        if [[ -f "${SYSTEMD_DIR}/${legacy}.timer" ]] \
        || [[ -f "${SYSTEMD_DIR}/${legacy}.service" ]]; then
            log "  ${legacy}.*: removing legacy units (replaced by forward/backward)"
            systemctl disable --now "${legacy}.timer" 2>/dev/null || true
            rm -f "${SYSTEMD_DIR}/${legacy}.timer" "${SYSTEMD_DIR}/${legacy}.service"
        fi
    done

    UNITS_CHANGED=0
    for unit in \
        dshield_prism-forward.service \
        dshield_prism-forward.timer \
        dshield_prism-backward.service \
        dshield_prism-backward.timer \
        dshield_prism-mine-findings.service \
        dshield_prism-mine-findings.timer
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

    systemctl enable --now dshield_prism-forward.timer
    systemctl enable --now dshield_prism-backward.timer
    systemctl enable --now dshield_prism-mine-findings.timer
    if (( UNITS_CHANGED )); then
        systemctl restart dshield_prism-forward.timer
        systemctl restart dshield_prism-backward.timer
        systemctl restart dshield_prism-mine-findings.timer
    fi

    log "Timer status:"
    systemctl --no-pager list-timers \
        dshield_prism-forward.timer \
        dshield_prism-backward.timer \
        dshield_prism-mine-findings.timer || true
else
    warn "Skipping systemd install (--no-systemd)"
fi

# ---- done ------------------------------------------------------------------

cat <<EOF

${GREEN}Setup complete.${RESET}

Scheduled services installed:

  dshield_prism-forward.timer           (every 30 min)
    → healthcheck --scope llm   (hard fail = skip the pass)
    → enrich                    (command enrichment + cloud escalation)
    → rollup sessions           (session aggregation)
    → rollup ips                (IP aggregation)

  dshield_prism-backward.timer          (every 6h at 00,06,12,18 UTC)
    → healthcheck --scope llm   (soft check; most steps don't need LLM)
    → re-enrich-stale           (LLM-side cache drift; near-no-op when fresh)
    → reembed                   (embed-side cache drift; near-no-op when fresh)
    → reset --session-watermark --ip-watermark   (force full re-rollup)
    → rollup sessions / ips     (re-pool with refreshed command embeddings)
    → cluster commands          (HDBSCAN; refreshes novelty)
    → cluster sessions / ips    (HDBSCAN)
    → escalate                  (cloud rescue for novel commands)
    → name playbooks            (local LLM names each session cluster)
    → name ip-clusters          (annotate IP centroids with dominant playbook)
    → mine campaigns            (FP-growth + shared-artifact miners)
    → intel refresh             (external threat-intel providers)

  dshield_prism-mine-findings.timer     (hourly at :05)
    → mine findings             (one card per playbook + per campaign;
                                 powers the console /findings page)

  All three serialise on /var/lib/dshield_prism/.lock via flock.

The first forward pass will fire within 30 min. To kick off a run now:

  sudo systemctl start dshield_prism-forward.service
  sudo systemctl start dshield_prism-backward.service
  sudo systemctl start dshield_prism-mine-findings.service

Tail live logs:

  journalctl -fu dshield_prism-forward.service
  journalctl -fu dshield_prism-backward.service
  journalctl -fu dshield_prism-mine-findings.service

Useful CLI commands (run as the service user):

  CLI="sudo -u ${SERVICE_USER} ${VENV}/bin/python -m enrich.cli"
  \$CLI healthcheck                  # ES + LLM + SQLite + cloud + intel
  \$CLI enrich --dry-run             # show what would be enriched
  \$CLI budget                       # today's cloud-LLM spend
  \$CLI cluster commands --dry-run   # command-level cluster stats
  \$CLI name playbooks --dry-run     # preview playbook naming candidates
  \$CLI mine campaigns --dry-run     # preview multi-session campaign mining
  \$CLI mine findings --dry-run      # preview the findings inbox refresh
  \$CLI intel refresh --dry-run      # preview intel queue + provider dispatch

The browser console is installed separately (see console/README.md):

  cd console && python3 -m venv .venv && source .venv/bin/activate
  pip install -e .
  dshield_prism_console serve --port 8765
  # then open http://127.0.0.1:8765/  (redirects to /findings)

Import the Kibana dashboards (Saved Objects → Import):
  ${INSTALL_DIR}/es-dashboards/session-analysis.ndjson
  ${INSTALL_DIR}/es-dashboards/command-enrichment-dashboard.ndjson

Re-running this script is safe — every step is idempotent.
EOF
