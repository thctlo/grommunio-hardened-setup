#!/usr/bin/env bash
#
# server-setup.sh
#
# Orchestrator for building a mail server from a clean Debian 13 install.
# Sources every functions/*.sh in numeric-filename order, then calls each
# step's step_<name> function in that same order, stopping on the first
# failure.
#
# Adding a step:
#   Drop a new functions/NN-some-name.sh file defining step_some_name().
#   The number sets where it runs relative to the others. NN=00 is reserved
#   for shared helpers (functions/00-common.sh) — a file whose derived
#   function name has no matching step_* function is sourced (so its helpers
#   are available) but not called as a step.
#
# Config: each step persists its own decisions under /root/cfg-server/ (see
# functions/00-common.sh) so a later run against the same step files can
# skip the "what do you want" prompts. Destructive-change confirmations are
# never skipped by this mechanism — that is each step's own responsibility.
#
# Usage:
#   sudo ./server-setup.sh [--domain example.com] [--hostname mx1]
#                          [--no-grommunio-setup]
#
#   --domain <domain>       Pre-fills step 10's hostname/domain prompt (and,
#                           through it, step 31's domain-to-create) - skips
#                           being asked interactively. Combine with
#                           --hostname for the full FQDN (<hostname>.<domain>).
#   --hostname <name>       Same, for the hostname half.
#   --no-grommunio-setup    Stop BEFORE step 30 (the grommunio-setup
#                           wizard) instead of running it - for running
#                           that wizard by hand (interactively, or because
#                           it already ran once and its own "already
#                           completed" branch would otherwise ask to wipe
#                           everything via removealldata). The script
#                           prints the exact command to resume with
#                           afterwards (START_AT=<next step>).
#
# Run this ON the target server, not on the build host.

# errtrace (-E) matters as much as -e here: without it, the ERR trap below
# does not fire for a failure inside a step function (only for failures at
# this script's own top level) - a step can then die completely silently,
# with no error printed at all, found live 2026-10-24 (see 35-saslauthd.sh's
# SERVICE_LINE fix for the specific failure that first exposed this).
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
FUNCTIONS_DIR="${SCRIPT_DIR}/functions"

CLI_DOMAIN=""
CLI_HOSTNAME=""
CLI_NO_GROMMUNIO_SETUP=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)
            CLI_DOMAIN="${2:?--domain needs a value}"; shift 2 ;;
        --domain=*)
            CLI_DOMAIN="${1#*=}"; shift ;;
        --hostname)
            CLI_HOSTNAME="${2:?--hostname needs a value}"; shift 2 ;;
        --hostname=*)
            CLI_HOSTNAME="${1#*=}"; shift ;;
        --no-grommunio-setup)
            CLI_NO_GROMMUNIO_SETUP=1; shift ;;
        -h|--help)
            sed -n '3,38p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *)
            echo "server-setup.sh: unknown argument: $1 (see --help)" >&2
            exit 1 ;;
    esac
done

if [[ "${EUID}" -ne 0 ]]; then
    echo "server-setup.sh: this script must be run as root (e.g. with sudo)." >&2
    exit 1
fi

if [[ ! -d "$FUNCTIONS_DIR" ]]; then
    echo "server-setup.sh: functions directory not found: $FUNCTIONS_DIR" >&2
    exit 1
fi

# ============================================================
# Source every functions/*.sh in numeric-filename order
# ============================================================

shopt -s nullglob
FUNCTION_FILES=("${FUNCTIONS_DIR}"/*.sh)
shopt -u nullglob

if [[ "${#FUNCTION_FILES[@]}" -eq 0 ]]; then
    echo "server-setup.sh: no step files found in $FUNCTIONS_DIR" >&2
    exit 1
fi

mapfile -t FUNCTION_FILES < <(printf '%s\n' "${FUNCTION_FILES[@]}" | sort -V)

for f in "${FUNCTION_FILES[@]}"; do
    # shellcheck disable=SC1090
    source "$f"
done

# 00-common.sh must have defined these; fail loudly if the file layout ever
# changes underneath this script.
for required_fn in log err die require_root require_cmd ensure_cfg_dir cfg_file save_cfg backup_file print_backup_manifest; do
    if ! declare -F "$required_fn" >/dev/null; then
        echo "server-setup.sh: expected helper '$required_fn' was not defined after sourcing $FUNCTIONS_DIR/*.sh (is 00-common.sh present?)." >&2
        exit 1
    fi
done

require_root
ensure_cfg_dir

log "Backups of any file changed by this run will be written under: ${BACKUP_ROOT}"

# ============================================================
# --domain/--hostname: pre-seed step 10's own saved-config file. Step 10
# already skips its interactive prompt whenever this file has NEW_HOSTNAME
# set (replay logic it already had for a second run of this same script) -
# reusing that exact mechanism, rather than teaching step 10 a second way
# to learn the hostname/domain. Step 31 (grommunio-domain) already reads
# NEW_DOMAIN from this same file too, so one write here covers both.
# An explicit CLI flag always overwrites whatever was saved before -
# the admin asked for this value on THIS run, that wins.
# PRIMARY_IPV4/6 (which step 10 also computes/saves) are preserved if a
# config already existed, since neither flag speaks to IP selection.
# ============================================================

if [[ -n "$CLI_DOMAIN" || -n "$CLI_HOSTNAME" ]]; then
    NET_CFG="$(cfg_file 10-network-hostname)"
    NEW_HOSTNAME="" NEW_DOMAIN="" NEW_FQDN="" PRIMARY_IPV4="" PRIMARY_IPV6=""
    if [[ -f "$NET_CFG" ]]; then
        # shellcheck disable=SC1090
        source "$NET_CFG"
    fi
    [[ -n "$CLI_HOSTNAME" ]] && NEW_HOSTNAME="$CLI_HOSTNAME"
    [[ -n "$CLI_DOMAIN" ]] && NEW_DOMAIN="$CLI_DOMAIN"
    [[ -z "$NEW_HOSTNAME" ]] && die "--domain given without --hostname (and no hostname saved from an earlier run) - step 10 needs both to build the FQDN."
    NEW_FQDN="${NEW_HOSTNAME}${NEW_DOMAIN:+.$NEW_DOMAIN}"
    save_cfg "$NET_CFG" \
        "NEW_HOSTNAME=$NEW_HOSTNAME" \
        "NEW_DOMAIN=$NEW_DOMAIN" \
        "NEW_FQDN=$NEW_FQDN" \
        "PRIMARY_IPV4=$PRIMARY_IPV4" \
        "PRIMARY_IPV6=$PRIMARY_IPV6"
    log "Pre-seeded hostname/domain from --domain/--hostname: $NEW_FQDN (step 10 will still ask to confirm applying the network config itself)."
fi

# ============================================================
# Single top-level error trap — every step function runs in this same
# process, so only one trap is defined for all of them (defining one per
# step file, as the old standalone scripts each did, would just overwrite
# the previous one).
# ============================================================

CURRENT_STEP="(before any step)"

on_error()
{
    local exit_code=$?
    local line_no=$1
    err "Command failed (exit ${exit_code}) at line ${line_no} while running step: ${CURRENT_STEP}"
    err "Aborting. Already-applied changes from earlier, completed steps are NOT rolled back."
    print_backup_manifest
    exit "$exit_code"
}
trap 'on_error $LINENO' ERR

# ============================================================
# Derive the step order from the sourced filenames and run each one
#
#   10-network-hostname.sh  ->  step_network_hostname
#   20-firewall-fail2ban.sh ->  step_firewall_fail2ban
#
# A file whose derived name has no matching function (e.g. 00-common.sh,
# which is shared helpers, not a step) is sourced above but simply skipped
# here.
# ============================================================

START_AT="${START_AT:-00}"   # e.g. START_AT=40 skips steps numbered below 40

for i in "${!FUNCTION_FILES[@]}"; do
    f="${FUNCTION_FILES[$i]}"
    base="$(basename "$f" .sh)"
    if [[ "${base%%-*}" -lt "$START_AT" ]]; then
        log "Skipping $base (START_AT=${START_AT})."
        continue
    fi
    name="${base#*-}"        # strip the leading "NN-"
    name="${name//-/_}"      # dashes -> underscores
    fn="step_${name}"

    if ! declare -F "$fn" >/dev/null; then
        log "Skipping $base (no ${fn} function — shared helpers, not a step)."
        continue
    fi

    if [[ "$fn" == "step_grommunio_setup" && "$CLI_NO_GROMMUNIO_SETUP" -eq 1 ]]; then
        # Find the next actual step after this one (skipping any further
        # non-step helper files), so the resume command is always correct
        # even if steps are renumbered/added/removed later.
        next_num=""
        for j in $(seq $((i + 1)) $((${#FUNCTION_FILES[@]} - 1))); do
            next_base="$(basename "${FUNCTION_FILES[$j]}" .sh)"
            next_name="${next_base#*-}"; next_name="${next_name//-/_}"
            if declare -F "step_${next_name}" >/dev/null; then
                next_num="${next_base%%-*}"
                break
            fi
        done

        echo
        echo "############################################################"
        echo "# Stopping before step: $base (--no-grommunio-setup)"
        echo "############################################################"
        echo
        echo "Two ways to continue, depending on what you want:"
        echo
        echo "  1) Let this script run grommunio-setup after all: just run it"
        echo "     again WITHOUT --no-grommunio-setup. Step 10 will not ask"
        echo "     again (replayed from its saved config), and the script will"
        echo "     naturally reach and run step $base this time."
        echo
        echo "       sudo $0"
        echo
        echo "  2) Run grommunio-setup yourself (interactively, or however you"
        echo "     prefer), then skip past it here and resume from the next"
        echo "     step:"
        echo
        echo "       sudo START_AT=${next_num:-31} $0"
        echo
        echo "     (--domain/--hostname do not need to be repeated either way -"
        echo "     step 10 already saved them for replay.)"
        print_backup_manifest
        exit 0
    fi

    CURRENT_STEP="$base ($fn)"
    echo
    echo "############################################################"
    echo "# Step: $base"
    echo "############################################################"
    echo
    "$fn"
done

CURRENT_STEP="(all steps complete)"

echo
echo "############################################################"
echo "# All steps complete"
echo "############################################################"
echo
echo "IMPORTANT: reboot this server now, then verify hostname, network,"
echo "firewall and fail2ban all came back up correctly on their own —"
echo "changes applied live in this run (networkd restart, firewalld/ufw"
echo "reload) can still differ from what actually persists across a boot."
echo
echo "  reboot"
print_backup_manifest
