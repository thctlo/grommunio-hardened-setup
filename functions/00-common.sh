#!/usr/bin/env bash
#
# 00-common.sh
#
# Shared helpers for every step function under functions/. Sourced first by
# server-setup.sh (numeric order). Defines no step_* function itself — it
# only provides building blocks the numbered steps use.
#
# Config persistence convention:
#   Each step writes what it decided (not raw detected facts — those are
#   always re-detected fresh on every run) to a small shell-sourceable file
#   under CFG_DIR, one file per step, named after the step's own script
#   (e.g. 10-network-hostname.conf for functions/10-network-hostname.sh).
#   On a later run (replay, or a fresh server built the same way), a step
#   that finds its own config file loads it and skips the interactive
#   questions, going straight to apply/verify with the same answers.
#
#   This does NOT skip the safety confirmations before a destructive change
#   (network restart, firewall enable) — only the "what do you want" prompts.

CFG_DIR="/root/cfg-server"

# ============================================================
# Pre-change backups
#
# One timestamp per invocation of whatever sourced this file (server-setup.sh
# itself, or a standalone script like manage-mfa.sh run on its own) - every
# backup_file call made during that single run lands under the same
# directory, so it is always obvious which backups belong together and
# what the system looked like right before that run started.
#
# BACKUP_ROOT is intentionally allowed to come in pre-set from the
# environment (server-setup.sh does not need to do this; it is here for
# tests/tooling that want every sourced script to agree on one timestamp
# without re-deriving it independently).
# ============================================================
RUN_TIMESTAMP="${RUN_TIMESTAMP:-$(date +%Y%m%d-%H%M%S)}"
BACKUP_ROOT="${BACKUP_ROOT:-/root/backups/${RUN_TIMESTAMP}}"
MANIFEST_FILE="${BACKUP_ROOT}/modified-files.txt"

# backup_file <absolute path>
#
# Copies an existing file to BACKUP_ROOT, preserving its full original path
# (e.g. /etc/gromox/keycloak.json -> $BACKUP_ROOT/etc/gromox/keycloak.json),
# and records it in MANIFEST_FILE (one line per actual backup: the
# step/script that touched the file, the original path, then where this
# particular backup landed) - see print_backup_manifest below, which reads
# this file back. A no-op, successfully, if the path does not exist yet
# (nothing to back up - most config files this framework writes do not
# exist before their own step creates them for the first time). Call this
# immediately before any line that creates or overwrites a file already on
# disk (cat >, sed -i, cp as a destination, install, postconf -e, etc.) -
# never after - and call finalize_backup (below) on that same path right
# after the write/edit finishes.
#
# NOT idempotent across repeated touches, by design: the same file is
# often modified by several different steps within one run (e.g.
# /etc/postfix/main.cf, touched by 34-postfix-hardening.sh,
# 34-postfix-tls.sh, 38-antispam.sh and 50-grommunio-archive.sh in the
# same run). The first call backs up the true pre-run original to the
# plain path; every later call in the same run that finds that path
# already taken appends ".1", ".2", ".3"... instead of overwriting it or
# skipping - so the manifest shows the actual before-each-step
# progression, not just a single before/after snapshot of the whole run.
#
# Records the destination it just computed in _BACKUP_DEST_FOR[<target>]
# for finalize_backup to use - keyed by target path (not a single
# last-call slot), so backing up several files in a batch before writing
# any of them (several steps do exactly this) still lets finalize_backup
# find the right backup for each one later, in any order. Not meant to
# be read directly by callers.
declare -A _BACKUP_DEST_FOR

backup_file()
{
    local target="$1"
    unset '_BACKUP_DEST_FOR[$target]' 2>/dev/null
    [[ -e "$target" ]] || return 0
    local dest="${BACKUP_ROOT}${target}"
    mkdir -p "$(dirname "$dest")"
    if [[ -e "$dest" ]]; then
        local n=1
        while [[ -e "${dest}.${n}" ]]; do
            n=$((n + 1))
        done
        dest="${dest}.${n}"
    fi
    cp -a "$target" "$dest"
    mkdir -p "$(dirname "$MANIFEST_FILE")"
    printf '%-40s %-50s %s\n' "$(basename "${BASH_SOURCE[1]:-server-setup.sh}")" "$target" "$dest" >> "$MANIFEST_FILE"
    _BACKUP_DEST_FOR["$target"]="$dest"
}

# finalize_backup <same path just passed to backup_file>
#
# Call exactly once, after whatever wrote/edited/copied that same path
# finishes - regardless of how (heredoc, sed -i, cp, a separate tool),
# and regardless of how many OTHER files' backup_file/finalize_backup
# calls happen in between (looked up by target path, not call order). If
# the file ended up byte-identical to the backup backup_file took for it
# - i.e. nothing actually changed this run, which is common since most
# steps regenerate a config from scratch every time - this removes that
# backup copy and its manifest line again, so the manifest (and the
# backup directory itself) only ever reflects files genuinely modified
# this run, not every file a step merely considered touching.
#
# Safe/no-op (never dies, never blocks the real provisioning logic over
# backup bookkeeping) if: this target has no recorded backup_file call
# this run (a missed pairing - treat as "nothing to finalize", don't
# guess), or backup_file found nothing to back up in the first place (a
# brand new file has nothing to compare against, so it is always kept,
# as before).
finalize_backup()
{
    local target="$1"
    local dest="${_BACKUP_DEST_FOR[$target]:-}"
    [[ -n "$dest" ]] || return 0
    [[ -e "$target" && -e "$dest" ]] || return 0
    if cmp -s "$target" "$dest"; then
        rm -f "$dest"
        if [[ -f "$MANIFEST_FILE" ]]; then
            # grep -v exits 1 (not an error here) when the filtered
            # result is empty - the "|| true" matters even without an
            # explicit "&&" after it: under set -e (every caller of this
            # file has it), a bare command returning non-zero still
            # aborts the whole script, found live when this was the
            # only remaining manifest line.
            grep -vF "$dest" "$MANIFEST_FILE" > "${MANIFEST_FILE}.tmp" 2>/dev/null || true
            mv "${MANIFEST_FILE}.tmp" "$MANIFEST_FILE"
        fi
    fi
    unset '_BACKUP_DEST_FOR[$target]'
}

# print_backup_manifest
#
# Prints a summary of every file this run has modified (per MANIFEST_FILE,
# written by backup_file above) plus where the actual backups live. Safe
# to call with nothing backed up yet (prints that explicitly, not a wall
# of nothing). Called from server-setup.sh at every point the script can
# stop: normal completion, the --no-grommunio-setup early stop, and the
# top-level error trap - so there is always a clear answer to "what did
# this run actually touch", including on a failed/aborted run.
print_backup_manifest()
{
    echo
    echo "------------------------------------------------------------"
    echo "Files modified this run"
    echo "------------------------------------------------------------"
    if [[ -s "$MANIFEST_FILE" ]]; then
        column -t "$MANIFEST_FILE" 2>/dev/null || cat "$MANIFEST_FILE"
        echo
        echo "Originals backed up under: $BACKUP_ROOT"
        echo "This list: $MANIFEST_FILE"
    else
        echo "(none yet)"
    fi
    echo
}

log()  { echo "[$(basename "${BASH_SOURCE[1]:-server-setup.sh}")] $*"; }
err()  { echo "[$(basename "${BASH_SOURCE[1]:-server-setup.sh}")] ERROR: $*" >&2; }
die()  { err "$*"; exit 1; }

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        die "This script must be run as root (e.g. with sudo)."
    fi
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "Required command '$1' not found."
}

is_valid_ipv4() {
    local ip="$1"
    local IFS='.'
    local -a octets
    read -r -a octets <<< "$ip"
    [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
    for octet in "${octets[@]}"; do
        [[ "$octet" =~ ^[0-9]+$ ]] || return 1
        (( octet >= 0 && octet <= 255 )) || return 1
    done
    return 0
}

is_valid_ipv6() {
    local ip="$1"
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$ip" <<'PY' 2>/dev/null
import sys, ipaddress
try:
    ipaddress.IPv6Address(sys.argv[1])
except ValueError:
    sys.exit(1)
PY
        return $?
    fi
    [[ "$ip" =~ ^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$ ]]
}

ip_family() {
    [[ "$1" == *:* ]] && echo ipv6 || echo ipv4
}

# ensure_cfg_dir: create /root/cfg-server (0700, root-only: it can hold
# passwords and other sensitive values entered during setup).
ensure_cfg_dir() {
    mkdir -p "${CFG_DIR}"
    chmod 700 "${CFG_DIR}"
}

# cfg_file <step-script-basename-without-.sh>
# e.g. cfg_file 10-network-hostname  ->  /root/cfg-server/10-network-hostname.conf
cfg_file() {
    echo "${CFG_DIR}/$1.conf"
}

# save_cfg <file> KEY=VALUE [KEY=VALUE ...]
# Writes a shell-sourceable config file (0600). Values are single-quoted;
# any literal single quote in a value is escaped correctly for re-sourcing.
save_cfg() {
    local file="$1"; shift
    ensure_cfg_dir
    {
        echo "# Written by $(basename "${BASH_SOURCE[1]:-server-setup.sh}") on $(date -Is)"
        echo "# Safe to hand-edit before a replay run; delete this file to be re-prompted."
        for kv in "$@"; do
            local key="${kv%%=*}"
            local val="${kv#*=}"
            printf '%s=%q\n' "$key" "$val"
        done
    } > "$file"
    chmod 600 "$file"
}

# save_cfg_array <file> ARRAY_NAME_TO_WRITE <values...>
# Writes an array assignment line, e.g. WHITELIST_IPS=("1.2.3.4" "::1")
save_cfg_array_append() {
    local file="$1" name="$2"; shift 2
    printf '%s=(' "$name" >> "$file"
    for v in "$@"; do
        printf '%q ' "$v" >> "$file"
    done
    printf ')\n' >> "$file"
}

# ============================================================
# Shared grommunio admin password for this run
# Kept in memory only: never written to disk, never in the saved answers.
# Step 30 sets it after the wizard; later steps use it instead of asking again.
# ============================================================
SHARED_ADMIN_PASSWORD="${SHARED_ADMIN_PASSWORD:-}"

shared_admin_password_get()
{
    # $1 = prompt text. Asks only when no password is kept for this run.
    if [[ -z "$SHARED_ADMIN_PASSWORD" ]]; then
        local p=""
        read -r -s -p "${1:-Shared grommunio admin password: }" p
        echo
        SHARED_ADMIN_PASSWORD="$p"
    fi
}

shared_admin_password_confirm()
{
    # Asks twice; keeps the password only when both entries match.
    local a b
    while true; do
        read -r -s -p "Shared grommunio admin password (same one grommunio-setup just showed you): " a
        echo
        read -r -s -p "Once more, to confirm: " b
        echo
        if [[ -n "$a" && "$a" == "$b" ]]; then
            SHARED_ADMIN_PASSWORD="$a"
            log "[ OK ] Admin password kept for this run (memory only, not saved)."
            return 0
        fi
        err "The two entries do not match or are empty. Try again."
    done
}

# first_active_domain: the domain this server was FIRST installed with,
# determined the same way IS_FIRST_DOMAIN already works in
# 31-grommunio-domain.sh (lowest grommunio-admin domain ID among active
# domains) - confirmed live 2026-10-30 that domain IDs reflect creation
# order (the actual first domain on a test server had ID 1; later
# domains had higher IDs even after one was deleted and another added in
# between). Used by anything that needs "the" primary domain for a
# first-domain-only feature (e.g. the dedicated mx1.<domain> MX hostname,
# see dns-records-reference.md) without re-deriving that logic separately
# each time. Prints nothing and returns 1 if there are no active domains
# yet (e.g. called before step 31 has ever run).
first_active_domain()
{
    grommunio-admin domain list 2>/dev/null \
        | sed -nE 's/^([0-9]+): ([^ ]+) \(active\).*/\1 \2/p' \
        | sort -n -k1,1 \
        | awk 'NR==1{print $2}'
}
