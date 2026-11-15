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

# ============================================================
# --brief support for manage-*.sh's own --status/--report/--setup
# output. A caller sets BRIEF=1 before running its checks; okline()
# then silently drops [ OK ] lines while failline()/warnline() always
# print - giving the exact "only what needs attention, one-line
# summary" shape check-dns.sh's own --brief already had, now shared
# instead of three scripts reimplementing the same filter separately.
# Added 2026-11-15 alongside --report/--mail for manage-dane.sh/
# manage-dkim.sh/manage-mta-sts.sh - the three tools that can actually
# write DNS records, per the operator's own request to add these consistently
# wherever that's true.
# ============================================================
BRIEF="${BRIEF:-0}"

okline()   { [[ "$BRIEF" -eq 1 ]] || echo "[ OK ] $*"; }
failline() { echo "[FAIL] $*"; }
warnline() { echo "[WARN] $*"; }

# ============================================================
# --mail support: every manage-*.sh --mail option sends its captured
# output through the LOCAL MTA (sendmail -t) - no mailx/mail binary
# dependency (confirmed not installed; only /usr/sbin/sendmail is).
# ============================================================

# default_report_mail_to: "admin@<first active domain>" - the hub
# mailbox step 31 creates for every server, the default --mail
# recipient whenever one isn't given explicitly. Prints nothing if
# there is no active domain yet (nothing to default to).
default_report_mail_to()
{
    local first
    first="$(first_active_domain)"
    [[ -n "$first" ]] && echo "admin@${first}"
}

# send_report_mail <to> <subject> <body>: plain-text report mail via
# sendmail -t. From is root@<this server's own real FQDN> (NEW_FQDN if
# step 10 saved one, else `hostname -f`) - matches what any other
# local cron/report mail on this server already looks like.
send_report_mail()
{
    local to="$1" subject="$2" body="$3"
    local net_cfg new_fqdn="" from
    net_cfg="$(cfg_file 10-network-hostname)"
    [[ -f "$net_cfg" ]] && source "$net_cfg" 2>/dev/null
    from="root@${NEW_FQDN:-$(hostname -f 2>/dev/null || echo localhost)}"
    require_cmd sendmail
    {
        echo "From: ${from}"
        echo "To: ${to}"
        echo "Subject: ${subject}"
        echo "Date: $(date -R)"
        echo "Content-Type: text/plain; charset=UTF-8"
        echo
        echo "$body"
    } | sendmail -t
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

# dane_label_for: the correct mail-hostname LABEL for a domain's own MX
# record. "mx1" for whichever domain is first_active_domain() (it has no
# mail.<domain>-shaped hostname of its own that could serve this - that
# name means the shared server identity for it specifically, see
# dns-records-reference.md; its PTR record is also set to mx1.<domain>
# specifically so it matches Postfix's own HELO name). "mail" for every
# other domain - it already has its own mail.<domain> A/AAAA from normal
# domain setup, nothing new to create there. Shared by manage-dane.sh and
# manage-mta-sts.sh - both need the same real MX hostname per domain, and
# must never derive it two different ways.
dane_label_for()
{
    local domain="$1" first
    first="$(first_active_domain)"
    if [[ "$domain" == "$first" ]]; then
        echo "mx1"
    else
        echo "mail"
    fi
}

# discover_cert_name: the REAL name of the one shared Let's Encrypt
# certificate this stack issues (see manage-certs.sh's own header) -
# whatever hostname it actually lives under in /etc/letsencrypt/live/,
# never guessed from the system/web hostname alone. Moved here
# 2026-11-15 after the same hardcoded "CERT_NAME=${NEW_FQDN:-...}" bug
# was found independently in both manage-certs.sh and manage-dane.sh:
# certbot names the live/ directory after whatever --cert-name it was
# issued with, which on a server with a dedicated mx-hostname is
# Postfix's own identity (NEW_MX_FQDN), not the web hostname (NEW_FQDN)
# - confirmed live, the real directory was mx1.example1.eu, not
# mail.example1.eu. Checks postconf's live myhostname first (the
# actual source of truth for what the cert SHOULD be named after), then
# NEW_MX_FQDN/NEW_FQDN as saved-config fallbacks, then whatever single
# certificate actually exists on disk, so every caller discovers the
# same name the same way instead of each hardcoding its own guess that
# can silently drift from reality (and from each other).
discover_cert_name()
{
    local net_cfg new_fqdn="" new_mx_fqdn="" candidate
    net_cfg="$(cfg_file 10-network-hostname)"
    [[ -f "$net_cfg" ]] && source "$net_cfg" 2>/dev/null
    new_fqdn="${NEW_FQDN:-}"; new_mx_fqdn="${NEW_MX_FQDN:-}"

    if command -v postconf >/dev/null 2>&1; then
        candidate="$(postconf -h myhostname 2>/dev/null || true)"
        [[ -n "$candidate" && -f "/etc/letsencrypt/live/${candidate}/cert.pem" ]] && { echo "$candidate"; return; }
    fi
    for candidate in "$new_mx_fqdn" "$new_fqdn"; do
        [[ -n "$candidate" && -f "/etc/letsencrypt/live/${candidate}/cert.pem" ]] && { echo "$candidate"; return; }
    done
    for candidate in /etc/letsencrypt/live/*/; do
        [[ -f "${candidate}cert.pem" ]] || continue
        basename "${candidate%/}"
        return
    done
    echo "${new_mx_fqdn:-${new_fqdn:-mail.example.com}}"
}

# ============================================================
# TransIP DNS account helpers - shared by every manage-*.sh tool that
# can write DNS records via the TransIP API (manage-dane.sh,
# manage-dkim.sh's --setup). Moved here 2026-11-15 when manage-dkim.sh
# needed the exact same per-domain account resolution manage-dane.sh
# had just gained - keeping one copy instead of two that can drift.
# ============================================================

# accounts.d/*.ini (directory mode), not the legacy single-file
# transip.ini/transip.key pair this project used before 2026-11-04 -
# that pair was an old, no-longer-used leftover and has since been
# deleted (confirmed on purpose, not a bug to work around here).
#
# Hardcoding "account1" specifically breaks the moment a second TransIP
# account exists - resolved PER DOMAIN instead, the same way
# certbot_dns_transip's own plugin does it (see its
# _load_account_directory/dns_transip_domains in
# /usr/lib/python3/dist-packages/certbot_dns_transip/dns_transip.py):
# each accounts.d/*.ini may list its own "dns_transip_domains" (comma-
# separated) - the account whose list contains the domain being managed
# wins. Unlike the plugin, this does NOT also fall back to a live API
# probe when no ini hints the domain - every caller here only ever
# touches a domain this server already knows about (step 31), so
# requiring an explicit dns_transip_domains hint is a reasonable, much
# simpler substitute for that same live-probe fallback.
TRANSIP_ACCOUNTS_DIR="${TRANSIP_ACCOUNTS_DIR:-/etc/letsencrypt/transip/accounts.d}"

# transip_account_for <domain>: prints the accounts.d/*.ini path whose
# own dns_transip_domains (comma-separated, matching the format
# certbot_dns_transip's own ConfigObj parsing produces) lists this
# domain, or nothing + returns 1 if no account hints it.
transip_account_for()
{
    local domain="$1" ini_file domains_line d
    [[ -d "$TRANSIP_ACCOUNTS_DIR" ]] || return 1
    for ini_file in "$TRANSIP_ACCOUNTS_DIR"/*.ini; do
        [[ -f "$ini_file" ]] || continue
        domains_line="$(grep '^dns_transip_domains' "$ini_file" | sed 's/.*= *//')"
        [[ -n "$domains_line" ]] || continue
        IFS=',' read -ra listed <<< "$domains_line"
        for d in "${listed[@]}"; do
            d="${d//[[:space:]]/}"
            [[ "$d" == "$domain" ]] && { echo "$ini_file"; return 0; }
        done
    done
    return 1
}

have_transip_creds()
{
    local domain="$1" ini_file key_file
    ini_file="$(transip_account_for "$domain")" || return 1
    key_file="$(grep '^dns_transip_key_file' "$ini_file" | sed 's/.*= *//')"
    [[ -n "$key_file" && -f "$key_file" ]]
}

transip_user_for()
{
    local domain="$1" ini_file
    ini_file="$(transip_account_for "$domain")" || return 1
    grep '^dns_transip_username' "$ini_file" | sed 's/.*= *//'
}

transip_key_for()
{
    local domain="$1" ini_file
    ini_file="$(transip_account_for "$domain")" || return 1
    grep '^dns_transip_key_file' "$ini_file" | sed 's/.*= *//'
}

# transip_live_ttl_for <domain> <name> <type>: the TTL the record
# ACTUALLY has right now, straight from the TransIP API via `transip-dns
# list` (not resolvectl - a resolver's cached/default TTL display can
# disagree with the authoritative value, and `transip-dns update`
# requires the exact live one, name/type/TTL must match the live record
# exactly - TTL is not something update can change, see its own
# --help).
transip_live_ttl_for()
{
    local domain="$1" name="$2" rtype="$3" user key_file
    user="$(transip_user_for "$domain")" || return 1
    key_file="$(transip_key_for "$domain")" || return 1
    transip-dns --username "$user" --key-file "$key_file" list "$domain" 2>/dev/null \
        | awk -v n="$name" -v t="$rtype" '$1 == n && $3 == t { print $2; exit }'
}
