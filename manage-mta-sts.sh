#!/usr/bin/env bash
#
# manage-mta-sts.sh
#
# Standalone management of MTA-STS (RFC 8461) policy hosting for every
# active grommunio domain. Not part of server-setup.sh's pipeline - mirrors
# manage-dkim.sh/manage-certs.sh in spirit: re-run by hand any time a
# domain is added or removed.
#
# MTA-STS needs three things per domain, two of which this script handles:
#   1. A DNS TXT record at _mta-sts.<domain> ("v=STSv1; id=...") - NOT done
#      by this script, requires registrar access (--validate only checks,
#      read-only via resolvectl). Registrar-agnostic for the same reason:
#      this script never writes DNS itself, regardless of which registrar
#      is in use - you publish that TXT record by hand wherever your zone
#      lives, same as manage-dkim.sh.
#   2. A certificate covering mta-sts.<domain> - handled by
#      manage-certs.sh (already extended to include this hostname).
#   3. The policy file itself, served over HTTPS at exactly
#      https://mta-sts.<domain>/.well-known/mta-sts.txt - THIS script's
#      job: writes one nginx server block + one policy file PER DOMAIN,
#      fully independent of every other domain (even though their content
#      happens to be identical right now, since every domain here shares
#      the same mail server) - deliberately not a single shared
#      file/vhost, so a future domain-specific policy (different mode,
#      different mx, different max_age) needs only that one domain's own
#      files touched, nothing else.
#
# Same scoping as manage-certs.sh: only domains whose mta-sts.<domain>
# hostname actually resolves here are included - every run recomputes the
# complete list from scratch, not from a separate state file.
#
# Starts every domain in "testing" mode deliberately (not "enforce") -
# testing mode has zero delivery risk (failures are only reported, never
# block mail), the safe default until proven working. Switch a specific
# domain to "enforce" by hand later (edit that domain's own policy file),
# once confirmed working.
#
# Each domain's policy "mx:" field must match that domain's own real MX
# record - NOT necessarily this server's own global hostname. A domain
# whose mail.<domain> collides with this server's own canonical hostname
# gets a dedicated "mx1.<domain>" MX instead (see dane_label_for() in
# functions/00-common.sh, shared with manage-dane.sh - same reasoning:
# its PTR is set to mx1.<domain> specifically so it matches Postfix's own
# HELO name). cmd_generate() computes this correctly for files it writes,
# but - by design - never touches a policy file that already exists, so
# a file written before this per-domain logic existed can be stuck with
# the wrong mx forever. --status detects that; --reconfigure fixes it.
#
# Usage:
#   manage-mta-sts.sh                Show this help (no arguments = help).
#   manage-mta-sts.sh --all          Recompute the full domain list and
#                                    write/update each domain's own policy
#                                    file + nginx server block to match.
#                                    Never overwrites an existing policy
#                                    file's content - see --reconfigure.
#   manage-mta-sts.sh -domain <name> Same, but fail loudly if this one
#                                    domain's mta-sts.<domain> hostname
#                                    does not resolve here.
#   manage-mta-sts.sh --status       Check DNS (_mta-sts TXT), the
#                                    live-served policy file, and that
#                                    its "mx:" value matches this domain's
#                                    real MX record, for every active
#                                    domain; report what is missing or
#                                    wrong. Read-only, changes nothing.
#                                    (--validate is a kept alias.)
#   manage-mta-sts.sh --reconfigure  Like --all, but also FIXES an
#                                    existing policy file's "mx:" line if
#                                    it does not match this domain's real
#                                    MX record - the one thing --all
#                                    deliberately never touches. Preserves
#                                    that file's "mode:"/"max_age:"
#                                    exactly as they are (an enforce-mode
#                                    promotion, or a hand-tuned max_age,
#                                    survives).

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/functions/00-common.sh"

NET_CFG="$(cfg_file 10-network-hostname)"
PRIMARY_IPV4="" PRIMARY_IPV6=""
[[ -f "$NET_CFG" ]] && source "$NET_CFG"

POLICY_ROOT="/var/www/mta-sts"
NGINX_CONF="/etc/nginx/conf.d/mta-sts.conf"
DEFAULT_MAX_AGE=604800   # 1 week

show_help()
{
    sed -n '3,75p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

resolves_here()
{
    local host="$1" out
    if [[ -n "$PRIMARY_IPV4" ]]; then
        out="$(resolvectl query --type=A "$host" 2>/dev/null || true)"
        grep -qF "$PRIMARY_IPV4" <<< "$out" && return 0
    fi
    if [[ -n "$PRIMARY_IPV6" ]]; then
        out="$(resolvectl query --type=AAAA "$host" 2>/dev/null || true)"
        grep -qF "$PRIMARY_IPV6" <<< "$out" && return 0
    fi
    return 1
}

all_active_domains()
{
    grommunio-admin domain list 2>/dev/null | sed -nE 's/^[0-9]+: ([^ ]+) \(active\).*/\1/p'
}

# wanted_domains: every active domain whose mta-sts.<domain> hostname
# actually resolves here.
wanted_domains()
{
    local d
    local -a domains=()
    while read -r d; do [[ -n "$d" ]] && domains+=("$d"); done < <(all_active_domains)
    [[ "${#domains[@]}" -gt 0 ]] || die "No active domains found (grommunio-admin domain list)."

    for d in "${domains[@]}"; do
        if resolves_here "mta-sts.${d}"; then
            echo "$d"
        else
            log "[SKIP] $d: mta-sts.$d does not resolve to this server - excluded." >&2
        fi
    done
}

# policy_mx_for <domain>: the correct "mx:" value for that domain's own
# MTA-STS policy - its real MX hostname, via the same dane_label_for()
# this server's DANE setup uses (functions/00-common.sh), NOT this
# server's own global hostname. Using the wrong value here is exactly
# the bug --status/--reconfigure exist to catch and fix (see the header
# comment above).
policy_mx_for()
{
    local domain="$1"
    echo "$(dane_label_for "$domain").${domain}"
}

# _mta_sts_rebuild_nginx_conf: one nginx conf FILE, but one independent
# server{} block PER DOMAIN - never a shared block/shared server_name
# list, so one domain's block can diverge (e.g. its own cert, its own
# root) without touching any other domain's block. Rebuilt from scratch
# every run, matching the full current domain list exactly (a domain
# that stops resolving here is dropped here too, not left stale). Shared
# by cmd_generate and cmd_reconfigure - both need the exact same nginx
# side, only the policy-file side differs between them. Returns via the
# global $_changed (set to 1 if anything was written/reloaded).
_mta_sts_rebuild_nginx_conf()
{
    local -a domains=("$@")
    local conf_new d
    conf_new="$(mktemp)"
    {
        echo "# Managed by manage-mta-sts.sh - do not edit by hand."
        echo "# One independent server block per domain; see that script"
        echo "# for why this is deliberately not a single shared block."
        for d in "${domains[@]}"; do
            echo
            echo "server {"
            echo "    listen 443 ssl;"
            echo "    listen [::]:443 ssl;"
            echo "    http2 on;"
            echo "    server_name mta-sts.${d};"
            echo "    include /etc/grommunio-common/nginx/ssl_*.conf;"
            echo "    root ${POLICY_ROOT}/${d};"
            echo "    location /.well-known/mta-sts.txt {"
            echo "        default_type text/plain;"
            echo "    }"
            echo "    location / {"
            echo "        return 404;"
            echo "    }"
            echo "}"
        done
    } > "$conf_new"

    if ! cmp -s "$conf_new" "$NGINX_CONF" 2>/dev/null; then
        backup_file "$NGINX_CONF"
        install -m 0644 "$conf_new" "$NGINX_CONF"
        finalize_backup "$NGINX_CONF"
        _changed=1
        log "[ OK ] Wrote $NGINX_CONF with ${#domains[@]} domain-specific server block(s)."
    else
        log "[ OK ] $NGINX_CONF already up to date."
    fi
    rm -f "$conf_new"
}

# ============================================================
# cmd_generate: for every domain in scope, write/keep its own policy file
# and its own nginx server block. A domain's existing policy file is never
# overwritten if it already exists (so a hand-edited "enforce" switch, or
# a domain-specific mx/max_age, survives every re-run) - only missing
# domains get a fresh "testing" default written, with the correct
# per-domain mx (policy_mx_for). A file that already exists with the
# WRONG mx is left untouched here on purpose - see --reconfigure.
# ============================================================

cmd_generate()
{
    require_cmd resolvectl

    local -a domains=()
    while read -r d; do [[ -n "$d" ]] && domains+=("$d"); done < <(wanted_domains)
    [[ "${#domains[@]}" -gt 0 ]] || die "No mta-sts.<domain> hostname resolves to this server - nothing to configure."

    local _changed=0 d policy_file mx_host

    for d in "${domains[@]}"; do
        install -d -m 0755 "${POLICY_ROOT}/${d}/.well-known"
        policy_file="${POLICY_ROOT}/${d}/.well-known/mta-sts.txt"
        if [[ -f "$policy_file" ]]; then
            log "[ OK ] $d: $policy_file already exists - left as-is (edit it by hand for mode/mx/max_age changes, or run --status/--reconfigure to check/fix just the mx value)."
        else
            mx_host="$(policy_mx_for "$d")"
            printf 'version: STSv1\nmode: testing\nmx: %s\nmax_age: %s\n' "$mx_host" "$DEFAULT_MAX_AGE" > "$policy_file"
            chmod 0644 "$policy_file"
            _changed=1
            log "[ OK ] $d: wrote $policy_file (mode: testing, mx: $mx_host)."
        fi
    done

    _mta_sts_rebuild_nginx_conf "${domains[@]}"

    if [[ "$_changed" -eq 1 ]]; then
        nginx -t || die "nginx -t failed after the MTA-STS config change."
        systemctl reload nginx || die "nginx did not reload."
        log "[ OK ] nginx reloaded."
    fi
}

# ============================================================
# cmd_reconfigure: like cmd_generate, but also FIXES an existing policy
# file's "mx:" line if it does not match policy_mx_for() - the one thing
# cmd_generate deliberately never touches. Preserves that file's
# "mode:"/"max_age:" exactly as they are (an enforce-mode promotion, or
# a hand-tuned max_age, survives). Missing files are created fresh,
# same as cmd_generate.
# ============================================================

cmd_reconfigure()
{
    require_cmd resolvectl

    local -a domains=()
    while read -r d; do [[ -n "$d" ]] && domains+=("$d"); done < <(wanted_domains)
    [[ "${#domains[@]}" -gt 0 ]] || die "No mta-sts.<domain> hostname resolves to this server - nothing to configure."

    local _changed=0 d policy_file expected_mx actual_mx mode max_age

    for d in "${domains[@]}"; do
        install -d -m 0755 "${POLICY_ROOT}/${d}/.well-known"
        policy_file="${POLICY_ROOT}/${d}/.well-known/mta-sts.txt"
        expected_mx="$(policy_mx_for "$d")"

        if [[ ! -f "$policy_file" ]]; then
            printf 'version: STSv1\nmode: testing\nmx: %s\nmax_age: %s\n' "$expected_mx" "$DEFAULT_MAX_AGE" > "$policy_file"
            chmod 0644 "$policy_file"
            _changed=1
            log "[ OK ] $d: wrote $policy_file (mode: testing, mx: $expected_mx)."
            continue
        fi

        actual_mx="$(grep -E '^mx:' "$policy_file" | awk '{print $2}')"
        if [[ "$actual_mx" == "$expected_mx" ]]; then
            log "[ OK ] $d: $policy_file already has the correct mx ($expected_mx) - left as-is."
            continue
        fi

        mode="$(grep -E '^mode:' "$policy_file" | awk '{print $2}')"
        max_age="$(grep -E '^max_age:' "$policy_file" | awk '{print $2}')"
        mode="${mode:-testing}"
        max_age="${max_age:-$DEFAULT_MAX_AGE}"

        backup_file "$policy_file"
        printf 'version: STSv1\nmode: %s\nmx: %s\nmax_age: %s\n' "$mode" "$expected_mx" "$max_age" > "$policy_file"
        chmod 0644 "$policy_file"
        finalize_backup "$policy_file"
        _changed=1
        log "[FIX ] $d: $policy_file had mx '$actual_mx', corrected to '$expected_mx' (mode: $mode, max_age: $max_age preserved)."
    done

    _mta_sts_rebuild_nginx_conf "${domains[@]}"

    if [[ "$_changed" -eq 1 ]]; then
        nginx -t || die "nginx -t failed after the MTA-STS config change."
        systemctl reload nginx || die "nginx did not reload."
        log "[ OK ] nginx reloaded."
    else
        log "[ OK ] Nothing needed fixing."
    fi
}

# ============================================================
# cmd_status: DNS + live-served-policy + mx-correctness check, no
# changes made. (--validate is a kept alias for this same command.)
# ============================================================

cmd_status()
{
    require_cmd resolvectl
    require_cmd curl

    local -a all_domains=()
    while read -r d; do [[ -n "$d" ]] && all_domains+=("$d"); done < <(all_active_domains)

    local d failed=0 txt policy_url served expected_mx actual_mx
    for d in "${all_domains[@]}"; do
        echo
        echo "=== $d ==="

        txt="$(resolvectl query --type=TXT "_mta-sts.${d}" 2>/dev/null | grep -o 'v=STSv1[^"]*' || true)"
        if [[ -n "$txt" ]]; then
            echo "[ OK ] _mta-sts.$d TXT record found: $txt"
        else
            echo "[FAIL] _mta-sts.$d TXT record not found."
            failed=$((failed + 1))
        fi

        if resolves_here "mta-sts.${d}"; then
            echo "[ OK ] mta-sts.$d resolves to this server."
            policy_url="https://mta-sts.${d}/.well-known/mta-sts.txt"
            served="$(curl -sf --max-time 5 "$policy_url" 2>/dev/null || true)"
            if [[ -n "$served" ]]; then
                echo "[ OK ] Policy served at $policy_url:"
                sed 's/^/       /' <<< "$served"

                expected_mx="$(policy_mx_for "$d")"
                actual_mx="$(grep -E '^mx:' <<< "$served" | awk '{print $2}')"
                if [[ "$actual_mx" == "$expected_mx" ]]; then
                    echo "[ OK ] Served mx ($actual_mx) matches this domain's real MX hostname."
                else
                    echo "[FAIL] Served mx is '$actual_mx', should be '$expected_mx' (run --reconfigure to fix)."
                    failed=$((failed + 1))
                fi
            else
                echo "[FAIL] Could not fetch $policy_url (nginx not configured? run --all first)."
                failed=$((failed + 1))
            fi
        else
            echo "[SKIP] mta-sts.$d does not resolve to this server - not ours to serve."
        fi
    done

    echo
    if [[ "$failed" -eq 0 ]]; then
        log "[ OK ] No issues found for any domain whose DNS already points here."
    else
        err "$failed issue(s) found - see [FAIL] lines above."
        return 1
    fi
}

# ============================================================
# Argument parsing
# ============================================================

if [[ $# -eq 0 ]]; then
    show_help
    exit 0
fi

ACTION="" TARGET_DOMAIN=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --all)
            ACTION="all"; shift ;;
        -domain)
            [[ -n "${2:-}" ]] || die "-domain needs a value."
            ACTION="domain"; TARGET_DOMAIN="$2"; shift 2 ;;
        --status|--validate)
            ACTION="status"; shift ;;
        --reconfigure)
            ACTION="reconfigure"; shift ;;
        -h|--help)
            show_help; exit 0 ;;
        *)
            echo "manage-mta-sts.sh: unknown option: $1 (see --help)" >&2
            exit 1 ;;
    esac
done

require_root
require_cmd grommunio-admin

case "$ACTION" in
    all)
        cmd_generate
        ;;
    domain)
        mapfile -t ALL_DOMAINS < <(all_active_domains)
        found=0
        for a in "${ALL_DOMAINS[@]}"; do [[ "$a" == "$TARGET_DOMAIN" ]] && { found=1; break; }; done
        [[ "$found" -eq 1 ]] || die "Domain '$TARGET_DOMAIN' is not an active grommunio domain (grommunio-admin domain list)."
        resolves_here "mta-sts.$TARGET_DOMAIN" || die "mta-sts.$TARGET_DOMAIN does not resolve to this server."
        cmd_generate
        ;;
    status)
        cmd_status
        ;;
    reconfigure)
        cmd_reconfigure
        ;;
    *)
        show_help
        exit 1
        ;;
esac
