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
# Usage:
#   manage-mta-sts.sh                Show this help (no arguments = help).
#   manage-mta-sts.sh --all          Recompute the full domain list and
#                                    write/update each domain's own policy
#                                    file + nginx server block to match.
#   manage-mta-sts.sh -domain <name> Same, but fail loudly if this one
#                                    domain's mta-sts.<domain> hostname
#                                    does not resolve here.
#   manage-mta-sts.sh --validate     Check DNS (_mta-sts TXT + mta-sts.
#                                    A/AAAA) and the live-served policy
#                                    file for every active domain; report
#                                    what is still missing (DNS is never
#                                    fixed by this script, by design).

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/functions/00-common.sh"

NET_CFG="$(cfg_file 10-network-hostname)"
NEW_FQDN="" PRIMARY_IPV4="" PRIMARY_IPV6=""
[[ -f "$NET_CFG" ]] && source "$NET_CFG"
MX_HOST="${NEW_FQDN:-mail.example.com}"

POLICY_ROOT="/var/www/mta-sts"
NGINX_CONF="/etc/nginx/conf.d/mta-sts.conf"
DEFAULT_MAX_AGE=604800   # 1 week

show_help()
{
    sed -n '3,37p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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

# ============================================================
# cmd_generate: for every domain in scope, write/keep its own policy file
# and its own nginx server block. A domain's existing policy file is never
# overwritten if it already exists (so a hand-edited "enforce" switch, or
# a domain-specific mx/max_age, survives every re-run) - only missing
# domains get a fresh "testing" default written.
# ============================================================

cmd_generate()
{
    require_cmd resolvectl

    local -a domains=()
    while read -r d; do [[ -n "$d" ]] && domains+=("$d"); done < <(wanted_domains)
    [[ "${#domains[@]}" -gt 0 ]] || die "No mta-sts.<domain> hostname resolves to this server - nothing to configure."

    local changed=0 d policy_file server_block_file

    for d in "${domains[@]}"; do
        install -d -m 0755 "${POLICY_ROOT}/${d}/.well-known"
        policy_file="${POLICY_ROOT}/${d}/.well-known/mta-sts.txt"
        if [[ -f "$policy_file" ]]; then
            log "[ OK ] $d: $policy_file already exists - left as-is (edit it by hand for mode/mx/max_age changes)."
        else
            printf 'version: STSv1\nmode: testing\nmx: %s\nmax_age: %s\n' "$MX_HOST" "$DEFAULT_MAX_AGE" > "$policy_file"
            chmod 0644 "$policy_file"
            changed=1
            log "[ OK ] $d: wrote $policy_file (mode: testing, mx: $MX_HOST)."
        fi
    done

    # One nginx conf FILE, but one independent server{} block PER DOMAIN -
    # never a shared block/shared server_name list, so one domain's block
    # can diverge (e.g. its own cert, its own root) without touching any
    # other domain's block. Rebuilt from scratch every run, matching the
    # full current domain list exactly (a domain that stops resolving
    # here is dropped here too, not left stale).
    local conf_new
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
        changed=1
        log "[ OK ] Wrote $NGINX_CONF with ${#domains[@]} domain-specific server block(s)."
    else
        log "[ OK ] $NGINX_CONF already up to date."
    fi
    rm -f "$conf_new"

    if [[ "$changed" -eq 1 ]]; then
        nginx -t || die "nginx -t failed after the MTA-STS config change."
        systemctl reload nginx || die "nginx did not reload."
        log "[ OK ] nginx reloaded."
    fi
}

# ============================================================
# cmd_validate: DNS + live-served-policy check, no changes made.
# ============================================================

cmd_validate()
{
    require_cmd resolvectl
    require_cmd curl

    local -a all_domains=()
    while read -r d; do [[ -n "$d" ]] && all_domains+=("$d"); done < <(all_active_domains)

    local d failed=0 txt policy_url served
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
        log "[ OK ] No missing pieces found for any domain whose DNS already points here."
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
        --validate)
            ACTION="validate"; shift ;;
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
    validate)
        cmd_validate
        ;;
    *)
        show_help
        exit 1
        ;;
esac
