#!/usr/bin/env bash
#
# check-cert-readiness.sh
#
# Standalone, read-only pre-flight check: is a domain ready for an
# HTTP-01 Let's Encrypt certificate on THIS server? Checks:
#   - CAA records: either none at all, or an explicit "letsencrypt.org"
#     issue entry - anything else would make issuance fail outright.
#   - The 3 hostnames manage-certs.sh cares about for HTTP-01 purposes:
#     <domain>, mail.<domain>, autodiscover.<domain> - do they already
#     resolve (A/AAAA) to this server's own saved primary address(es)?
#
# Deliberately excludes mta-sts.<domain> and TLSA/DANE - those are
# separate, later concerns once a domain actually has mail flowing
# here; this is only "can a cert even be requested here at all".
#
# Works for ANY domain, including one not yet added to grommunio at
# all (unlike manage-certs.sh --status, which only ever considers
# domains grommunio-admin already knows about) - meant to be run
# BEFORE a domain is cut over, while preparing for it.
#
# Fully registrar-agnostic and never writes anything - only queries
# DNS (resolvectl/dig).
#
# Usage:
#   check-cert-readiness.sh -domain <name>            Check one domain.
#   check-cert-readiness.sh -domain <name> --brief    Only [FAIL] lines
#                                                       and the summary.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/functions/00-common.sh"

NET_CFG="$(cfg_file 10-network-hostname)"
PRIMARY_IPV4="" PRIMARY_IPV6=""
[[ -f "$NET_CFG" ]] && source "$NET_CFG"

# Same auto-detect fallback as check-dns.sh, for the same reason: this
# script is meant to be runnable before step 10 has ever saved
# anything. `ip route get` only consults the routing table (no packet
# sent) - read-only, nothing saved to disk.
if [[ -z "$PRIMARY_IPV4" ]]; then
    PRIMARY_IPV4="$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || true)"
    [[ -n "$PRIMARY_IPV4" ]] && log "Auto-detected primary IPv4: ${PRIMARY_IPV4} (step 10 has not saved one yet)."
fi
if [[ -z "$PRIMARY_IPV6" ]]; then
    PRIMARY_IPV6="$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | grep -oP 'src \K\S+' || true)"
    [[ -n "$PRIMARY_IPV6" ]] && log "Auto-detected primary IPv6: ${PRIMARY_IPV6} (step 10 has not saved one yet)."
fi

show_help() {
    sed -n '3,27p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

BRIEF=0
TARGET_DOMAIN=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -domain) TARGET_DOMAIN="${2:-}"; shift 2 ;;
        --brief) BRIEF=1; shift ;;
        -h|--help) show_help; exit 0 ;;
        *) shift ;;
    esac
done
if [[ -z "$TARGET_DOMAIN" ]]; then
    show_help
    exit 0
fi

# resolves_here <hostname>: same check as manage-certs.sh's own
# resolves_here() - kept in sync deliberately, not sourced, since this
# script must also run standalone against a domain manage-certs.sh
# doesn't know about at all yet.
resolves_here() {
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

ISSUES=0

# --- CAA ---
CAA_OUTPUT="$(dig +short CAA "$TARGET_DOMAIN" 2>/dev/null || true)"
if [[ -z "$CAA_OUTPUT" ]]; then
    [[ "$BRIEF" -eq 1 ]] || log "[ OK ] ${TARGET_DOMAIN}: no CAA records - any CA, including Let's Encrypt, may issue."
elif grep -qi 'letsencrypt\.org' <<< "$CAA_OUTPUT"; then
    [[ "$BRIEF" -eq 1 ]] || log "[ OK ] ${TARGET_DOMAIN}: CAA explicitly permits letsencrypt.org."
else
    log "[FAIL] ${TARGET_DOMAIN}: CAA records exist but do NOT list letsencrypt.org - issuance would be refused:"
    while IFS= read -r caa_line; do log "       ${caa_line}"; done <<< "$CAA_OUTPUT"
    ISSUES=$((ISSUES + 1))
fi

# --- Hostnames (HTTP-01 relevant only) ---
for host in "$TARGET_DOMAIN" "mail.${TARGET_DOMAIN}" "autodiscover.${TARGET_DOMAIN}"; do
    if resolves_here "$host"; then
        [[ "$BRIEF" -eq 1 ]] || log "[ OK ] ${host} resolves to this server."
    else
        log "[FAIL] ${host} does NOT resolve to this server - HTTP-01 cannot validate it yet."
        ISSUES=$((ISSUES + 1))
    fi
done

echo
if [[ "$ISSUES" -eq 0 ]]; then
    log "SUMMARY: ${TARGET_DOMAIN} is ready for an HTTP-01 certificate on this server."
else
    log "SUMMARY: ${TARGET_DOMAIN} has ${ISSUES} issue(s) - not yet ready."
fi
exit $(( ISSUES > 0 ))
