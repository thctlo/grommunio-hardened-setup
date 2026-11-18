#!/usr/bin/env bash
#
# bootstrap-domain-dns.sh
#
# Creates the basic DNS a brand-new domain needs before
# check-cert-readiness.sh/manage-certs.sh can do anything useful at all:
#   <domain>              A/AAAA -> this server's own saved primary address(es)
#   mail.<domain>         A/AAAA -> same
#   autodiscover.<domain> CNAME  -> mail.<domain>
#
# No existing script in this project actually writes a brand-new
# domain's first A/AAAA records - manage-certs.sh/manage-dane.sh/
# manage-mta-sts.sh all assume those already exist and only add
# further records (cert SAN, TLSA, MTA-STS policy host) on top. This
# fills that one gap, reusing the same TransIP helpers
# (transip_account_for/have_transip_creds/transip_user_for/
# transip_key_for, functions/00-common.sh) and the same fallback
# pattern as every other DNS-writing tool here: on a registrar other
# than TransIP, --setup cannot write anything, so it prints the exact
# records to add by hand instead (same as manage-dane.sh --setup).
#
# --setup writes real DNS zone records. The operator runs this
# command themselves - an agent must never run --setup (same rule as
# every other DNS-writing tool in this project). --report is always
# safe (read-only, prints what --setup would do without doing it).
#
# Usage:
#   bootstrap-domain-dns.sh -domain <name> --report   Print what would
#                                                       be added, write
#                                                       nothing.
#   bootstrap-domain-dns.sh -domain <name> --setup    Actually create
#                                                       the records
#                                                       (TransIP only).

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/functions/00-common.sh"

NET_CFG="$(cfg_file 10-network-hostname)"
PRIMARY_IPV4="" PRIMARY_IPV6=""
[[ -f "$NET_CFG" ]] && source "$NET_CFG"

# Same auto-detect fallback as check-dns.sh/check-cert-readiness.sh -
# read-only, nothing saved to disk.
if [[ -z "$PRIMARY_IPV4" ]]; then
    PRIMARY_IPV4="$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || true)"
fi
if [[ -z "$PRIMARY_IPV6" ]]; then
    PRIMARY_IPV6="$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | grep -oP 'src \K\S+' || true)"
fi

show_help() {
    sed -n '3,29p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

MODE="" TARGET_DOMAIN=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -domain) TARGET_DOMAIN="${2:-}"; shift 2 ;;
        --setup) MODE="setup"; shift ;;
        --report) MODE="report"; shift ;;
        -h|--help) show_help; exit 0 ;;
        *) shift ;;
    esac
done
if [[ -z "$TARGET_DOMAIN" || -z "$MODE" ]]; then
    show_help
    exit 0
fi
[[ -n "$PRIMARY_IPV4" || -n "$PRIMARY_IPV6" ]] || die "Could not determine this server's own primary address - run step 10 first."

print_records() {
    [[ -n "$PRIMARY_IPV4" ]] && echo "  ${TARGET_DOMAIN}              A      ${PRIMARY_IPV4}"
    [[ -n "$PRIMARY_IPV6" ]] && echo "  ${TARGET_DOMAIN}              AAAA   ${PRIMARY_IPV6}"
    [[ -n "$PRIMARY_IPV4" ]] && echo "  mail.${TARGET_DOMAIN}         A      ${PRIMARY_IPV4}"
    [[ -n "$PRIMARY_IPV6" ]] && echo "  mail.${TARGET_DOMAIN}         AAAA   ${PRIMARY_IPV6}"
    echo "  autodiscover.${TARGET_DOMAIN}  CNAME  mail.${TARGET_DOMAIN}."
}

if [[ "$MODE" == "report" ]]; then
    echo "Records needed for ${TARGET_DOMAIN} (this server: ${PRIMARY_IPV4:-no IPv4} / ${PRIMARY_IPV6:-no IPv6}):"
    print_records
    exit 0
fi

# --- --setup ---
if ! have_transip_creds "$TARGET_DOMAIN"; then
    err "No TransIP credentials for ${TARGET_DOMAIN} (no accounts.d/*.ini lists it in dns_transip_domains) - add these records by hand at your registrar:"
    print_records
    exit 1
fi

require_cmd transip-dns
TD_USER="$(transip_user_for "$TARGET_DOMAIN")"
TD_KEY_FILE="$(transip_key_for "$TARGET_DOMAIN")"

# One read of the whole zone, reused by every upsert_record call below -
# never re-queried per record, and never assumed empty. A domain being
# cut over from an old server already has every one of these records,
# just pointing elsewhere - this is NOT only a "brand-new domain,
# nothing exists" tool.
EXISTING="$(transip-dns --username "$TD_USER" --key-file "$TD_KEY_FILE" list "$TARGET_DOMAIN" 2>/dev/null)"

# upsert_record <name> <type> <content>: adds a fresh record if none
# exists yet for this name+type, or updates the existing one's content
# in place - reusing ITS OWN live TTL, never a fixed default, since
# transip-dns update requires the exact current TTL to match (confirmed
# via `transip-dns update --help`). Skips entirely if the existing
# content already matches (idempotent, safe to re-run).
#
# REAL BUG FOUND 2026-11-16: a blind `add` with a fixed TTL of 86400
# failed outright against a real domain's existing @ A record (TTL
# 300, pointing at the OLD server) - "the expire of all records in an
# rrset must be all the same". Same root cause already seen in
# update-dane-tlsa.sh. This is the fix: check first, update (same TTL)
# instead of add whenever a record is already there.
upsert_record() {
    local name="$1" rtype="$2" content="$3"
    local existing_line existing_ttl existing_content
    existing_line="$(awk -F'\t' -v n="$name" -v t="$rtype" '$1==n && $3==t {print; exit}' <<< "$EXISTING")"
    if [[ -z "$existing_line" ]]; then
        transip-dns --username "$TD_USER" --key-file "$TD_KEY_FILE" add "$TARGET_DOMAIN" "$name" "$rtype" "$content" --ttl 86400
        log "[ OK ] ${name}.${TARGET_DOMAIN} ${rtype} added -> ${content}"
        return
    fi
    existing_ttl="$(awk -F'\t' '{print $2}' <<< "$existing_line")"
    existing_content="$(cut -f4- -d$'\t' <<< "$existing_line")"
    if [[ "$existing_content" == "$content" ]]; then
        log "[ OK ] ${name}.${TARGET_DOMAIN} ${rtype} already correct - nothing to do."
        return
    fi
    log "Updating ${name}.${TARGET_DOMAIN} ${rtype}: '${existing_content}' -> '${content}' (keeping its own TTL ${existing_ttl})"
    transip-dns --username "$TD_USER" --key-file "$TD_KEY_FILE" update "$TARGET_DOMAIN" "$name" "$rtype" "$content" --ttl "$existing_ttl"
    log "[ OK ] ${name}.${TARGET_DOMAIN} ${rtype} updated -> ${content}"
}

[[ -n "$PRIMARY_IPV4" ]] && upsert_record "@" A "$PRIMARY_IPV4"
[[ -n "$PRIMARY_IPV6" ]] && upsert_record "@" AAAA "$PRIMARY_IPV6"
[[ -n "$PRIMARY_IPV4" ]] && upsert_record "mail" A "$PRIMARY_IPV4"
[[ -n "$PRIMARY_IPV6" ]] && upsert_record "mail" AAAA "$PRIMARY_IPV6"
upsert_record "autodiscover" CNAME "mail.${TARGET_DOMAIN}."

log "[ OK ] Done. Re-run check-cert-readiness.sh -domain ${TARGET_DOMAIN} once this has propagated to confirm."
log "Note: this script only touches @/mail/autodiscover (A/AAAA/CNAME). It does NOT touch MX, SPF/TXT, or www - those need their own separate, deliberate review (a cut-over domain's existing SPF record, for example, can still explicitly authorize the OLD server's IP)."
