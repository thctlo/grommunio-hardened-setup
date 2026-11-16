#!/usr/bin/env bash
#
# update-dane-tlsa.sh
#
# Keeps the DANE TLSA record for every domain in DANE_DOMAINS below in
# sync with the shared certificate's current public key (usage 3 /
# DANE-EE, selector 1 / SPKI, matching-type 1 / SHA-256). Meant to be run
# as a certbot renewal-hooks/deploy script (installed by manage-dane.sh
# into /etc/letsencrypt/renewal-hooks/deploy/ on testvps), so it fires
# automatically after every renewal of the shared certificate - but it is
# also safe to run by hand any time to check/fix drift.
#
# Each domain gets its own isolated MX hostname (<label>.<domain>) and
# its own TLSA record at _25._tcp.<label>.<domain> - never on a shared
# mail.<domain> hostname, which would force DANE onto every OTHER domain
# sharing that same MX target too (see dns-records-reference.md).
#
#   - "mx1" for whichever domain's mail.<domain> happens to equal this
#     server's own canonical hostname (found via PTR by step 10, used by
#     Postfix as myhostname/HELO) - that name is already the server's
#     shared identity, not exclusive to that domain, so DANE for it needs
#     a distinct, otherwise-unused MX hostname instead (see
#     dns-records-reference.md and 31-grommunio-domain.sh's
#     hint_dedicated_mx_if_needed, which detects this automatically per
#     domain - it is usually, but not necessarily, the first domain this
#     server was ever installed with; decided by the PTR/A record, not by
#     creation order).
#   - "mail" for every other domain (decided 2026-11-04): a plain
#     mail.<domain> works exactly the same way and reads more naturally
#     - it only needs the "mx1" workaround for the one domain, if any,
#       that collides with the shared identity.
#
# Add a new "domain:label" pair here once manage-dane.sh (or the manual
# equivalent) has set up that domain's own A/AAAA, cert SAN, MX record
# and initial TLSA value - this script only ever keeps an EXISTING TLSA
# record in sync with the certificate's current key, it does not create
# the rest of a domain's DANE setup from scratch.
DANE_DOMAINS=(
    "example.com:mx1"
    "example.net:mail"
)
#
# The certificate's key is set to reuse_key=True by manage-certs.sh, so in
# the common case this script finds nothing to do - the hash does not
# change across a renewal unless the key itself is ever regenerated for
# some other reason. It still runs every renewal as a safety net, not
# relying on reuse_key alone.
#
# Uses the same transip-dns CLI (python3-transip-rest) already proven live
# for the mx1.<first domain> A/AAAA records and an MX change. The right
# TransIP account for EACH domain is resolved separately (transip_account_for()
# below) via that account's own dns_transip_domains hint in
# accounts.d/*.ini - not a single fixed account1.ini/.key for every
# domain (directory mode, not the legacy single-file transip.ini/
# transip.key, which this script used before 2026-11-04; that pair was
# an old, no-longer-used leftover and has since been deleted, confirmed
# on purpose, not a bug to work around here). Requires TransIP DNS
# credentials to already be set up (see manage-dane.sh, which this
# assumes has already run once for every domain in DANE_DOMAINS).
#
# Unlike every other DNS-related tool in this project, this one has NO
# manual-fallback path and hard-requires transip-dns - it dies outright
# if that's missing. Deliberate: this runs unattended as a certbot
# renewal deploy-hook, where printing instructions for a human to act on
# would be pointless. On a registrar other than TransIP, this specific
# piece of automation (auto-republishing DANE on every renewal) needs an
# equivalent hook written against that registrar's own API/CLI instead -
# every other script in this project (check-dns.sh, manage-certs.sh,
# manage-dkim.sh, manage-mta-sts.sh, and manage-dane.sh's own --status)
# still works unchanged regardless of registrar.
#
# On a real change, UPDATE the existing record in place (same name/type,
# its own live TTL, only the content changes) rather than add-then-delete -
# transip-dns update is a single atomic content swap, so there is never a
# moment with zero valid TLSA records published, same goal the old
# add-then-delete approach had, but without its own real failure mode:
#
# REAL BUG FOUND 2026-11-16 (three separate live renewals, confirmed by
# the same error every time): add-then-delete's own ADD step used a fixed
# TTL ($TTL below, 3600s) - TransIP's API rejects adding a record into an
# rrset that already has an entry at a DIFFERENT TTL ("the expire of all
# records in an rrset must be all the same"), so the add failed outright
# before the delete was ever reached, every single time this fired after
# a key rotation. update does not have this problem: it requires (and
# reuses) the EXISTING record's own live TTL, confirmed via
# `transip-dns update --help`, so there's nothing to mismatch - this is
# also the same proven-working pattern already used by manage-dane.sh's
# own cmd_setup and bootstrap-domain-dns.sh's upsert_record().
#
# Usage: update-dane-tlsa.sh [cert_dir]
#   cert_dir defaults to /etc/letsencrypt/live/mail.example.com (the live
#   symlink, always current) - certbot's own deploy-hook mechanism sets
#   $RENEWED_LINEAGE to the same thing, passed through if set.

set -euo pipefail

CERT_DIR="${1:-${RENEWED_LINEAGE:-/etc/letsencrypt/live/mail.example.com}}"
CERT_FILE="${CERT_DIR}/cert.pem"
TTL=3600

ACCOUNTS_DIR="/etc/letsencrypt/transip/accounts.d"

log() { echo "[update-dane-tlsa] $*"; }
die() { echo "[update-dane-tlsa] ERROR: $*" >&2; exit 1; }

# transip_account_for <domain>: prints the accounts.d/*.ini path whose
# own dns_transip_domains (comma-separated) lists this domain, or
# nothing + returns 1 if no account hints it. Same per-domain
# resolution as functions/00-common.sh's own transip_account_for()
# (used by manage-dane.sh/manage-dkim.sh/manage-mta-sts.sh) -
# deliberately duplicated here, not sourced, so this unattended
# certbot deploy-hook keeps zero dependency on files outside its own
# deployed copy (same robustness principle as the header's own "no
# manual-fallback path" design note).
#
# REAL BUG FOUND 2026-11-15: this script hardcoded account1.ini/.key
# for EVERY domain in DANE_DOMAINS, no matter which TransIP account
# actually owns it - worked only because exactly one account existed.
# Flagged live by the operator right after the same hardcoding was fixed in
# manage-dane.sh, which this script was missed by at the time since it
# runs standalone, not through functions/00-common.sh.
transip_account_for()
{
    local domain="$1" ini_file domains_line d
    [[ -d "$ACCOUNTS_DIR" ]] || return 1
    for ini_file in "$ACCOUNTS_DIR"/*.ini; do
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

[[ -f "$CERT_FILE" ]] || die "Certificate not found: $CERT_FILE"
command -v transip-dns >/dev/null || die "transip-dns not found (python3-transip-rest not installed?)."

NEW_HASH="$(openssl x509 -in "$CERT_FILE" -noout -pubkey \
    | openssl pkey -pubin -outform DER \
    | openssl dgst -sha256 -hex \
    | sed 's/^.*= //')"
[[ "${#NEW_HASH}" -eq 64 ]] || die "Computed hash is not 64 hex chars (got '${NEW_HASH}') - refusing to publish."
NEW_RRDATA="3 1 1 ${NEW_HASH}"

# One certificate, one key, so every domain below gets the exact same
# new TLSA rrdata - computed once, then applied per domain:label pair.
FAILED=0
for entry in "${DANE_DOMAINS[@]}"; do
    DOMAIN="${entry%%:*}"
    LABEL="${entry##*:}"
    RECORD_NAME="_25._tcp.${LABEL}"

    INI_FILE="$(transip_account_for "$DOMAIN")" \
        || { log "[ERROR] No TransIP account found for ${DOMAIN} (no accounts.d/*.ini lists it in dns_transip_domains) - skipping."; FAILED=1; continue; }
    TRANSIP_USER="$(grep '^dns_transip_username' "$INI_FILE" | sed 's/.*= *//')"
    KEY_FILE="$(grep '^dns_transip_key_file' "$INI_FILE" | sed 's/.*= *//')"
    if [[ -z "$TRANSIP_USER" || -z "$KEY_FILE" || ! -f "$KEY_FILE" ]]; then
        log "[ERROR] Incomplete TransIP credentials in ${INI_FILE} for ${DOMAIN} - skipping."
        FAILED=1
        continue
    fi

    CURRENT_LINE="$(transip-dns --username "$TRANSIP_USER" --key-file "$KEY_FILE" list "$DOMAIN" 2>/dev/null \
        | awk -v n="$RECORD_NAME" '$1==n && $3=="TLSA"')"
    CURRENT_RRDATA="$(echo "$CURRENT_LINE" | sed -E 's/^\S+\s+\S+\s+\S+\s+//')"
    CURRENT_TTL="$(echo "$CURRENT_LINE" | awk '{print $2}')"

    if [[ -n "$CURRENT_RRDATA" && "$CURRENT_RRDATA" == "$NEW_RRDATA" ]]; then
        log "[ OK ] TLSA for ${RECORD_NAME}.${DOMAIN} already matches the current certificate - nothing to do."
        continue
    fi

    if [[ -n "$CURRENT_RRDATA" ]]; then
        log "Updating TLSA for ${RECORD_NAME}.${DOMAIN}: ${CURRENT_RRDATA} -> ${NEW_RRDATA} (keeping its own TTL ${CURRENT_TTL})"
        if ! transip-dns --username "$TRANSIP_USER" --key-file "$KEY_FILE" \
            update "$DOMAIN" "$RECORD_NAME" TLSA "$NEW_RRDATA" --ttl "$CURRENT_TTL"; then
            log "[ERROR] Could not update the TLSA record for ${RECORD_NAME}.${DOMAIN} - the old value was left in place untouched."
            FAILED=1
            continue
        fi
        log "[ OK ] TLSA record updated for ${RECORD_NAME}.${DOMAIN}."
    else
        log "Publishing new TLSA rrdata for ${RECORD_NAME}.${DOMAIN}: ${NEW_RRDATA}"
        if ! transip-dns --username "$TRANSIP_USER" --key-file "$KEY_FILE" \
            add "$DOMAIN" "$RECORD_NAME" TLSA "$NEW_RRDATA" --ttl "$TTL"; then
            log "[ERROR] Could not add the new TLSA record for ${RECORD_NAME}.${DOMAIN}."
            FAILED=1
            continue
        fi
        log "[ OK ] New TLSA record added for ${RECORD_NAME}.${DOMAIN}."
    fi
done

(( FAILED == 0 )) || die "One or more domains failed to update - see [ERROR] lines above."
log "[ OK ] Done."
