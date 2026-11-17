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

# DANE_SCHEME: which of Internet.nl's own two recommended double-TLSA
# rollover schemes to publish - always exactly 2 records total per
# domain, never a combination of both. Must match manage-dane.sh's own
# DANE_SCHEME choice for every domain here (that script is what sets
# up each domain's TLSA record in the first place; this one only
# keeps it in sync on renewal). See manage-dane.sh's own DANE_SCHEME
# comment for the full explanation of "rollover" vs "issuer".
DANE_SCHEME="${DANE_SCHEME:-rollover}"
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
# REDESIGNED 2026-11-17, reconciled via delete(exact old
# content)+add(new content) - never transip-dns update/PATCH any
# more. History of why, in order:
#
# REAL BUG FOUND 2026-11-16 (three separate live renewals, same error
# every time): the original add-then-delete approach's own ADD step
# used a fixed TTL - TransIP rejects adding a record into an rrset
# that already has an entry at a DIFFERENT TTL ("the expire of all
# records in an rrset must be all the same"), so the add failed before
# the delete was ever reached. Switched to `transip-dns update`
# (PATCH), reusing the existing record's own live TTL - no TTL
# mismatch possible there.
#
# REAL BUG FOUND 2026-11-17: PATCH identifies the record to change by
# name+expire+type ONLY (confirmed by rereading transip_rest's own
# update_dns_entry() and the TransIP docs it quotes) - never content.
# That's fine with exactly one record of a usage-type at a name, but
# once the DANE-EE/DANE-TA rollover scheme below means TWO records
# coexist at the same name+ttl, and a real key rotation needs updating
# one of them, TransIP can no longer tell the two apart and correctly
# refuses with 406 "Multiple matches found" - leaving the DNS stale
# (confirmed live: a cert renewal changed the key, the deploy-hook
# logged this error for both DANE-EE and DANE-TA, and the old,
# now-wrong TLSA values stayed published for hours before being caught
# and fixed by hand).
#
# Fixed by switching every TLSA write to delete(exact old
# content)+add(new content) instead - delete's own request includes
# the content being removed, so it is never ambiguous.
#
# ALSO CORRECTED 2026-11-17, same day: the first version of this fix
# additionally tried to publish an independent "N and N-1" rotation
# window for EACH usage-type separately (2x "3 1 1" AND 2x "2 1 1" -
# 4 TLSA records total). That is neither of Internet.nl's own two
# recommended double-TLSA schemes (always exactly 2 records total:
# "3 1 1"+"3 1 1", or "3 1 1"+"2 1 1") - its own guidance explicitly
# warns that other combinations are "more error prone and less
# interoperable". Corrected before ever running against live DNS: see
# DANE_SCHEME below, which now selects exactly ONE of the two
# recommended schemes (never both at once), defaulting to "rollover"
# ("3 1 1" current + "3 1 1" previous - the "previous" value read
# straight from certbot's own archive/ directory, no state tracking
# of its own needed). This still gives the same resilience against an
# unexpected key rotation (e.g. if reuse_key is ever silently dropped
# again) that motivated the original idea, just within one correct,
# 2-record scheme instead of stacking both.
#
# Usage: update-dane-tlsa.sh [cert_dir]
#   cert_dir defaults to /etc/letsencrypt/live/mail.example.com (the live
#   symlink, always current) - certbot's own deploy-hook mechanism sets
#   $RENEWED_LINEAGE to the same thing, passed through if set.

set -euo pipefail

CERT_DIR="${1:-${RENEWED_LINEAGE:-/etc/letsencrypt/live/mail.example.com}}"
CERT_FILE="${CERT_DIR}/cert.pem"
FULLCHAIN_FILE="${CERT_DIR}/fullchain.pem"
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

# ee_hash_from/ta_hash_from <cert_file> <fullchain_file>: print "3 1 1
# <hash>" / "2 1 1 <hash>", or nothing if the file is missing or the
# hash can't be computed (e.g. no 2nd certificate in a fullchain).
ee_hash_from()
{
    local cert_file="$1" hash
    [[ -f "$cert_file" ]] || return 0
    hash="$(openssl x509 -in "$cert_file" -noout -pubkey 2>/dev/null \
        | openssl pkey -pubin -outform DER 2>/dev/null \
        | openssl dgst -sha256 -hex 2>/dev/null \
        | sed 's/^.*= //')"
    [[ "${#hash}" -eq 64 ]] || return 0
    echo "3 1 1 ${hash}"
}
ta_hash_from()
{
    local fullchain_file="$1" hash
    [[ -f "$fullchain_file" ]] || return 0
    hash="$(awk -v n=2 '/-----BEGIN CERTIFICATE-----/{c++} c==n{print} /-----END CERTIFICATE-----/{if(c==n) exit}' "$fullchain_file" \
        | openssl x509 -noout -pubkey 2>/dev/null \
        | openssl pkey -pubin -outform DER 2>/dev/null \
        | openssl dgst -sha256 -hex 2>/dev/null \
        | sed 's/^.*= //')"
    [[ "${#hash}" -eq 64 ]] || return 0
    echo "2 1 1 ${hash}"
}

NEW_RRDATA_EE="$(ee_hash_from "$CERT_FILE")"
[[ -n "$NEW_RRDATA_EE" ]] || die "Could not compute a DANE-EE (3 1 1) value from ${CERT_FILE} - refusing to publish."
NEW_RRDATA_TA="$(ta_hash_from "$FULLCHAIN_FILE")"
if [[ -z "$NEW_RRDATA_TA" ]]; then
    log "[WARN] Could not compute a DANE-TA (2 1 1) value from ${FULLCHAIN_FILE} - only the DANE-EE (3 1 1) record will be kept in sync this run."
fi

# ============================================================
# "N and N-1" TLSA rotation (2026-11-17): find certbot's own PREVIOUS
# certificate generation (the one just superseded by this renewal) via
# its archive/ directory - certbot already keeps every past
# cert/fullchain generation there, so "the previous value" can always
# be computed straight from that, with no separate state tracking of
# our own needed at all. $CERT_FILE/$FULLCHAIN_FILE above are the LIVE
# (current, generation N) symlinks; resolving them gives the archive
# path and generation number, from which generation N-1's own files
# are named exactly the same way, one number lower.
# ============================================================

PREV_RRDATA_EE="" PREV_RRDATA_TA=""
RESOLVED_CERT="$(readlink -f "$CERT_FILE" 2>/dev/null || true)"
if [[ "$RESOLVED_CERT" =~ ^(.*)/cert([0-9]+)\.pem$ ]]; then
    ARCHIVE_DIR="${BASH_REMATCH[1]}"
    CUR_GEN="${BASH_REMATCH[2]}"
    if [[ "$CUR_GEN" -gt 1 ]]; then
        PREV_GEN=$((CUR_GEN - 1))
        PREV_RRDATA_EE="$(ee_hash_from "${ARCHIVE_DIR}/cert${PREV_GEN}.pem")"
        PREV_RRDATA_TA="$(ta_hash_from "${ARCHIVE_DIR}/fullchain${PREV_GEN}.pem")"
    fi
else
    log "[WARN] Could not resolve ${CERT_FILE} to a numbered certbot archive file - no 'previous generation' rotation value available this run."
fi

# publish_tlsa_pair <domain> <record_name> <user> <key_file>
#                    <usage_prefix> <new_rrdata> <prev_rrdata>:
# "N and N-1" rotation reconciliation for ONE TLSA usage-type at
# <record_name>.<domain> - called once per domain for DANE-EE and once
# for DANE-TA. Desired end state is {new_rrdata} alone, or
# {new_rrdata, prev_rrdata} when prev_rrdata is non-empty and actually
# differs from new_rrdata (the common case, thanks to reuse_key, is
# that they're identical - nothing to add there, one record stays
# correct and expected, not a gap). Whatever is currently published
# but no longer in that desired set gets deleted.
#
# REAL BUG FOUND AND FIXED 2026-11-17: the previous version of this
# function used `transip-dns update` (TransIP's PATCH endpoint) to
# change an existing record's content in place. Re-reading
# transip_rest's own update_dns_entry() (and the TransIP API docs it
# quotes) confirmed PATCH identifies the record to change by
# name+expire+type ONLY, never content - fine with exactly one record
# of a given usage-type at a name, but as soon as TWO coexist at the
# same name+ttl (this exact rollover scheme, confirmed live the moment
# a real key rotation needed updating one of them), TransIP can no
# longer tell them apart and correctly refuses with 406 "Multiple
# matches found" - leaving the old, wrong value live. delete's own
# request includes the exact content being removed, so it never has
# this ambiguity; every change here is now delete(exact old content)
# + add(new content), never update/PATCH.
publish_tlsa_pair()
{
    local domain="$1" record_name="$2" user="$3" key_file="$4" usage_prefix="$5" new_rrdata="$6" prev_rrdata="$7"
    [[ -n "$new_rrdata" ]] || return 0

    local -a desired=("$new_rrdata")
    [[ -n "$prev_rrdata" && "$prev_rrdata" != "$new_rrdata" ]] && desired+=("$prev_rrdata")

    local all_lines
    all_lines="$(transip-dns --username "$user" --key-file "$key_file" list "$domain" 2>/dev/null \
        | awk -v n="$record_name" '$1==n && $3=="TLSA"')"

    local -a current_rrdata=() current_ttl=()
    local line
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        current_rrdata+=("$(sed -E 's/^\S+\s+\S+\s+\S+\s+//' <<< "$line")")
        current_ttl+=("$(awk '{print $2}' <<< "$line")")
    done < <(awk -v u="$usage_prefix" '$4==u' <<< "$all_lines")

    # TTL for any add below: reuse whatever TTL ANY existing TLSA
    # record at this name already has (any usage-type - TransIP
    # enforces one shared TTL per name+type rrset), falling back to
    # the script's own default only when this is genuinely the very
    # first TLSA record ever published at this name.
    local add_ttl="$TTL"
    if [[ -n "$all_lines" ]]; then
        local any_ttl
        any_ttl="$(awk '{print $2; exit}' <<< "$all_lines")"
        [[ -n "$any_ttl" ]] && add_ttl="$any_ttl"
    fi

    local rc=0 want have found i

    for want in "${desired[@]}"; do
        found=0
        for have in "${current_rrdata[@]}"; do [[ "$have" == "$want" ]] && { found=1; break; }; done
        [[ "$found" -eq 1 ]] && continue
        log "Publishing TLSA (${usage_prefix} x x) for ${record_name}.${domain}: ${want}"
        if ! transip-dns --username "$user" --key-file "$key_file" \
            add "$domain" "$record_name" TLSA "$want" --ttl "$add_ttl"; then
            log "[ERROR] Could not add TLSA (${usage_prefix} x x) '${want}' for ${record_name}.${domain}."
            rc=1
            continue
        fi
        log "[ OK ] TLSA (${usage_prefix} x x) published for ${record_name}.${domain}: ${want}"
    done

    for ((i = 0; i < ${#current_rrdata[@]}; i++)); do
        have="${current_rrdata[$i]}"
        found=0
        for want in "${desired[@]}"; do [[ "$have" == "$want" ]] && { found=1; break; }; done
        [[ "$found" -eq 1 ]] && continue
        log "Removing superseded TLSA (${usage_prefix} x x) for ${record_name}.${domain}: ${have}"
        if ! transip-dns --username "$user" --key-file "$key_file" \
            delete "$domain" "$record_name" TLSA "$have" --ttl "${current_ttl[$i]}"; then
            log "[ERROR] Could not delete the superseded TLSA (${usage_prefix} x x) record '${have}' for ${record_name}.${domain}."
            rc=1
            continue
        fi
        log "[ OK ] Superseded TLSA (${usage_prefix} x x) removed for ${record_name}.${domain}: ${have}"
    done

    if [[ "$rc" -eq 0 ]]; then
        log "[ OK ] TLSA (${usage_prefix} x x) for ${record_name}.${domain} now matches the desired set exactly."
    fi
    return "$rc"
}

# remove_usage_type <domain> <record_name> <user> <key_file>
# <usage_prefix>: deletes every live TLSA record of this usage-type at
# this name - for cleaning up the OTHER scheme's record(s) left behind
# by a DANE_SCHEME switch (e.g. an existing "2 1 1" DANE-TA entry when
# now running in "rollover" mode, which never publishes one at all).
remove_usage_type()
{
    local domain="$1" record_name="$2" user="$3" key_file="$4" usage_prefix="$5"
    local all_lines
    all_lines="$(transip-dns --username "$user" --key-file "$key_file" list "$domain" 2>/dev/null \
        | awk -v n="$record_name" '$1==n && $3=="TLSA"')"
    local -a live=() ttls=()
    local line
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        live+=("$(sed -E 's/^\S+\s+\S+\s+\S+\s+//' <<< "$line")")
        ttls+=("$(awk '{print $2}' <<< "$line")")
    done < <(awk -v u="$usage_prefix" '$4==u' <<< "$all_lines")
    [[ "${#live[@]}" -gt 0 ]] || return 0
    local i rc=0
    for ((i = 0; i < ${#live[@]}; i++)); do
        if ! transip-dns --username "$user" --key-file "$key_file" \
            delete "$domain" "$record_name" TLSA "${live[$i]}" --ttl "${ttls[$i]}"; then
            log "[ERROR] Could not remove leftover TLSA (${usage_prefix} x x) record '${live[$i]}' from the previous scheme for ${record_name}.${domain}."
            rc=1
            continue
        fi
        log "[ OK ] Removed leftover TLSA (${usage_prefix} x x) record from the previous scheme for ${record_name}.${domain}: ${live[$i]}"
    done
    return "$rc"
}

# One certificate, one key, so every domain below gets the exact same
# new TLSA rrdata - computed once above, then applied per domain:label
# pair.
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

    if [[ "$DANE_SCHEME" == "rollover" ]]; then
        publish_tlsa_pair "$DOMAIN" "$RECORD_NAME" "$TRANSIP_USER" "$KEY_FILE" "3" "$NEW_RRDATA_EE" "$PREV_RRDATA_EE" || FAILED=1
        remove_usage_type "$DOMAIN" "$RECORD_NAME" "$TRANSIP_USER" "$KEY_FILE" "2" || FAILED=1
    else
        publish_tlsa_pair "$DOMAIN" "$RECORD_NAME" "$TRANSIP_USER" "$KEY_FILE" "3" "$NEW_RRDATA_EE" "" || FAILED=1
        publish_tlsa_pair "$DOMAIN" "$RECORD_NAME" "$TRANSIP_USER" "$KEY_FILE" "2" "$NEW_RRDATA_TA" "" || FAILED=1
    fi
done

(( FAILED == 0 )) || die "One or more domains failed to update - see [ERROR] lines above."
log "[ OK ] Done."
