#!/usr/bin/env bash
#
# manage-dane.sh
#
# Standalone, optional setup for DANE (TLSA), for any domain hosted here -
# not just the first one (generalized 2026-11-05, was first-domain-only
# since 2026-10-30). DANE is keyed on the MX target hostname, so a shared
# mail.<domain> MX would force DANE onto every OTHER domain sharing it -
# every domain therefore gets its own isolated MX hostname before DANE is
# set up on it: "mx1.<domain>" for whichever domain is
# functions/00-common.sh's first_active_domain(), "mail.<domain>" for
# every domain after that (it already has its own mail.<domain> A/AAAA
# from its normal setup - nothing new to create there, unlike mx1). See
# dns-records-reference.md for the full reasoning.
#
# Using a DNS registrar other than TransIP: what still works, and what
# doesn't, varies per tool in this project -
#   - check-dns.sh and the other manage-*.sh scripts (manage-certs.sh,
#     manage-dkim.sh, manage-mta-sts.sh) are fully registrar-agnostic:
#     they only ever READ DNS (resolvectl/dig) and print what to add by
#     hand. They work the same regardless of registrar.
#   - THIS script (manage-dane.sh --setup) is the one place that can
#     actually WRITE DNS records, and only because the TransIP registrar
#     API happens to be available here (python3-transip-rest, set up for
#     the certbot-dns-transip plugin). On a different registrar, it still
#     runs, checks for TransIP credentials (have_transip_creds), and when
#     they're missing, falls back cleanly: it does NOT crash, it prints
#     the exact record you need to add by hand (including the computed
#     DANE hash where relevant) and exits non-zero. --status always
#     works everywhere - it never attempts to write anything.
#   - update-dane-tlsa.sh (the certbot renewal deploy-hook that
#     re-publishes DANE automatically on every cert renewal) has NO such
#     fallback - it hard-requires transip-dns and dies without it. That
#     is deliberate: it runs unattended during renewal, where printing
#     manual instructions for nobody to read is pointless. On another
#     registrar, that one piece of automation (auto-republish on
#     renewal) needs an equivalent hook written against that registrar's
#     own API/CLI - everything else above still works as described.
#
# Requires, before --setup can do anything:
#   - functions/00-common.sh's first_active_domain() must resolve to a
#     real domain (i.e. step 31 has run at least once).
#   - For the first domain specifically: manage-certs.sh --all must
#     already have added mx1.<first domain> to the certificate (which
#     itself requires the mx1 A/AAAA record to already resolve here -
#     see the chicken-and-egg note in --setup). Every other domain
#     already has its own mail.<domain> on the certificate from its
#     normal setup.
#   - TransIP credentials for this domain, in one of
#     /etc/letsencrypt/transip/accounts.d/*.ini (matched per domain via
#     that account's own dns_transip_domains - see
#     docs/certbot-dns-transip-setup, or project-certbot-dns-transip memory).
#
# Usage:
#   manage-dane.sh [-domain <name>]              Show this help (no
#                                                  arguments = help).
#   manage-dane.sh [-domain <name>] --status     Report what's done/missing
#                                                  - DNS, cert SAN,
#                                                  reuse_key, TLSA record,
#                                                  deploy-hook entry. Never
#                                                  changes anything.
#   manage-dane.sh [-domain <name>] --setup      Do whatever --status found
#                                                  missing, where possible
#                                                  (TransIP only), and adds
#                                                  <name> to
#                                                  update-dane-tlsa.sh's own
#                                                  DANE_DOMAINS list so a
#                                                  future key rotation keeps
#                                                  it in sync too.
#   manage-dane.sh [-domain <name>] --report     Not a check - prints just
#                                                  this domain's own TLSA
#                                                  record (name/type/value),
#                                                  copy-paste-ready for a
#                                                  registrar that needs it
#                                                  added by hand.
#   --brief                                       Modifier for --status/
#                                                  --report/--setup: only
#                                                  [FAIL]/[WARN] lines and a
#                                                  one-line summary, no
#                                                  [ OK ] lines.
#   --mail [<address>]                            Modifier for --status/
#                                                  --report/--setup: also
#                                                  emails the exact output
#                                                  via this server's own
#                                                  MTA. Default recipient
#                                                  (no address given):
#                                                  admin@<first active
#                                                  domain> - the hub
#                                                  mailbox step 31 creates.
#
# --setup writes real DNS zone records (via transip-dns). The operator
# runs this command themselves - an agent must never run --setup (this is
# a standing, absolute rule for every DNS zone-record change in this
# project, not specific to this script). The classifier that gates DNS/cert
# changes at the tool layer may also prompt separately if an agent ever
# attempts it regardless - that is a second, redundant backstop, not the
# actual reason this is off-limits. An agent may run --status freely
# (read-only) and should hand the operator the exact --setup command to
# run themselves.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/functions/00-common.sh"

# TransIP account helpers (transip_account_for/have_transip_creds/
# transip_user_for/transip_key_for/transip_live_ttl_for) now live in
# functions/00-common.sh - shared with manage-dkim.sh's --setup, which
# needed the exact same per-domain account resolution.
DANE_TLSA_SCRIPT="${SCRIPT_DIR}/update-dane-tlsa.sh"

# discover_cert_name() (functions/00-common.sh) - NOT a hardcoded
# NEW_FQDN guess. Found live 2026-11-15: this used to hardcode
# CERT_NAME="${NEW_FQDN:-mail.example.com}", checking the WRONG
# renewal.conf/cert.pem the moment a dedicated mx-hostname exists (the
# real cert lives under mx1.<domain>, not mail.<domain>) - explained a
# real, confusing symptom: --setup reported "reuse_key is not set" and
# "TLSA record already published" using a stale/orphaned certificate's
# data, right after manage-certs.sh had just confirmed setting
# reuse_key on the REAL certificate two lines above in the same run.
CERT_NAME="$(discover_cert_name)"
DEPLOY_HOOK="/etc/letsencrypt/renewal-hooks/deploy/75-update-dane-tlsa"
TTL=3600

show_help()
{
    sed -n '3,98p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# dane_label_for() now lives in functions/00-common.sh - shared with
# manage-mta-sts.sh, which needs the exact same per-domain MX hostname.

# expected_tlsa_for: "3 1 1 <hash>" computed from the CURRENT
# certificate's public key - the value a correct TLSA record should
# have right now. Prints nothing if the certificate doesn't exist (or
# the key isn't 64 hex chars after hashing) - callers must check for
# that, never publish/compare against an empty expected value.
expected_tlsa_for()
{
    local hash
    [[ -f "/etc/letsencrypt/live/${CERT_NAME}/cert.pem" ]] || return 0
    hash="$(openssl x509 -in "/etc/letsencrypt/live/${CERT_NAME}/cert.pem" -noout -pubkey 2>/dev/null \
        | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -hex 2>/dev/null | sed 's/^.*= //')"
    [[ "${#hash}" -eq 64 ]] || return 0
    echo "3 1 1 ${hash}"
}

# expected_tlsa_ta_for: "2 1 1 <hash>" (DANE-TA) computed from the
# CURRENT certificate chain's own issuing intermediate CA certificate
# - the 2nd PEM block in fullchain.pem, not the leaf (1st block).
# Published alongside expected_tlsa_for()'s own "3 1 1" record at the
# SAME name, giving a rollover scheme ("Current + Issuer CA") per the
# Internet.nl DANE test's own recommendation: even if the leaf key
# changes, this entry stays valid as long as Let's Encrypt keeps using
# the same intermediate - which changes far less often than our own
# key does. Prints nothing if fullchain.pem is missing, there is no
# 2nd certificate in it, or the hash isn't 64 hex chars - callers must
# check for that, same contract as expected_tlsa_for().
expected_tlsa_ta_for()
{
    local hash
    [[ -f "/etc/letsencrypt/live/${CERT_NAME}/fullchain.pem" ]] || return 0
    hash="$(awk -v n=2 '/-----BEGIN CERTIFICATE-----/{c++} c==n{print} /-----END CERTIFICATE-----/{if(c==n) exit}' \
        "/etc/letsencrypt/live/${CERT_NAME}/fullchain.pem" \
        | openssl x509 -noout -pubkey 2>/dev/null \
        | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -hex 2>/dev/null | sed 's/^.*= //')"
    [[ "${#hash}" -eq 64 ]] || return 0
    echo "2 1 1 ${hash}"
}

# ============================================================
# cmd_status: report-only, never changes anything.
# ============================================================

cmd_status()
{
    require_cmd openssl
    require_cmd resolvectl

    local domain="$1" label target
    [[ -n "$domain" ]] || die "No active domain found (grommunio-admin domain list) - run step 31 first."
    label="$(dane_label_for "$domain")"
    target="${label}.${domain}"

    local failed=0

    echo
    echo "=== DANE status for ${target} (domain: ${domain}, label: ${label}) ==="
    [[ "$BRIEF" -eq 1 ]] || echo

    if have_transip_creds "$domain"; then
        okline "TransIP DNS credentials found for ${domain} - --setup can write DNS records."
    else
        warnline "No TransIP DNS credentials found for ${domain} (no accounts.d/*.ini lists it in"
        echo "       dns_transip_domains) - --setup can only report, every missing DNS record"
        echo "       below must be added by hand at your registrar."
    fi

    # Every resolvectl query below is guarded with `if ! out=...` before
    # piping its output anywhere - resolvectl exits non-zero when
    # nothing is found (same as every such query throughout this
    # project), and this script runs under `set -o pipefail`: an
    # unguarded pipeline would silently kill the whole script the
    # moment a brand new domain (the main case --status is for) simply
    # does not have a record yet. Found and fixed 2026-11-05 while
    # generalizing this script beyond the one domain that already had
    # everything set up, where this had never been exercised before.
    local out v4 v6
    v4="" v6=""
    if out="$(resolvectl query --type=A "$target" 2>/dev/null)"; then
        v4="$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' <<< "$out" | head -1 || true)"
    fi
    if out="$(resolvectl query --type=AAAA "$target" 2>/dev/null)"; then
        v6="$(grep -oE '[0-9a-fA-F:]+:[0-9a-fA-F:]+' <<< "$out" | head -1 || true)"
    fi
    if [[ -n "$v4" || -n "$v6" ]]; then
        okline "${target} resolves (A: ${v4:-<none>}, AAAA: ${v6:-<none>})."
    else
        failline "${target} does not resolve at all - needs an A/AAAA record first."
        failed=$((failed + 1))
    fi

    local cert_sans
    cert_sans="$(openssl x509 -in /etc/letsencrypt/live/${CERT_NAME}/cert.pem -noout -ext subjectAltName 2>/dev/null)"
    if echo "$cert_sans" | grep -qF "$target"; then
        okline "${target} is covered by the certificate."
    else
        failline "${target} is NOT yet in the certificate - run manage-certs.sh --all (needs the A/AAAA record above to exist first)."
        failed=$((failed + 1))
    fi

    local renewal_conf="/etc/letsencrypt/renewal/${CERT_NAME}.conf"
    if [[ -f "$renewal_conf" ]] && grep -q '^reuse_key = True$' "$renewal_conf"; then
        okline "reuse_key is set (TLSA value will stay stable across renewals)."
    else
        failline "reuse_key is not set - run manage-certs.sh --all."
        failed=$((failed + 1))
    fi

    # Two TLSA records now coexist at the same name (DANE-EE "3 1 1"
    # for the leaf key, DANE-TA "2 1 1" for the issuing intermediate -
    # the "Current + Issuer CA" rollover scheme). Each lookup below
    # filters by its own usage-type digit (leading "3 " or "2 ") so
    # the two checks never pick up each other's value.
    local out_tlsa_all
    out_tlsa_all=""
    if out="$(resolvectl query --type=TLSA "_25._tcp.${target}" 2>/dev/null)"; then
        out_tlsa_all="$(grep -oE '[0-9]+ [0-9]+ [0-9]+ [0-9a-fA-F]+' <<< "$out" || true)"
    fi

    local tlsa_live="" want_tlsa=""
    tlsa_live="$(grep -E '^3 ' <<< "$out_tlsa_all" | head -1 || true)"
    want_tlsa="$(expected_tlsa_for)"
    # REAL BUG FOUND 2026-11-15: this used to only check whether ANY TLSA
    # record existed at this name - never whether its VALUE still matches
    # the current certificate's key. Confirmed live: a record published
    # against an earlier key (before reuse_key took effect) was reported
    # "[ OK ] ... already published" every run since, even though it no
    # longer matched the live certificate at all - the exact kind of
    # silent drift DANE is supposed to prevent, not cause.
    if [[ -z "$tlsa_live" ]]; then
        failline "No DANE-EE (3 1 1) TLSA record published yet at _25._tcp.${target}."
        failed=$((failed + 1))
    elif [[ -n "$want_tlsa" && "${tlsa_live,,}" != "${want_tlsa,,}" ]]; then
        failline "DANE-EE TLSA record is stale: published \"${tlsa_live}\", current certificate needs \"${want_tlsa}\" - run --setup to update it."
        if [[ "$BRIEF" -ne 1 ]]; then
            echo "       If --setup already ran: this can just be the record's own TTL not having"
            echo "       expired yet in a resolver's cache (including this server's own) - compare"
            echo "       against \`transip-dns list ${domain}\` (bypasses caching) before assuming"
            echo "       --setup didn't work."
        fi
        failed=$((failed + 1))
    else
        okline "DANE-EE (3 1 1) TLSA record published and matches the current certificate: ${tlsa_live}"
    fi

    local tlsa_ta_live="" want_tlsa_ta=""
    tlsa_ta_live="$(grep -E '^2 ' <<< "$out_tlsa_all" | head -1 || true)"
    want_tlsa_ta="$(expected_tlsa_ta_for)"
    if [[ -z "$tlsa_ta_live" ]]; then
        failline "No DANE-TA (2 1 1, issuer CA / rollover scheme) TLSA record published yet at _25._tcp.${target}."
        failed=$((failed + 1))
    elif [[ -n "$want_tlsa_ta" && "${tlsa_ta_live,,}" != "${want_tlsa_ta,,}" ]]; then
        failline "DANE-TA TLSA record is stale: published \"${tlsa_ta_live}\", current intermediate CA needs \"${want_tlsa_ta}\" - run --setup to update it."
        failed=$((failed + 1))
    else
        okline "DANE-TA (2 1 1) TLSA record published and matches the current issuing CA: ${tlsa_ta_live}"
    fi

    if grep -qF "\"${domain}:${label}\"" "$DANE_TLSA_SCRIPT" 2>/dev/null; then
        okline "${domain} is in update-dane-tlsa.sh's DANE_DOMAINS (kept in sync on key rotation)."
    else
        failline "${domain} is NOT in update-dane-tlsa.sh's DANE_DOMAINS yet - run --setup, or add \"${domain}:${label}\" by hand."
        failed=$((failed + 1))
    fi

    if [[ -x "$DEPLOY_HOOK" ]]; then
        okline "Deploy-hook installed: $DEPLOY_HOOK"
    else
        failline "Deploy-hook not installed - TLSA will not auto-update on renewal."
        failed=$((failed + 1))
    fi
    [[ "$BRIEF" -eq 1 ]] || echo
    if [[ "$failed" -eq 0 ]]; then
        echo "SUMMARY: ${target} - all OK."
    else
        echo "SUMMARY: ${target} - ${failed} issue(s) found."
    fi
}

# ============================================================
# cmd_setup: do what --status found missing, TransIP-only for the DNS
# writes. Each live DNS write is its own explicit, confirmable action -
# this script does not try to bundle them into one silent pass.
# ============================================================

cmd_setup()
{
    require_cmd openssl
    require_cmd resolvectl

    local domain="$1" label target
    [[ -n "$domain" ]] || die "No active domain found (grommunio-admin domain list) - run step 31 first."
    label="$(dane_label_for "$domain")"
    target="${label}.${domain}"

    local target_resolves=0
    if resolvectl query "$target" >/dev/null 2>&1; then
        target_resolves=1
    fi

    if [[ "$target_resolves" -eq 0 ]]; then
        if [[ "$label" != "mx1" ]]; then
            # A non-first domain's own mail.<domain> is created during
            # its normal domain setup, long before this script ever
            # runs - if it is missing, that setup is incomplete, and
            # guessing an IP to copy here would paper over a real
            # problem rather than fix it.
            die "${target} does not resolve, and this is not the first domain (label: ${label}) - its own mail.${domain} A/AAAA should already exist from its normal domain setup. Fix that first, then re-run."
        fi
        if have_transip_creds "$domain"; then
            log "Creating ${target} A/AAAA records via transip-dns..."
            require_cmd transip-dns
            local user key_file ipv4 ipv6 out
            user="$(transip_user_for "$domain")"
            key_file="$(transip_key_for "$domain")"
            ipv4="" ipv6=""
            if out="$(resolvectl query --type=A "mail.${domain}" 2>/dev/null)"; then
                ipv4="$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' <<< "$out" | head -1 || true)"
            fi
            if out="$(resolvectl query --type=AAAA "mail.${domain}" 2>/dev/null)"; then
                ipv6="$(grep -oE '[0-9a-fA-F:]+:[0-9a-fA-F:]+' <<< "$out" | head -1 || true)"
            fi
            [[ -n "$ipv4" ]] && transip-dns --username "$user" --key-file "$key_file" add "$domain" "$label" A "$ipv4" --ttl 86400
            [[ -n "$ipv6" ]] && transip-dns --username "$user" --key-file "$key_file" add "$domain" "$label" AAAA "$ipv6" --ttl 86400
            log "[ OK ] ${target} A/AAAA created - may take a moment to propagate before the certificate step below can use it."
        else
            err "${target} does not resolve, and no TransIP credentials are available to create it."
            err "Add this by hand at your registrar, matching mail.${domain}'s own A/AAAA:"
            err "  ${target}  A     <same IPv4 as mail.${domain}>"
            err "  ${target}  AAAA  <same IPv6 as mail.${domain}>"
            return 1
        fi
    else
        log "[ OK ] ${target} already resolves."
    fi

    log "Ensuring the certificate covers ${target} and reuse_key is set..."
    "${SCRIPT_DIR}/manage-certs.sh" --all

    # publish_tlsa_entry <usage_prefix> <description> <want_value>:
    # shared add/update/skip logic for ONE TLSA usage-type at
    # _25._tcp.<label>.<domain> - called once for DANE-EE ("3 1 1",
    # the leaf key, existing behaviour) and once for DANE-TA
    # ("2 1 1", the issuing intermediate CA) - the "Current + Issuer
    # CA" rollover scheme the Internet.nl DANE test recommends. Both
    # entries share the same name+type (TLSA), so TransIP requires
    # them to share one TTL too (confirmed via its own 406 error
    # wording) - transip_live_ttl_for's plain name+type match is
    # therefore always correct here, regardless of which usage-type
    # entry it happens to find first.
    publish_tlsa_entry()
    {
        local usage_prefix="$1" description="$2" want_value="$3"
        local live="" out all_lines=""
        if out="$(resolvectl query --type=TLSA "_25._tcp.${target}" 2>/dev/null)"; then
            all_lines="$(grep -oE '[0-9]+ [0-9]+ [0-9]+ [0-9a-fA-F]+' <<< "$out" || true)"
            live="$(grep -E "^${usage_prefix} " <<< "$all_lines" | head -1 || true)"
        fi
        [[ -n "$want_value" ]] || die "Could not compute the expected ${description} value - refusing to publish."

        if [[ -z "$live" ]]; then
            if have_transip_creds "$domain"; then
                log "Computing and publishing the initial ${description} record..."
                require_cmd transip-dns
                local user key_file; user="$(transip_user_for "$domain")"; key_file="$(transip_key_for "$domain")"
                # REAL BUG FOUND 2026-11-16: a SIBLING TLSA entry (the
                # other usage-type) can already exist at this exact
                # name - TransIP requires every record in that rrset to
                # share one TTL, so adding this one with the script's
                # own fixed $TTL default fails outright (406 "the
                # expire of all records in an rrset must be all the
                # same") whenever that sibling's own live TTL differs.
                # Use the sibling's live TTL when one exists, $TTL only
                # when this is truly the first TLSA record at this name.
                local add_ttl="$TTL"
                if [[ -n "$all_lines" ]]; then
                    local sibling_ttl
                    sibling_ttl="$(transip_live_ttl_for "$domain" "_25._tcp.${label}" TLSA)"
                    [[ -n "$sibling_ttl" ]] && add_ttl="$sibling_ttl"
                fi
                # Also found in the same incident: this add's own exit
                # status was never checked, so a failed add (like the
                # TTL-mismatch 406 above) was still reported "[ OK ]
                # Published" - confirmed live by a --status run right
                # after showing the record was never actually there.
                if ! transip-dns --username "$user" --key-file "$key_file" \
                    add "$domain" "_25._tcp.${label}" TLSA "$want_value" --ttl "$add_ttl"; then
                    err "Could not add the new ${description} record for _25._tcp.${target}."
                    return 1
                fi
                log "[ OK ] Published ${description}: ${want_value}"
                log "      TTL is ${add_ttl}s - resolvers (including this server's own cache) may keep"
                log "      answering with no/old data for up to that long. A --status run inside"
                log "      this window can still show [FAIL] even though the record is correct."
            else
                err "No ${description} record exists and no TransIP credentials are available to publish one."
                err "Publish as: _25._tcp.${target}  TLSA  ${want_value}"
                return 1
            fi
        elif [[ "${live,,}" != "${want_value,,}" ]]; then
            # REAL BUG FOUND 2026-11-15: this branch didn't exist at all -
            # any existing record, however stale, was reported "already
            # published" and left untouched forever. Using transip-dns
            # update (name/type/ttl must match the live record exactly,
            # only content changes), not add - add would create a SECOND,
            # conflicting TLSA record alongside the stale one instead of
            # replacing it.
            if have_transip_creds "$domain"; then
                log "Published ${description} record is stale (${live}) - updating to match the current certificate..."
                require_cmd transip-dns
                local user key_file live_ttl
                user="$(transip_user_for "$domain")"; key_file="$(transip_key_for "$domain")"
                live_ttl="$(transip_live_ttl_for "$domain" "_25._tcp.${label}" TLSA)"
                [[ -n "$live_ttl" ]] || die "Could not find the live TLSA record's own TTL via transip-dns list - refusing to guess one for update."
                transip-dns --username "$user" --key-file "$key_file" \
                    update "$domain" "_25._tcp.${label}" TLSA "$want_value" --ttl "$live_ttl"
                log "[ OK ] Updated ${description} record: ${live} -> ${want_value}"
                log "      TTL is ${live_ttl}s - resolvers (including this server's own cache) may"
                log "      keep answering with the OLD value for up to that long. A --status run"
                log "      inside this window can still show [FAIL] stale even though TransIP's"
                log "      own answer (transip-dns list ${domain}) is already correct."
            else
                err "Published ${description} record is stale and no TransIP credentials are available to update it."
                err "Current:   _25._tcp.${target}  TLSA  ${live}"
                err "Should be: _25._tcp.${target}  TLSA  ${want_value}"
                return 1
            fi
        else
            [[ "$BRIEF" -eq 1 ]] || log "[ OK ] ${description} record already published and matches the current certificate: ${live}"
        fi
        return 0
    }

    publish_tlsa_entry "3" "DANE-EE (3 1 1)" "$(expected_tlsa_for)" || return 1
    publish_tlsa_entry "2" "DANE-TA (2 1 1, issuer CA)" "$(expected_tlsa_ta_for)" || return 1

    if grep -qF "\"${domain}:${label}\"" "$DANE_TLSA_SCRIPT" 2>/dev/null; then
        [[ "$BRIEF" -eq 1 ]] || log "[ OK ] ${domain} already in update-dane-tlsa.sh's DANE_DOMAINS."
    else
        log "Adding ${domain}:${label} to update-dane-tlsa.sh's DANE_DOMAINS..."
        backup_file "$DANE_TLSA_SCRIPT"
        sed -i "/^DANE_DOMAINS=($/,/^)$/{ /^)$/i\\    \"${domain}:${label}\"
}" "$DANE_TLSA_SCRIPT"
        grep -qF "\"${domain}:${label}\"" "$DANE_TLSA_SCRIPT" \
            || die "Could not add ${domain}:${label} to $DANE_TLSA_SCRIPT - add it by hand."
        bash -n "$DANE_TLSA_SCRIPT" || die "$DANE_TLSA_SCRIPT has a syntax error after editing - check it by hand."
        finalize_backup "$DANE_TLSA_SCRIPT"
        log "[ OK ] Added. Remember to also update the deployed copy if this script lives elsewhere too."
    fi

    if [[ ! -x "$DEPLOY_HOOK" ]]; then
        log "Installing the renewal deploy-hook..."
        install -m 0755 "$DANE_TLSA_SCRIPT" "$DEPLOY_HOOK"
        log "[ OK ] Installed $DEPLOY_HOOK."
    else
        log "Refreshing the renewal deploy-hook (DANE_DOMAINS may have just changed)..."
        install -m 0755 "$DANE_TLSA_SCRIPT" "$DEPLOY_HOOK"
        log "[ OK ] Deploy-hook up to date."
    fi

    echo
    cmd_status "$domain"
}

# ============================================================
# cmd_report: standalone, copy-paste-friendly DNS record block for
# this domain's own TLSA record - not a status check, just "what to
# publish", matching check-dns.sh --report's own spirit but scoped to
# only what THIS script manages (TLSA), not every record a domain
# needs.
# ============================================================

cmd_report()
{
    local domain="$1" label target want_tlsa
    [[ -n "$domain" ]] || die "No active domain found (grommunio-admin domain list) - run step 31 first."
    label="$(dane_label_for "$domain")"
    target="${label}.${domain}"
    want_tlsa="$(expected_tlsa_for)"
    [[ -n "$want_tlsa" ]] || die "Could not compute the expected TLSA value - does /etc/letsencrypt/live/${CERT_NAME}/cert.pem exist yet?"

    echo "DANE/TLSA record for ${target}"
    echo "================================"
    echo
    echo "  Name:  _25._tcp.${target}"
    echo "  Type:  TLSA"
    echo "  Value: ${want_tlsa}"
    echo
    echo "Publish this exact record at your DNS registrar (TTL: your registrar's"
    echo "own short-lived-record default is fine, e.g. 300-3600s)."
    echo "Re-run manage-dane.sh -domain ${domain} --status afterward to confirm it matches."
}

# ============================================================
# Argument parsing
# ============================================================

if [[ $# -eq 0 ]]; then
    show_help
    exit 0
fi

ACTION="" TARGET_DOMAIN="" MAIL_TO=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -domain)
            [[ -n "${2:-}" ]] || die "-domain needs a value."
            TARGET_DOMAIN="$2"; shift 2 ;;
        --status)
            ACTION="status"; shift ;;
        --setup)
            ACTION="setup"; shift ;;
        --report)
            ACTION="report"; shift ;;
        --brief)
            BRIEF=1; shift ;;
        --mail)
            if [[ -n "${2:-}" && "$2" == *"@"* ]]; then
                MAIL_TO="$2"; shift 2
            else
                MAIL_TO="$(default_report_mail_to)"; shift
            fi ;;
        -h|--help)
            show_help; exit 0 ;;
        *)
            echo "manage-dane.sh: unknown option: $1 (see --help)" >&2
            exit 1 ;;
    esac
done

[[ -n "$TARGET_DOMAIN" ]] || TARGET_DOMAIN="$(first_active_domain)"

run_action()
{
    case "$ACTION" in
        status) cmd_status "$TARGET_DOMAIN" ;;
        setup) require_root; cmd_setup "$TARGET_DOMAIN" ;;
        report) cmd_report "$TARGET_DOMAIN" ;;
        "") show_help ;;
    esac
}

if [[ -n "$MAIL_TO" ]]; then
    [[ -n "$ACTION" ]] || die "--mail needs an action (--status, --setup or --report)."
    OUTPUT="$(run_action 2>&1)"
    printf '%s\n' "$OUTPUT"
    send_report_mail "$MAIL_TO" "manage-dane.sh ${ACTION} - ${TARGET_DOMAIN}" "$OUTPUT"
    log "[ OK ] Report mailed to ${MAIL_TO}."
else
    run_action
fi
