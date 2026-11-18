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
#   manage-dane.sh [-domain <name>] --teardown   Removes DANE entirely for
#                                                  this domain: every live
#                                                  TLSA record at
#                                                  _25._tcp.<label>.<domain>
#                                                  (both usage-types, a
#                                                  clean sweep regardless of
#                                                  scheme) and the domain's
#                                                  own entry from
#                                                  update-dane-tlsa.sh's
#                                                  DANE_DOMAINS, so a future
#                                                  cert renewal stops
#                                                  touching it. Does not
#                                                  remove the deploy-hook
#                                                  itself or anything for
#                                                  OTHER domains.
#   --brief                                       Modifier for --status/
#                                                  --report/--setup: only
#                                                  [FAIL]/[WARN] lines and a
#                                                  one-line summary, no
#                                                  [ OK ] lines.
#   --mail [<address>]                            Modifier for --status/
#                                                  --report/--setup/
#                                                  --teardown: also emails
#                                                  the exact output via this
#                                                  server's own MTA. Default
#                                                  recipient (no address
#                                                  given): admin@<first
#                                                  active domain> - the hub
#                                                  mailbox step 31 creates.
#   -scheme <rollover|issuer>                      Which double-TLSA
#                                                  rollover scheme to use -
#                                                  see DANE_SCHEME's own
#                                                  comment below for the
#                                                  full explanation.
#                                                  Default: rollover.
#
# --setup and --teardown both write real DNS zone records (via
# transip-dns) - the operator runs either themselves, an agent must
# never run either (this is a standing, absolute rule for every DNS
# zone-record change in this project, not specific to this script).
# The classifier that gates DNS/cert changes at the tool layer may
# also prompt separately if an agent ever attempts it regardless -
# that is a second, redundant backstop, not the actual reason this is
# off-limits. An agent may run --status/--report freely (read-only)
# and should hand the operator the exact --setup/--teardown command to
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

# DANE_SCHEME: which of Internet.nl's own two recommended double-TLSA
# rollover schemes to publish - always exactly 2 records total, never
# a combination of both (2026-11-17, corrected after first proposing
# 4 records - see below). Overridable via the environment or -scheme.
#   rollover (default): "3 1 1" (current leaf key) + "3 1 1" (the
#     immediately PRECEDING leaf key, from certbot's own archive/) -
#     Internet.nl's "Current + Next" scheme, reinterpreted as
#     "Current + Previous" since this project has no planned future
#     key to pre-announce (reuse_key=True is meant to keep the key
#     stable indefinitely). Chosen as the default: it protects
#     against ANY leaf-key change, planned or not - directly covering
#     the exact failure mode hit twice live this same day (the
#     reuse_key regression silently generating a new key during a
#     certificate --expand).
#   issuer: "3 1 1" (current leaf key) + "2 1 1" (current issuing
#     intermediate CA) - Internet.nl's "Current + Issuer CA" scheme,
#     this project's original choice. Protects against Let's
#     Encrypt's own intermediate certificate rotating, but NOT
#     against an unexpected leaf-key change - no second "3 1 1" value
#     to fall back on if that happens.
#
# REAL BUG FOUND 2026-11-17: the first version of this redesign
# applied the "current + previous" idea to EACH usage-type
# independently (2x "3 1 1" AND 2x "2 1 1"), publishing 4 TLSA
# records total - neither of Internet.nl's own two recommended
# schemes, which the test's own text warns against ("other types...
# will generally be more error prone and less interoperable").
# Corrected before ever being run against live DNS.
DANE_SCHEME="${DANE_SCHEME:-rollover}"

show_help()
{
    sed -n '3,121p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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

# expected_tlsa_prev_for / expected_tlsa_ta_prev_for: same as the two
# functions above, but computed from certbot's own PREVIOUS archive
# generation (the one just superseded, if any) instead of the live
# one - part of the "N and N-1" rotation added 2026-11-17, see the
# file header's "DANE rollover scheme" section for the full reasoning.
# certbot already keeps every past cert/fullchain generation under
# archive/, named identically one number lower, so "the previous
# value" needs no state tracking of its own: resolve the live symlink
# to find the current generation number, then read the file one
# number below it. Prints nothing if that can't be determined (e.g.
# this is the very first issuance, with no N-1 at all) - callers must
# check for that.
_dane_prev_generation_file()
{
    local kind="$1" resolved
    resolved="$(readlink -f "/etc/letsencrypt/live/${CERT_NAME}/cert.pem" 2>/dev/null || true)"
    [[ "$resolved" =~ ^(.*)/cert([0-9]+)\.pem$ ]] || return 1
    local archive_dir="${BASH_REMATCH[1]}" cur_gen="${BASH_REMATCH[2]}"
    [[ "$cur_gen" -gt 1 ]] || return 1
    local prev_gen=$((cur_gen - 1))
    local f="${archive_dir}/${kind}${prev_gen}.pem"
    [[ -f "$f" ]] || return 1
    echo "$f"
}
expected_tlsa_prev_for()
{
    local f hash
    f="$(_dane_prev_generation_file cert)" || return 0
    hash="$(openssl x509 -in "$f" -noout -pubkey 2>/dev/null \
        | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -hex 2>/dev/null | sed 's/^.*= //')"
    [[ "${#hash}" -eq 64 ]] || return 0
    echo "3 1 1 ${hash}"
}
expected_tlsa_ta_prev_for()
{
    local f hash
    f="$(_dane_prev_generation_file fullchain)" || return 0
    hash="$(awk -v n=2 '/-----BEGIN CERTIFICATE-----/{c++} c==n{print} /-----END CERTIFICATE-----/{if(c==n) exit}' "$f" \
        | openssl x509 -noout -pubkey 2>/dev/null \
        | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -hex 2>/dev/null | sed 's/^.*= //')"
    [[ "${#hash}" -eq 64 ]] || return 0
    echo "2 1 1 ${hash}"
}

# tlsa_lookup_all <domain> <label> <usage_prefix>: prints EVERY
# matching TLSA record's rrdata for this usage-type, one per line (0,
# 1 or 2 lines - the "N and N-1" rotation keeps at most 2). Prefers
# transip-dns list - the authoritative source, queried live with zero
# caching - over resolvectl's own DNS-based lookup, whenever TransIP
# credentials are available for this domain. REAL BUG FOUND
# 2026-11-16: --status used resolvectl only, which can lag the true
# state by up to the record's own TTL (a resolver cache, including
# this server's own) - right after a --setup run that had genuinely
# just succeeded, --status still showed [FAIL] for several minutes
# even though `transip-dns list` already showed the correct value.
# Falls back to resolvectl (first match only - it cannot reliably
# enumerate multiple same-name+type records) only when there is no
# TransIP access to query directly (a different registrar) - that
# case has no zero-caching, multi-record-aware alternative available.
tlsa_lookup_all()
{
    local domain="$1" label="$2" usage_prefix="$3"
    if have_transip_creds "$domain"; then
        local user key_file
        user="$(transip_user_for "$domain")"; key_file="$(transip_key_for "$domain")"
        transip-dns --username "$user" --key-file "$key_file" list "$domain" 2>/dev/null \
            | awk -v n="_25._tcp.${label}" -v u="$usage_prefix" \
                '$1==n && $3=="TLSA" && $4==u { for (i=4; i<=NF; i++) printf "%s%s", $i, (i<NF ? " " : "\n") }'
    else
        local out
        if out="$(resolvectl query --type=TLSA "_25._tcp.${label}.${domain}" 2>/dev/null)"; then
            grep -oE '[0-9]+ [0-9]+ [0-9]+ [0-9a-fA-F]+' <<< "$out" | grep -E "^${usage_prefix} " || true
        fi
    fi
}

# tlsa_lookup <domain> <label> <usage_prefix>: first match only, kept
# for any caller that genuinely wants just one value.
tlsa_lookup()
{
    tlsa_lookup_all "$@" | head -1
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

    # tlsa_lookup_all() prefers transip-dns list - zero caching - over
    # DNS resolution, so a --setup run's result shows correctly here
    # immediately, not just after the record's own TTL expires
    # everywhere.
    #
    # check_tlsa_pair <usage_prefix> <description> <new_value> <prev_value>:
    # compares the live set against the desired set ({new_value}, or
    # {new_value, prev_value} when prev_value is non-empty and
    # actually differs) in BOTH directions - every live value must be
    # desired (catches stale cruft) AND every desired value must be
    # live (catches a missing "new" or a missing "prev" the active
    # scheme expects). REAL BUG FOUND 2026-11-17 while first testing
    # this live: the original version only checked the first
    # direction, so "new" published but "prev" still missing (the
    # live state right after switching DANE_SCHEME to "rollover") was
    # silently treated as neither OK nor FAIL - no line printed at
    # all for that usage-type.
    check_tlsa_pair()
    {
        local usage_prefix="$1" description="$2" new_value="$3" prev_value="$4"
        local -a live=()
        while IFS= read -r line; do [[ -n "$line" ]] && live+=("$line"); done \
            < <(tlsa_lookup_all "$domain" "$label" "$usage_prefix")

        if [[ "${#live[@]}" -eq 0 ]]; then
            failline "No ${description} TLSA record published yet at _25._tcp.${target}."
            failed=$((failed + 1))
            return
        fi

        local -a desired=("$new_value")
        [[ -n "$prev_value" && "$prev_value" != "$new_value" ]] && desired+=("$prev_value")

        local have want found all_match=1
        for have in "${live[@]}"; do
            found=0
            for want in "${desired[@]}"; do [[ "${have,,}" == "${want,,}" ]] && { found=1; break; }; done
            if [[ "$found" -eq 0 ]]; then
                failline "${description} TLSA record \"${have}\" is stale (no longer the current or previous value) - run --setup to clean it up."
                failed=$((failed + 1))
                all_match=0
            fi
        done

        for want in "${desired[@]}"; do
            found=0
            for have in "${live[@]}"; do [[ "${have,,}" == "${want,,}" ]] && { found=1; break; }; done
            if [[ "$found" -eq 0 ]]; then
                failline "${description} is missing \"${want}\" - published {${live[*]}}, run --setup to add it."
                failed=$((failed + 1))
                all_match=0
            fi
        done

        [[ "$all_match" -eq 1 ]] && okline "${description} TLSA record(s) published and match the desired set: ${live[*]}"
        # REAL BUG FOUND 2026-11-17: without this, the function's own
        # exit status is whatever the `[[ ... ]] && okline ...` line
        # above evaluated to - 1 (false) every time all_match was 0,
        # i.e. every time a [FAIL] was found. check_tlsa_pair is
        # called bare (no `||` guard - --status must keep checking
        # everything else after one check fails, not abort), so under
        # set -e that silently killed the whole script right after
        # the first [FAIL] line - confirmed live: --status printed
        # exactly one [FAIL] and then stopped, never reaching the
        # DANE_DOMAINS/deploy-hook checks or the summary at all.
        return 0
    }

    okline "Rollover scheme: ${DANE_SCHEME} ($( [[ "$DANE_SCHEME" == "rollover" ]] && echo '"3 1 1" current + "3 1 1" previous' || echo '"3 1 1" current + "2 1 1" issuer CA' ))."
    if [[ "$DANE_SCHEME" == "rollover" ]]; then
        check_tlsa_pair "3" "DANE-EE (3 1 1, current + previous)" "$(expected_tlsa_for)" "$(expected_tlsa_prev_for)"
        local leftover_ta
        leftover_ta="$(tlsa_lookup_all "$domain" "$label" "2")"
        if [[ -n "$leftover_ta" ]]; then
            failline "Found leftover DANE-TA (2 1 1) record(s) from the 'issuer' scheme while running 'rollover' - run --setup to clean up: ${leftover_ta}"
            failed=$((failed + 1))
        fi
    else
        check_tlsa_pair "3" "DANE-EE (3 1 1)" "$(expected_tlsa_for)" ""
        check_tlsa_pair "2" "DANE-TA (2 1 1, issuer CA)" "$(expected_tlsa_ta_for)" ""
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

    # publish_tlsa_pair <usage_prefix> <description> <new_value> <prev_value>:
    # "N and N-1" rotation reconciliation for ONE TLSA usage-type at
    # _25._tcp.<label>.<domain> - called once for DANE-EE ("3 1 1")
    # and once for DANE-TA ("2 1 1"). Desired end state is
    # {new_value} alone, or {new_value, prev_value} when prev_value is
    # non-empty and actually differs (the common case, thanks to
    # reuse_key, is that they're identical - nothing extra to add
    # there). Whatever is currently published but no longer in that
    # desired set gets deleted. See the file header's "DANE rollover
    # scheme" section for the full history of why this replaced a
    # straight add/update design.
    #
    # REAL BUG FOUND AND FIXED 2026-11-17: the previous version used
    # `transip-dns update` (TransIP's PATCH endpoint) to change an
    # existing record's content in place. Re-reading transip_rest's
    # own update_dns_entry() (and the TransIP API docs it quotes)
    # confirmed PATCH identifies the record to change by
    # name+expire+type ONLY, never content - fine with exactly one
    # record of a usage-type at a name, but as soon as TWO coexist at
    # the same name+ttl (this exact rollover scheme, confirmed live
    # the moment a real key rotation needed updating one of them),
    # TransIP can no longer tell them apart and correctly refuses with
    # 406 "Multiple matches found" - leaving the old, wrong value
    # live. delete's own request includes the exact content being
    # removed, so it never has this ambiguity; every change here is
    # now delete(exact old content) + add(new content), never
    # update/PATCH.
    publish_tlsa_pair()
    {
        local usage_prefix="$1" description="$2" new_value="$3" prev_value="$4"
        [[ -n "$new_value" ]] || die "Could not compute the expected ${description} value - refusing to publish."

        local -a desired=("$new_value")
        [[ -n "$prev_value" && "$prev_value" != "$new_value" ]] && desired+=("$prev_value")

        local -a live=()
        while IFS= read -r line; do [[ -n "$line" ]] && live+=("$line"); done \
            < <(tlsa_lookup_all "$domain" "$label" "$usage_prefix")

        local rc=0 want have found i

        for want in "${desired[@]}"; do
            found=0
            for have in "${live[@]}"; do [[ "${have,,}" == "${want,,}" ]] && { found=1; break; }; done
            [[ "$found" -eq 1 ]] && continue
            if ! have_transip_creds "$domain"; then
                err "${description} needs ${want} published and no TransIP credentials are available."
                err "Add: _25._tcp.${target}  TLSA  ${want}"
                rc=1
                continue
            fi
            require_cmd transip-dns
            local user key_file add_ttl sibling_ttl
            user="$(transip_user_for "$domain")"; key_file="$(transip_key_for "$domain")"
            # A SIBLING TLSA entry (same or other usage-type) can
            # already exist at this exact name - TransIP requires
            # every record in that rrset to share one TTL, so adding
            # this one with the script's own fixed $TTL default fails
            # outright (406) whenever that sibling's own live TTL
            # differs. Use the sibling's live TTL when one exists,
            # $TTL only when this is truly the first TLSA record here.
            add_ttl="$TTL"
            sibling_ttl="$(transip_live_ttl_for "$domain" "_25._tcp.${label}" TLSA)"
            [[ -n "$sibling_ttl" ]] && add_ttl="$sibling_ttl"
            if ! transip-dns --username "$user" --key-file "$key_file" \
                add "$domain" "_25._tcp.${label}" TLSA "$want" --ttl "$add_ttl"; then
                err "Could not add ${description} record '${want}' for _25._tcp.${target}."
                rc=1
                continue
            fi
            log "[ OK ] Published ${description}: ${want}"
        done

        for ((i = 0; i < ${#live[@]}; i++)); do
            have="${live[$i]}"
            found=0
            for want in "${desired[@]}"; do [[ "${have,,}" == "${want,,}" ]] && { found=1; break; }; done
            [[ "$found" -eq 1 ]] && continue
            if ! have_transip_creds "$domain"; then
                err "${description} has a superseded record that needs removing and no TransIP credentials are available."
                err "Remove: _25._tcp.${target}  TLSA  ${have}"
                rc=1
                continue
            fi
            require_cmd transip-dns
            local user2 key_file2 have_ttl
            user2="$(transip_user_for "$domain")"; key_file2="$(transip_key_for "$domain")"
            have_ttl="$(transip_live_ttl_for "$domain" "_25._tcp.${label}" TLSA)"
            if ! transip-dns --username "$user2" --key-file "$key_file2" \
                delete "$domain" "_25._tcp.${label}" TLSA "$have" --ttl "${have_ttl:-$TTL}"; then
                err "Could not remove the superseded ${description} record '${have}' for _25._tcp.${target}."
                rc=1
                continue
            fi
            log "[ OK ] Removed superseded ${description} record: ${have}"
        done

        if [[ "$rc" -eq 0 ]]; then
            [[ "$BRIEF" -eq 1 ]] || log "[ OK ] ${description} now matches the desired set exactly."
            log "      Resolvers (including this server's own cache) may keep answering with"
            log "      old/missing data for up to the record's own TTL. A --status run inside"
            log "      this window can still show [FAIL] even though TransIP's own answer is"
            log "      already correct."
        fi
        return "$rc"
    }

    # remove_usage_type <usage_prefix> <description>: deletes every
    # live TLSA record of this usage-type at this name, for cleaning
    # up the OTHER scheme's record(s) left behind by a scheme switch
    # (e.g. an existing "2 1 1" DANE-TA entry when now running in
    # "rollover" mode, which never publishes one at all).
    remove_usage_type()
    {
        local usage_prefix="$1" description="$2"
        local -a live=()
        while IFS= read -r line; do [[ -n "$line" ]] && live+=("$line"); done \
            < <(tlsa_lookup_all "$domain" "$label" "$usage_prefix")
        [[ "${#live[@]}" -gt 0 ]] || return 0
        if ! have_transip_creds "$domain"; then
            err "${description} has ${#live[@]} record(s) left over from a scheme switch and no TransIP credentials are available to remove them."
            return 1
        fi
        require_cmd transip-dns
        local user key_file have_ttl have rc=0
        user="$(transip_user_for "$domain")"; key_file="$(transip_key_for "$domain")"
        for have in "${live[@]}"; do
            have_ttl="$(transip_live_ttl_for "$domain" "_25._tcp.${label}" TLSA)"
            if ! transip-dns --username "$user" --key-file "$key_file" \
                delete "$domain" "_25._tcp.${label}" TLSA "$have" --ttl "${have_ttl:-$TTL}"; then
                err "Could not remove the leftover ${description} record '${have}' from the previous scheme."
                rc=1
                continue
            fi
            log "[ OK ] Removed leftover ${description} record from the previous scheme: ${have}"
        done
        return "$rc"
    }

    log "Rollover scheme: ${DANE_SCHEME}."
    if [[ "$DANE_SCHEME" == "rollover" ]]; then
        publish_tlsa_pair "3" "DANE-EE (3 1 1, current + previous)" "$(expected_tlsa_for)" "$(expected_tlsa_prev_for)" || return 1
        remove_usage_type "2" "DANE-TA (2 1 1)" || return 1
    else
        publish_tlsa_pair "3" "DANE-EE (3 1 1)" "$(expected_tlsa_for)" "" || return 1
        publish_tlsa_pair "2" "DANE-TA (2 1 1, issuer CA)" "$(expected_tlsa_ta_for)" "" || return 1
    fi

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
# cmd_teardown: removes DANE entirely for one domain - every live
# TLSA record at _25._tcp.<label>.<domain> (both usage-types, whatever
# scheme is/was active - a clean sweep, not scheme-aware), and the
# domain's own "domain:label" entry from update-dane-tlsa.sh's
# DANE_DOMAINS (so a future cert renewal stops touching it). Does NOT
# remove the deploy-hook itself or anything for OTHER domains still
# in DANE_DOMAINS. Same standing rule as --setup: writes real DNS
# zone records, the operator runs this themselves, never an agent.
# ============================================================

cmd_teardown()
{
    require_cmd openssl

    local domain="$1" label target
    [[ -n "$domain" ]] || die "No active domain found (grommunio-admin domain list) - run step 31 first."
    label="$(dane_label_for "$domain")"
    target="${label}.${domain}"

    log "Removing all DANE/TLSA records for _25._tcp.${target}..."

    local -a leftover=()
    local up
    for up in 3 2; do
        while IFS= read -r line; do [[ -n "$line" ]] && leftover+=("$line"); done \
            < <(tlsa_lookup_all "$domain" "$label" "$up")
    done

    if [[ "${#leftover[@]}" -eq 0 ]]; then
        log "[ OK ] No TLSA record published at _25._tcp.${target} - nothing to remove there."
    elif ! have_transip_creds "$domain"; then
        local have
        for have in "${leftover[@]}"; do
            err "Remove by hand: _25._tcp.${target}  TLSA  ${have}"
        done
        return 1
    else
        require_cmd transip-dns
        local user key_file have ttl rc=0
        user="$(transip_user_for "$domain")"; key_file="$(transip_key_for "$domain")"
        for have in "${leftover[@]}"; do
            ttl="$(transip_live_ttl_for "$domain" "_25._tcp.${label}" TLSA)"
            if ! transip-dns --username "$user" --key-file "$key_file" \
                delete "$domain" "_25._tcp.${label}" TLSA "$have" --ttl "${ttl:-$TTL}"; then
                err "Could not remove TLSA record '${have}' for _25._tcp.${target}."
                rc=1
                continue
            fi
            log "[ OK ] Removed TLSA record: ${have}"
        done
        [[ "$rc" -eq 0 ]] || return 1
    fi

    if grep -qF "\"${domain}:${label}\"" "$DANE_TLSA_SCRIPT" 2>/dev/null; then
        log "Removing ${domain}:${label} from update-dane-tlsa.sh's DANE_DOMAINS..."
        backup_file "$DANE_TLSA_SCRIPT"
        sed -i "/\"${domain}:${label}\"/d" "$DANE_TLSA_SCRIPT"
        bash -n "$DANE_TLSA_SCRIPT" || die "$DANE_TLSA_SCRIPT has a syntax error after editing - check it by hand."
        finalize_backup "$DANE_TLSA_SCRIPT"
        if [[ -x "$DEPLOY_HOOK" ]]; then
            install -m 0755 "$DANE_TLSA_SCRIPT" "$DEPLOY_HOOK"
        fi
        log "[ OK ] Removed from DANE_DOMAINS and refreshed the deploy-hook."
    else
        log "[ OK ] ${domain} was not in update-dane-tlsa.sh's DANE_DOMAINS."
    fi

    log "[ OK ] DANE/TLSA fully removed for ${target}."
    log "      Resolvers (including this server's own cache) may keep answering with"
    log "      the old value for up to its own TTL."
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
        -scheme)
            [[ "${2:-}" == "rollover" || "${2:-}" == "issuer" ]] || die "-scheme must be 'rollover' or 'issuer' (got: '${2:-}')."
            DANE_SCHEME="$2"; shift 2 ;;
        --status)
            ACTION="status"; shift ;;
        --setup)
            ACTION="setup"; shift ;;
        --report)
            ACTION="report"; shift ;;
        --teardown)
            ACTION="teardown"; shift ;;
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
        teardown) require_root; cmd_teardown "$TARGET_DOMAIN" ;;
        "") show_help ;;
    esac
}

if [[ -n "$MAIL_TO" ]]; then
    [[ -n "$ACTION" ]] || die "--mail needs an action (--status, --setup, --report or --teardown)."
    OUTPUT="$(run_action 2>&1)"
    printf '%s\n' "$OUTPUT"
    send_report_mail "$MAIL_TO" "manage-dane.sh ${ACTION} - ${TARGET_DOMAIN}" "$OUTPUT"
    log "[ OK ] Report mailed to ${MAIL_TO}."
else
    run_action
fi
