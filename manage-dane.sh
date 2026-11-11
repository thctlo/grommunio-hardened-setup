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
#   - TransIP credentials at /etc/letsencrypt/transip/accounts.d/account1.ini
#     + /etc/letsencrypt/transip/keys/account1.key (see
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

# account1.ini/.key (directory mode), not the legacy single-file
# transip.ini/transip.key pair this script used before 2026-11-04 - that
# pair was an old, no-longer-used leftover and has since been deleted
# (confirmed on purpose, not a bug to work around here).
CREDS_INI="/etc/letsencrypt/transip/accounts.d/account1.ini"
TRANSIP_KEY="/etc/letsencrypt/transip/keys/account1.key"
DANE_TLSA_SCRIPT="${SCRIPT_DIR}/update-dane-tlsa.sh"

NET_CFG="$(cfg_file 10-network-hostname)"
NEW_FQDN="" PRIMARY_IPV4="" PRIMARY_IPV6=""
[[ -f "$NET_CFG" ]] && source "$NET_CFG"
CERT_NAME="${NEW_FQDN:-mail.example.com}"
DEPLOY_HOOK="/etc/letsencrypt/renewal-hooks/deploy/75-update-dane-tlsa"
TTL=3600

show_help()
{
    sed -n '3,62p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# "mx1" for whichever domain is first_active_domain() (it has no
# mail.<domain>-shaped hostname of its own that could serve this - that
# name means the shared server identity for it specifically, see
# dns-records-reference.md). "mail" for every other domain - it already
# has its own mail.<domain> A/AAAA from normal domain setup, nothing new
# to create there.
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

have_transip_creds()
{
    [[ -f "$CREDS_INI" && -f "$TRANSIP_KEY" ]]
}

transip_user()
{
    grep '^dns_transip_username' "$CREDS_INI" | sed 's/.*= *//'
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

    echo
    echo "=== DANE status for ${target} (domain: ${domain}, label: ${label}) ==="
    echo

    if have_transip_creds; then
        echo "[ OK ] TransIP DNS credentials found - --setup can write DNS records."
    else
        echo "[INFO] No TransIP DNS credentials found - --setup can only report, every"
        echo "       missing DNS record below must be added by hand at your registrar."
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
        v4="$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' <<< "$out" | head -1)"
    fi
    if out="$(resolvectl query --type=AAAA "$target" 2>/dev/null)"; then
        v6="$(grep -oE '[0-9a-fA-F:]+:[0-9a-fA-F:]+' <<< "$out" | head -1)"
    fi
    if [[ -n "$v4" || -n "$v6" ]]; then
        echo "[ OK ] ${target} resolves (A: ${v4:-<none>}, AAAA: ${v6:-<none>})."
    else
        echo "[FAIL] ${target} does not resolve at all - needs an A/AAAA record first."
    fi

    local cert_sans
    cert_sans="$(openssl x509 -in /etc/letsencrypt/live/${CERT_NAME}/cert.pem -noout -ext subjectAltName 2>/dev/null)"
    if echo "$cert_sans" | grep -qF "$target"; then
        echo "[ OK ] ${target} is covered by the certificate."
    else
        echo "[FAIL] ${target} is NOT yet in the certificate - run manage-certs.sh --all (needs the A/AAAA record above to exist first)."
    fi

    local renewal_conf="/etc/letsencrypt/renewal/${CERT_NAME}.conf"
    if [[ -f "$renewal_conf" ]] && grep -q '^reuse_key = True$' "$renewal_conf"; then
        echo "[ OK ] reuse_key is set (TLSA value will stay stable across renewals)."
    else
        echo "[FAIL] reuse_key is not set - run manage-certs.sh --all."
    fi

    local tlsa_live=""
    if out="$(resolvectl query --type=TLSA "_25._tcp.${target}" 2>/dev/null)"; then
        tlsa_live="$(grep -oE '[0-9]+ [0-9]+ [0-9]+ [0-9a-fA-F]+' <<< "$out" | head -1)"
    fi
    if [[ -n "$tlsa_live" ]]; then
        echo "[ OK ] TLSA record published: ${tlsa_live}"
    else
        echo "[FAIL] No TLSA record published yet at _25._tcp.${target}."
    fi

    if grep -qF "\"${domain}:${label}\"" "$DANE_TLSA_SCRIPT" 2>/dev/null; then
        echo "[ OK ] ${domain} is in update-dane-tlsa.sh's DANE_DOMAINS (kept in sync on key rotation)."
    else
        echo "[FAIL] ${domain} is NOT in update-dane-tlsa.sh's DANE_DOMAINS yet - run --setup, or add \"${domain}:${label}\" by hand."
    fi

    if [[ -x "$DEPLOY_HOOK" ]]; then
        echo "[ OK ] Deploy-hook installed: $DEPLOY_HOOK"
    else
        echo "[FAIL] Deploy-hook not installed - TLSA will not auto-update on renewal."
    fi
    echo
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
        if have_transip_creds; then
            log "Creating ${target} A/AAAA records via transip-dns..."
            require_cmd transip-dns
            local user ipv4 ipv6 out
            user="$(transip_user)"
            ipv4="" ipv6=""
            if out="$(resolvectl query --type=A "mail.${domain}" 2>/dev/null)"; then
                ipv4="$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' <<< "$out" | head -1)"
            fi
            if out="$(resolvectl query --type=AAAA "mail.${domain}" 2>/dev/null)"; then
                ipv6="$(grep -oE '[0-9a-fA-F:]+:[0-9a-fA-F:]+' <<< "$out" | head -1)"
            fi
            [[ -n "$ipv4" ]] && transip-dns --username "$user" --key-file "$TRANSIP_KEY" add "$domain" "$label" A "$ipv4" --ttl 86400
            [[ -n "$ipv6" ]] && transip-dns --username "$user" --key-file "$TRANSIP_KEY" add "$domain" "$label" AAAA "$ipv6" --ttl 86400
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

    local tlsa_live="" out
    if out="$(resolvectl query --type=TLSA "_25._tcp.${target}" 2>/dev/null)"; then
        tlsa_live="$(grep -oE '[0-9]+ [0-9]+ [0-9]+ [0-9a-fA-F]+' <<< "$out" | head -1)"
    fi
    if [[ -z "$tlsa_live" ]]; then
        if have_transip_creds; then
            log "Computing and publishing the initial TLSA record..."
            require_cmd transip-dns
            local user want_hash
            user="$(transip_user)"
            want_hash="$(openssl x509 -in /etc/letsencrypt/live/${CERT_NAME}/cert.pem -noout -pubkey \
                | openssl pkey -pubin -outform DER | openssl dgst -sha256 -hex | sed 's/^.*= //')"
            [[ "${#want_hash}" -eq 64 ]] || die "Computed hash is not 64 hex chars - refusing to publish."
            transip-dns --username "$user" --key-file "$TRANSIP_KEY" \
                add "$domain" "_25._tcp.${label}" TLSA "3 1 1 ${want_hash}" --ttl "$TTL"
            log "[ OK ] Published TLSA: 3 1 1 ${want_hash}"
        else
            err "No TLSA record exists and no TransIP credentials are available to publish one."
            err "Compute it by hand (usage 3, selector 1, matching-type 1 / SPKI-SHA256):"
            err "  openssl x509 -in /etc/letsencrypt/live/mail.${domain}/cert.pem -noout -pubkey \\"
            err "    | openssl pkey -pubin -outform DER | openssl dgst -sha256 -hex"
            err "Publish as: _25._tcp.${target}  TLSA  3 1 1 <that hash>"
            return 1
        fi
    else
        log "[ OK ] TLSA record already published: ${tlsa_live}"
    fi

    if grep -qF "\"${domain}:${label}\"" "$DANE_TLSA_SCRIPT" 2>/dev/null; then
        log "[ OK ] ${domain} already in update-dane-tlsa.sh's DANE_DOMAINS."
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
# Argument parsing
# ============================================================

if [[ $# -eq 0 ]]; then
    show_help
    exit 0
fi

ACTION="" TARGET_DOMAIN=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -domain)
            [[ -n "${2:-}" ]] || die "-domain needs a value."
            TARGET_DOMAIN="$2"; shift 2 ;;
        --status)
            ACTION="status"; shift ;;
        --setup)
            ACTION="setup"; shift ;;
        -h|--help)
            show_help; exit 0 ;;
        *)
            echo "manage-dane.sh: unknown option: $1 (see --help)" >&2
            exit 1 ;;
    esac
done

[[ -n "$TARGET_DOMAIN" ]] || TARGET_DOMAIN="$(first_active_domain)"

case "$ACTION" in
    status) cmd_status "$TARGET_DOMAIN" ;;
    setup) require_root; cmd_setup "$TARGET_DOMAIN" ;;
    "") show_help ;;
esac
