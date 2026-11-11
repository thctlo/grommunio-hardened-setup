#!/usr/bin/env bash
#
# manage-certs.sh
#
# Standalone management of ONE shared Let's Encrypt certificate covering
# every active grommunio domain's mail/web hostnames. Not part of
# server-setup.sh's pipeline - mirrors manage-dkim.sh in spirit: re-run by
# hand any time a domain is added or removed.
#
# Fully registrar-agnostic, including for brand-new hostnames: issuance
# uses certbot's --nginx plugin (HTTP-01 challenge over the webserver
# already running here), never DNS-01 - so unlike manage-dane.sh, no
# registrar API (TransIP or otherwise) is involved at all. The only DNS
# requirement is that a hostname's A/AAAA already resolves here (checked
# read-only, see above); nothing about certificate issuance itself cares
# which registrar that answer came from.
#
# For each active domain, four hostnames matter:
#   <domain>, mail.<domain>, autodiscover.<domain>, mta-sts.<domain>
# (mta-sts.<domain> added 2026-10-30 for the MTA-STS policy host, see
# manage-mta-sts.sh - that script writes the policy file served under
# this hostname; this script only needs to make sure the hostname has a
# certificate once DNS for it exists.)
# Only hostnames that actually resolve (A/AAAA) to THIS server's own public
# address(es) are included. Many domains recreated from an old backup on
# this test server do NOT point here at all (their real production hosting
# is elsewhere) - requesting a certificate for a hostname that resolves to
# a different server would fail outright (HTTP-01, this script's
# authenticator) and would be wrong to request at all even if it somehow
# succeeded. Found live 2026-10-25 on a multi-domain test server: of 11
# active domains, only 3 actually pointed here; the rest were skipped
# with a warning, not silently dropped.
#
# Every run recomputes the COMPLETE desired hostname list from scratch, from
# every currently active domain (not just the one given this run) - same
# principle as manage-dkim.sh: the live DNS answer for each domain is the
# source of truth every time, not a separate "which domains were already
# added" state. The one shared certificate (certbot's existing cert name,
# already used by nginx) is then issued/expanded (--expand) to cover
# exactly that hostname list - skipped entirely if the list hasn't changed,
# to avoid burning Let's Encrypt's rate limit on a no-op.
#
# Usage (run as root on the mail server itself, not the build host):
#   manage-certs.sh                 Show this help (no arguments = help).
#   manage-certs.sh --all           Recompute the full hostname list from
#                                   every active domain, and request/expand
#                                   the shared certificate to cover it.
#   manage-certs.sh -domain <name>  Same full recompute, but additionally
#                                   fail loudly if this one domain's own
#                                   hostnames do not resolve here.
#   manage-certs.sh --validate      Check DNS + the live certificate's SAN
#                                   list against what every active domain
#                                   should have, and report the cert's
#                                   expiry.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/functions/00-common.sh"

NET_CFG="$(cfg_file 10-network-hostname)"
NEW_FQDN="" PRIMARY_IPV4="" PRIMARY_IPV6=""
[[ -f "$NET_CFG" ]] && source "$NET_CFG"
CERT_NAME="${NEW_FQDN:-mail.example.com}"
CERT_DIR="/etc/letsencrypt/live/${CERT_NAME}"

show_help()
{
    sed -n '3,33p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# resolves_here <hostname>: does it have an A/AAAA record matching this
# server's own saved primary address(es) (from step 10's config)?
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

# wanted_hostnames: every "<domain> / mail.<domain> / autodiscover.<domain>"
# that actually resolves here, across every currently active domain. Prints
# one hostname per line; warns (to stderr, via log) about anything skipped.
wanted_hostnames()
{
    local d sub host
    local -a domains=()
    while read -r d; do [[ -n "$d" ]] && domains+=("$d"); done < <(all_active_domains)
    [[ "${#domains[@]}" -gt 0 ]] || die "No active domains found (grommunio-admin domain list)."

    for d in "${domains[@]}"; do
        local -a matched=() skipped=()
        for sub in "" "mail." "autodiscover." "mta-sts."; do
            host="${sub}${d}"
            if resolves_here "$host"; then
                matched+=("$host")
            else
                skipped+=("$host")
            fi
        done
        if [[ "${#matched[@]}" -eq 0 ]]; then
            log "[SKIP] $d: none of its hostnames resolve to this server (hosted elsewhere) - excluded entirely." >&2
        else
            if [[ "${#skipped[@]}" -gt 0 ]]; then
                log "[WARN] $d: ${matched[*]} resolve(s) here, but ${skipped[*]} do(es) not - only including the ones that do." >&2
            fi
            printf '%s\n' "${matched[@]}"
        fi
    done

    # Standing rule, decided 2026-10-30 (see dns-records-reference.md): the
    # FIRST domain this server was ever installed with always gets its own
    # dedicated mx1.<domain> MX target hostname, separate from the shared
    # mail.<domain> every other domain's MX still uses. Purpose: let that
    # one domain publish its own DANE TLSA record later without it silently
    # applying to every other domain too (DANE is keyed on the MX target
    # hostname, not the recipient domain - domains still using the shared
    # mail.<domain> MX are never affected by this). Not a per-domain
    # pattern like the four subs above - deliberately only ever checked
    # for this one domain's mx1 name, never generated for any other domain.
    local first_domain
    first_domain="$(first_active_domain)"
    if [[ -n "$first_domain" ]] && resolves_here "mx1.${first_domain}"; then
        echo "mx1.${first_domain}"
    fi
}

# current_cert_sans: the live certificate's own SAN list, one per line, or
# nothing if no certificate exists yet under this name.
current_cert_sans()
{
    [[ -f "$CERT_DIR/cert.pem" ]] || return 0
    openssl x509 -in "$CERT_DIR/cert.pem" -noout -ext subjectAltName 2>/dev/null \
        | tr ',' '\n' | sed -nE 's/^[[:space:]]*DNS:[[:space:]]*([^[:space:]]+).*/\1/p'
}

# ============================================================
# cmd_generate: recompute the full desired hostname list and issue/expand
# the shared certificate to match it, unless it already does.
# ============================================================

cmd_generate()
{
    require_cmd certbot
    require_cmd openssl
    require_cmd resolvectl

    # Standing rule, decided 2026-10-30: this certificate's key pair is
    # reused across renewals (not regenerated every time), so that a DANE
    # TLSA record pinned to it (usage 3/DANE-EE, see manage-dane.sh) stays
    # valid across renewals instead of needing an update every ~60-90
    # days. Checked/set every run, independent of whether the SAN list
    # below changes - does not itself trigger a renewal, only changes what
    # the NEXT renewal (triggered by certbot.timer, or the --expand call
    # further down if one happens this run) will do.
    local renewal_conf="/etc/letsencrypt/renewal/${CERT_NAME}.conf"
    if [[ -f "$renewal_conf" ]]; then
        if grep -q '^reuse_key = True$' "$renewal_conf"; then
            log "[ OK ] reuse_key already set on $renewal_conf."
        else
            backup_file "$renewal_conf"
            if grep -q '^reuse_key' "$renewal_conf"; then
                sed -i 's/^reuse_key.*/reuse_key = True/' "$renewal_conf"
            else
                sed -i '/^key_type = /a reuse_key = True' "$renewal_conf"
            fi
            finalize_backup "$renewal_conf"
            log "[ OK ] Set reuse_key = True on $renewal_conf (takes effect on the next renewal)."
        fi
    fi

    local -a wanted=()
    while read -r h; do [[ -n "$h" ]] && wanted+=("$h"); done < <(wanted_hostnames)
    [[ "${#wanted[@]}" -gt 0 ]] || die "No hostname resolves to this server at all - nothing to request a certificate for."

    local -a current=()
    while read -r h; do [[ -n "$h" ]] && current+=("$h"); done < <(current_cert_sans)

    local wanted_sorted current_sorted
    wanted_sorted="$(printf '%s\n' "${wanted[@]}" | sort -u)"
    current_sorted="$(printf '%s\n' "${current[@]}" | sort -u)"

    if [[ "$wanted_sorted" == "$current_sorted" ]]; then
        log "[ OK ] Certificate '$CERT_NAME' already covers exactly: ${wanted[*]}"
        return 0
    fi

    log "Requesting/expanding certificate '$CERT_NAME' to cover: ${wanted[*]}"
    local -a d_args=()
    local h
    for h in "${wanted[@]}"; do d_args+=(-d "$h"); done

    certbot certonly --cert-name "$CERT_NAME" --nginx --expand \
        --non-interactive --agree-tos "${d_args[@]}" \
        || die "certbot could not issue/expand the certificate '$CERT_NAME'."

    systemctl reload nginx || die "nginx did not reload after the certificate change."
    log "[ OK ] Certificate '$CERT_NAME' updated and nginx reloaded."
}

# ============================================================
# cmd_validate: DNS + live-certificate check, no changes made.
# ============================================================

cmd_validate()
{
    require_cmd openssl
    require_cmd resolvectl

    local -a wanted=()
    while read -r h; do [[ -n "$h" ]] && wanted+=("$h"); done < <(wanted_hostnames)

    local -a current=()
    while read -r h; do [[ -n "$h" ]] && current+=("$h"); done < <(current_cert_sans)

    echo
    echo "=== Certificate '$CERT_NAME' ==="
    if [[ ! -f "$CERT_DIR/cert.pem" ]]; then
        echo "[FAIL] No certificate found at $CERT_DIR."
        return 1
    fi
    local expiry
    expiry="$(openssl x509 -in "$CERT_DIR/cert.pem" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')"
    echo "Expiry: $expiry"
    echo "Current SANs: ${current[*]:-<none>}"
    echo "Should cover: ${wanted[*]:-<none>}"

    local failed=0 h found
    for h in "${wanted[@]}"; do
        found=0
        for c in "${current[@]}"; do [[ "$c" == "$h" ]] && { found=1; break; }; done
        if [[ "$found" -eq 1 ]]; then
            echo "[ OK ] $h is covered by the certificate."
        else
            echo "[FAIL] $h resolves here but is NOT covered by the certificate."
            failed=$((failed + 1))
        fi
    done
    for c in "${current[@]}"; do
        found=0
        for h in "${wanted[@]}"; do [[ "$h" == "$c" ]] && { found=1; break; }; done
        [[ "$found" -eq 1 ]] || echo "[WARN] $c is covered by the certificate but no longer resolves here (stale?)."
    done

    echo
    if [[ "$failed" -eq 0 ]]; then
        log "[ OK ] Certificate matches DNS for every hostname that should be covered."
    else
        err "$failed hostname(s) that resolve here are missing from the certificate."
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
            echo "manage-certs.sh: unknown option: $1 (see --help)" >&2
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
        if ! resolves_here "$TARGET_DOMAIN" && ! resolves_here "mail.$TARGET_DOMAIN" \
            && ! resolves_here "autodiscover.$TARGET_DOMAIN" && ! resolves_here "mta-sts.$TARGET_DOMAIN"; then
            die "None of $TARGET_DOMAIN / mail.$TARGET_DOMAIN / autodiscover.$TARGET_DOMAIN / mta-sts.$TARGET_DOMAIN resolve to this server."
        fi
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
