#!/usr/bin/env bash
#
# manage-dkim.sh
#
# Standalone, idempotent DKIM management for grommunio domains. Deliberately
# NOT part of server-setup.sh's pipeline (functions/*.sh) - the original/main
# domain's DKIM setup stays where it already is, in functions/38-antispam.sh,
# run once during initial provisioning. This script is for every domain,
# including ones added after the server was first set up, and is meant to be
# re-run by hand any time a domain is added or removed.
#
# Usage (run as root on the mail server itself, not the build host):
#   manage-dkim.sh                 Show this help (no arguments = help, not an action).
#   manage-dkim.sh --all           Generate any missing DKIM keys for every active
#                                  domain, and refresh dkim_signing.conf + the DNS
#                                  records file.
#   manage-dkim.sh -domain <name>  Same, but only for this one domain (must already
#                                  be an active grommunio domain).
#   manage-dkim.sh --validate      Check, for every domain that already has a local
#                                  key, whether DNS actually publishes the matching
#                                  dkim-ed, dkim-rsa and dkim (CNAME) records.
#
# --all/-domain generation is a full, idempotent pass, not an "add only" diff:
#   - creates both DKIM keys (Ed25519 + RSA 2048) per domain, keeping any that
#     already exist (same rspamadm mechanism 38-antispam.sh uses)
#   - regenerates local.d/dkim_signing.conf from scratch, from EVERY domain that
#     has a key on disk (not just the domain(s) given this run - otherwise running
#     this for one new domain would wipe out every domain set up earlier) - safe
#     to regenerate every time, reloads rspamd only if this file actually changed
#   - regenerates /root/cfg-server/dkim-dns-records.txt the same way
#
# Fully registrar-agnostic: --all/-domain only generate keys and write
# local files (rspamd config, the records-to-add text file above) - it
# never writes to any DNS registrar itself, you publish those TXT/CNAME
# records by hand wherever your zone lives. --validate only reads DNS
# (resolvectl) to confirm what you published matches. No registrar API
# of any kind is used anywhere in this script.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/functions/00-common.sh"

RSPAMD_DKIM_DIR="/var/lib/rspamd/dkim"
RSPAMD_DKIM_ED_SELECTOR="dkim-ed"
RSPAMD_DKIM_ED_TYPE="ed25519"
RSPAMD_DKIM_RSA_SELECTOR="dkim-rsa"
RSPAMD_DKIM_RSA_BITS=2048
SIGN_CFG="/etc/rspamd/local.d/dkim_signing.conf"
RECORDS="/root/cfg-server/dkim-dns-records.txt"

show_help()
{
    sed -n '3,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# make_dkim_key <domain> <selector> <type> [bits]: creates one key, keeps an existing one
make_dkim_key()
{
    local dom="$1" sel="$2" type="$3" bits="${4:-}"
    local key="$RSPAMD_DKIM_DIR/$dom.$sel.key"
    if [[ -f "$key" ]]; then
        log "[ OK ] $type DKIM key for $dom (selector $sel) exists (kept)."
        return 0
    fi
    local -a args=(-t "$type" -d "$dom" -s "$sel" -k "$key")
    [[ -n "$bits" ]] && args+=(-b "$bits")
    rspamadm dkim_keygen "${args[@]}" > "$RSPAMD_DKIM_DIR/$dom.$sel.txt" \
        || die "rspamadm could not create the $type DKIM key for $dom."
    chown _rspamd:_rspamd "$key"; chmod 0640 "$key"
    log "[ OK ] Created $type DKIM key for $dom (selector $sel)."
}

# all_active_domains: every domain grommunio currently considers active
all_active_domains()
{
    grommunio-admin domain list 2>/dev/null | sed -nE 's/^[0-9]+: ([^ ]+) \(active\).*/\1/p'
}

# every domain that already has BOTH local keys on disk, regardless of what
# was targeted on this particular run - the authoritative "currently signed" set
signed_domains()
{
    local keyfile d
    for keyfile in "$RSPAMD_DKIM_DIR"/*."$RSPAMD_DKIM_ED_SELECTOR".key; do
        [[ -e "$keyfile" ]] || continue
        d="$(basename "$keyfile" ".$RSPAMD_DKIM_ED_SELECTOR.key")"
        [[ -f "$RSPAMD_DKIM_DIR/$d.$RSPAMD_DKIM_RSA_SELECTOR.key" ]] && echo "$d"
    done
}

# normalize_dkim_value <raw text>: pulls every quoted segment out (DNS/zone-file
# TXT values are often split across several "..." "..." strings) and joins them
# into one comparable string, regardless of minor spacing differences.
normalize_dkim_value()
{
    tr -d '\n' <<< "$1" | grep -oE '"[^"]*"' | tr -d '"' | tr -d '\n' | sed -E 's/;[[:space:]]*p=/; p=/; s/[[:space:]]+/ /g'
}

# ============================================================
# cmd_generate <domain> ...: create missing keys for exactly these domains,
# then refresh dkim_signing.conf and the DNS records file from every domain
# that has keys (see signed_domains() above).
# ============================================================

cmd_generate()
{
    local -a target_domains=("$@")

    require_cmd rspamadm
    require_cmd systemctl

    install -d -o _rspamd -g _rspamd -m 0750 "$RSPAMD_DKIM_DIR" || die "Cannot create $RSPAMD_DKIM_DIR."

    local d
    for d in "${target_domains[@]}"; do
        make_dkim_key "$d" "$RSPAMD_DKIM_ED_SELECTOR" "$RSPAMD_DKIM_ED_TYPE"
        make_dkim_key "$d" "$RSPAMD_DKIM_RSA_SELECTOR" rsa "$RSPAMD_DKIM_RSA_BITS"
    done

    local -a all_signed=()
    while read -r d; do [[ -n "$d" ]] && all_signed+=("$d"); done < <(signed_domains)

    local sign_new
    sign_new="$(mktemp)"
    {
        echo "# local.d/dkim_signing.conf (managed by manage-dkim.sh)"
        echo "# Each domain signs with an Ed25519 and an RSA selector (two DKIM-Signature headers)."
        echo "sign_authenticated = true;"
        echo "sign_local = true;"
        echo "use_domain = \"header\";"
        echo "use_redis = false;"
        echo "allow_pubkey_mismatch = false;"
        echo "domain {"
        for d in "${all_signed[@]}"; do
            echo "  \"$d\" {"
            echo "    selectors ["
            echo "      { path = \"$RSPAMD_DKIM_DIR/$d.$RSPAMD_DKIM_ED_SELECTOR.key\"; selector = \"$RSPAMD_DKIM_ED_SELECTOR\"; },"
            echo "      { path = \"$RSPAMD_DKIM_DIR/$d.$RSPAMD_DKIM_RSA_SELECTOR.key\"; selector = \"$RSPAMD_DKIM_RSA_SELECTOR\"; }"
            echo "    ]"
            echo "  }"
        done
        echo "}"
    } > "$sign_new"

    local sign_changed=0
    if ! cmp -s "$sign_new" "$SIGN_CFG" 2>/dev/null; then
        backup_file "$SIGN_CFG"
        install -m 0644 "$sign_new" "$SIGN_CFG"
        finalize_backup "$SIGN_CFG"
        sign_changed=1
        log "[ OK ] Wrote $SIGN_CFG (${all_signed[*]})."
    else
        log "[ OK ] $SIGN_CFG already up to date."
    fi
    rm -f "$sign_new"

    if [[ "$sign_changed" -eq 1 ]]; then
        rspamadm configtest >/dev/null || die "rspamd config test fails after writing $SIGN_CFG."
        systemctl restart rspamd || die "rspamd did not restart after the DKIM signing config change."
        log "[ OK ] rspamd restarted."
    fi

    backup_file "$RECORDS"
    : > "$RECORDS"
    chmod 0600 "$RECORDS"
    local sel rec_value
    for d in "${all_signed[@]}"; do
        for sel in "$RSPAMD_DKIM_ED_SELECTOR" "$RSPAMD_DKIM_RSA_SELECTOR"; do
            rec_value="$(normalize_dkim_value "$(cat "$RSPAMD_DKIM_DIR/$d.$sel.txt")")"
            {
                echo "# $d ($sel)"
                echo "name:  ${sel}._domainkey"
                echo "type:  TXT"
                echo "value: $rec_value"
                echo
            } >> "$RECORDS"
        done
    done
    finalize_backup "$RECORDS"
    log "[ OK ] DKIM DNS records written to $RECORDS for: ${all_signed[*]}"
    log "     Publish these in DNS - DKIM does not verify until they are there."
}

# ============================================================
# cmd_validate: for every domain that already has local keys, check that
# dkim-ed, dkim-rsa (TXT) and dkim (CNAME to dkim-rsa) are actually correct
# in DNS right now.
# ============================================================

check_txt_selector()
{
    local dom="$1" sel="$2"
    local txt_file="$RSPAMD_DKIM_DIR/$dom.$sel.txt"
    local expected actual dns_out

    if [[ ! -f "$txt_file" ]]; then
        echo "[SKIP] ${sel}._domainkey.${dom}: no local key to compare against."
        return 1
    fi
    expected="$(normalize_dkim_value "$(cat "$txt_file")")"

    if ! dns_out="$(resolvectl query --type=TXT "${sel}._domainkey.${dom}" 2>/dev/null)"; then
        echo "[FAIL] ${sel}._domainkey.${dom}: no TXT record found in DNS."
        return 1
    fi
    actual="$(normalize_dkim_value "$dns_out")"

    if [[ -z "$actual" ]]; then
        echo "[FAIL] ${sel}._domainkey.${dom}: TXT record found but could not be parsed."
        return 1
    fi
    if [[ "$actual" == "$expected" ]]; then
        echo "[ OK ] ${sel}._domainkey.${dom}: matches."
        return 0
    fi
    echo "[FAIL] ${sel}._domainkey.${dom}: DNS value does not match the local key."
    echo "         expected: $expected"
    echo "         DNS has:  $actual"
    return 1
}

check_dkim_cname()
{
    local dom="$1"
    local expected="dkim-rsa._domainkey.${dom}"
    local dns_out actual

    if ! dns_out="$(resolvectl query --type=CNAME "dkim._domainkey.${dom}" 2>/dev/null)"; then
        echo "[FAIL] dkim._domainkey.${dom}: no CNAME record found in DNS."
        return 1
    fi
    actual="$(sed -nE 's/^.*IN[[:space:]]+CNAME[[:space:]]+([^[:space:]]+).*/\1/p' <<< "$dns_out" | sed 's/\.$//')"
    expected="${expected%.}"
    if [[ "$actual" == "$expected" ]]; then
        echo "[ OK ] dkim._domainkey.${dom}: CNAME to $expected."
        return 0
    fi
    echo "[FAIL] dkim._domainkey.${dom}: expected CNAME to $expected, DNS has: ${actual:-<none>}"
    return 1
}

cmd_validate()
{
    require_cmd resolvectl

    local -a domains=()
    while read -r d; do [[ -n "$d" ]] && domains+=("$d"); done < <(signed_domains)

    if [[ "${#domains[@]}" -eq 0 ]]; then
        die "No domains have a local DKIM key yet (run --all or -domain <name> first)."
    fi

    local d failed=0 checked=0
    for d in "${domains[@]}"; do
        echo
        echo "=== $d ==="
        checked=$((checked + 1))
        check_txt_selector "$d" "$RSPAMD_DKIM_ED_SELECTOR" || failed=$((failed + 1))
        check_txt_selector "$d" "$RSPAMD_DKIM_RSA_SELECTOR" || failed=$((failed + 1))
        check_dkim_cname "$d" || failed=$((failed + 1))
    done

    echo
    if [[ "$failed" -eq 0 ]]; then
        log "[ OK ] All DKIM DNS records correct for ${checked} domain(s)."
    else
        err "$failed check(s) failed across ${checked} domain(s) - see [FAIL] lines above."
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
            echo "manage-dkim.sh: unknown option: $1 (see --help)" >&2
            exit 1 ;;
    esac
done

require_root
require_cmd grommunio-admin

case "$ACTION" in
    all)
        mapfile -t ALL_DOMAINS < <(all_active_domains)
        [[ "${#ALL_DOMAINS[@]}" -gt 0 ]] || die "No active domains found (grommunio-admin domain list)."
        log "Generating DKIM for ${#ALL_DOMAINS[@]} active domain(s): ${ALL_DOMAINS[*]}"
        cmd_generate "${ALL_DOMAINS[@]}"
        ;;
    domain)
        mapfile -t ALL_DOMAINS < <(all_active_domains)
        found=0
        for a in "${ALL_DOMAINS[@]}"; do [[ "$a" == "$TARGET_DOMAIN" ]] && { found=1; break; }; done
        [[ "$found" -eq 1 ]] || die "Domain '$TARGET_DOMAIN' is not an active grommunio domain (grommunio-admin domain list)."
        cmd_generate "$TARGET_DOMAIN"
        ;;
    validate)
        cmd_validate
        ;;
    *)
        show_help
        exit 1
        ;;
esac
