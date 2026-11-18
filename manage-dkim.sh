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
#   manage-dkim.sh --status        Check, for every domain that already has a local
#                                  key, whether DNS actually publishes the matching
#                                  dkim-ed, dkim-rsa and dkim (CNAME) records.
#                                  Read-only, changes nothing. (--validate is a
#                                  kept alias, same naming as manage-certs.sh/
#                                  manage-mta-sts.sh's own --status.)
#   manage-dkim.sh --setup         Like --status, but also PUBLISHES/UPDATES
#                                  whatever it finds missing or wrong, via the
#                                  TransIP API (TransIP only - see below) -
#                                  for every domain that already has a local key.
#                                  Put -domain <name> BEFORE --setup to scope this
#                                  to just that one domain instead - -domain must
#                                  come first, a later flag only sets the action,
#                                  it never clears which domain was already given.
#                                  Omitting -domain always means every domain, and
#                                  now always asks for an explicit "yes" first
#                                  (confirm_all_domains, functions/00-common.sh) -
#                                  added 2026-11-19 after a real incident where
#                                  "-domain <name> --setup" was typed expecting one
#                                  domain and every signed domain got republished
#                                  instead, because this check did not exist yet.
#   manage-dkim.sh --report        Not a check - prints every signed domain's
#                                  own DKIM records (dkim-ed/dkim-rsa TXT,
#                                  dkim CNAME), copy-paste-ready for a
#                                  registrar that needs them added by hand.
#                                  -domain <name> before --status/--report also
#                                  scopes those two to just that one domain.
#   --brief                        Modifier for --status/--report/--setup:
#                                  only [FAIL]/[WARN] lines and a one-line
#                                  summary, no [ OK ] lines.
#   --mail [<address>]             Modifier for --status/--report/--setup:
#                                  also emails the exact output via this
#                                  server's own MTA. Default recipient (no
#                                  address given): admin@<first active
#                                  domain> - the hub mailbox step 31 creates.
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
# Registrar-agnostic for --all/-domain/--validate: they only ever generate
# keys, write local files, or read DNS (resolvectl) - never touch any
# registrar. --setup is the one action that can WRITE DNS records, and
# only because the TransIP registrar API happens to be available here
# (same account.d/*.ini credentials manage-dane.sh uses, matched per
# domain via dns_transip_domains - see functions/00-common.sh). On a
# different registrar it still runs, checks for TransIP credentials for
# each domain, and when they're missing, falls back cleanly: it does
# NOT crash, it prints the exact record you need to add by hand and
# exits non-zero for that domain. --setup writes real DNS zone records.
# The operator runs this command themselves - an agent must never run
# --setup (this is a standing, absolute rule for every DNS zone-record
# change in this project, not specific to this script, see
# manage-dane.sh's own header). An agent may run --validate freely
# (read-only) and should hand the operator the exact --setup command to
# run themselves.

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
# TTL used only when PUBLISHING A NEW record (--setup) - 5 minutes for
# both TXT and CNAME, matching this project's own documented convention
# for DKIM/DMARC (see docs/dns-records-reference.md: "Short TTLs (5
# minutes) on the DKIM and DMARC records make key rotation... take
# effect quickly"), the operator's own choice. Updating an EXISTING
# record instead uses its own live TTL (transip_live_ttl_for,
# functions/00-common.sh) - transip-dns update requires name/type/TTL
# to match exactly, it cannot change the TTL itself.
DKIM_DEFAULT_TTL=300

show_help()
{
    sed -n '3,79p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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
        failline "${sel}._domainkey.${dom}: no TXT record found in DNS."
        return 1
    fi
    actual="$(normalize_dkim_value "$dns_out")"

    if [[ -z "$actual" ]]; then
        failline "${sel}._domainkey.${dom}: TXT record found but could not be parsed."
        return 1
    fi
    if [[ "$actual" == "$expected" ]]; then
        okline "${sel}._domainkey.${dom}: matches."
        return 0
    fi
    failline "${sel}._domainkey.${dom}: DNS value does not match the local key."
    if [[ "$BRIEF" -ne 1 ]]; then
        echo "         expected: $expected"
        echo "         DNS has:  $actual"
    fi
    return 1
}

check_dkim_cname()
{
    local dom="$1"
    local expected="dkim-rsa._domainkey.${dom}"
    local dns_out actual

    if ! dns_out="$(resolvectl query --type=CNAME "dkim._domainkey.${dom}" 2>/dev/null)"; then
        failline "dkim._domainkey.${dom}: no CNAME record found in DNS."
        return 1
    fi
    actual="$(sed -nE 's/^.*IN[[:space:]]+CNAME[[:space:]]+([^[:space:]]+).*/\1/p' <<< "$dns_out" | sed 's/\.$//')"
    expected="${expected%.}"
    if [[ "$actual" == "$expected" ]]; then
        okline "dkim._domainkey.${dom}: CNAME to $expected."
        return 0
    fi
    failline "dkim._domainkey.${dom}: expected CNAME to $expected, DNS has: ${actual:-<none>}"
    return 1
}

# ============================================================
# cmd_setup: like cmd_validate, but PUBLISHES/UPDATES whatever it finds
# missing or wrong, via the TransIP API (transip_account_for() etc.,
# functions/00-common.sh - same per-domain account resolution
# manage-dane.sh uses). Degrades the same way manage-dane.sh does: no
# TransIP credentials for a domain means print the exact manual record
# and move on, never crash. Adding a brand new record uses the
# DKIM_DEFAULT_TTL constant above (5 minutes); updating
# an existing-but-wrong one uses transip_live_ttl_for() instead - the
# exact lesson learned fixing manage-dane.sh's own stale-TLSA update
# the same day (transip-dns update requires name/type/TTL to match the
# live record exactly, TTL itself is not something update can change).
# ============================================================

setup_txt_selector()
{
    local dom="$1" sel="$2"
    local name="${sel}._domainkey"
    local txt_file="$RSPAMD_DKIM_DIR/$dom.$sel.txt"
    local expected actual="" dns_out live_ttl user key_file

    if [[ ! -f "$txt_file" ]]; then
        err "${name}.${dom}: no local key to compare against."
        return 1
    fi
    expected="$(normalize_dkim_value "$(cat "$txt_file")")"

    if dns_out="$(resolvectl query --type=TXT "${name}.${dom}" 2>/dev/null)"; then
        actual="$(normalize_dkim_value "$dns_out")"
    fi

    if [[ -n "$actual" && "$actual" == "$expected" ]]; then
        [[ "$BRIEF" -eq 1 ]] || log "[ OK ] ${name}.${dom}: already matches."
        return 0
    fi

    if ! have_transip_creds "$dom"; then
        err "${name}.${dom}: $([[ -z "$actual" ]] && echo "no TXT record published" || echo "TXT record does not match") and no TransIP credentials are available to fix it."
        err "  Publish as: ${name}.${dom}  TXT  \"${expected}\""
        return 1
    fi

    require_cmd transip-dns
    user="$(transip_user_for "$dom")"; key_file="$(transip_key_for "$dom")"

    if [[ -z "$actual" ]]; then
        log "Publishing ${name}.${dom}..."
        transip-dns --username "$user" --key-file "$key_file" \
            add "$dom" "$name" TXT "$expected" --ttl "$DKIM_DEFAULT_TTL"
        log "[ OK ] Published ${name}.${dom}."
        log "      TTL is ${DKIM_DEFAULT_TTL}s - resolvers (including this server's own"
        log "      cache) may keep answering with no data for up to that long."
    else
        log "${name}.${dom} does not match - updating..."
        live_ttl="$(transip_live_ttl_for "$dom" "$name" TXT)"
        [[ -n "$live_ttl" ]] || die "Could not find ${name}.${dom}'s own live TTL via transip-dns list - refusing to guess one for update."
        transip-dns --username "$user" --key-file "$key_file" \
            update "$dom" "$name" TXT "$expected" --ttl "$live_ttl"
        log "[ OK ] Updated ${name}.${dom}."
        log "      TTL is ${live_ttl}s - resolvers (including this server's own cache) may"
        log "      keep answering with the OLD value for up to that long."
    fi
}

setup_dkim_cname()
{
    local dom="$1" name="dkim._domainkey"
    local expected="dkim-rsa._domainkey.${dom}." actual="" dns_out live_ttl user key_file

    if dns_out="$(resolvectl query --type=CNAME "${name}.${dom}" 2>/dev/null)"; then
        actual="$(sed -nE 's/^.*IN[[:space:]]+CNAME[[:space:]]+([^[:space:]]+).*/\1/p' <<< "$dns_out")"
        [[ -n "$actual" ]] && actual="${actual%.}."
    fi

    if [[ "$actual" == "$expected" ]]; then
        [[ "$BRIEF" -eq 1 ]] || log "[ OK ] ${name}.${dom}: already matches."
        return 0
    fi

    if ! have_transip_creds "$dom"; then
        err "${name}.${dom}: $([[ -z "$actual" ]] && echo "no CNAME published" || echo "CNAME does not match") and no TransIP credentials are available to fix it."
        err "  Publish as: ${name}.${dom}  CNAME  ${expected}"
        return 1
    fi

    require_cmd transip-dns
    user="$(transip_user_for "$dom")"; key_file="$(transip_key_for "$dom")"

    if [[ -z "$actual" ]]; then
        log "Publishing ${name}.${dom}..."
        transip-dns --username "$user" --key-file "$key_file" \
            add "$dom" "$name" CNAME "$expected" --ttl "$DKIM_DEFAULT_TTL"
        log "[ OK ] Published ${name}.${dom}."
        log "      TTL is ${DKIM_DEFAULT_TTL}s - resolvers (including this server's own"
        log "      cache) may keep answering with no data for up to that long."
    else
        log "${name}.${dom} does not match - updating..."
        live_ttl="$(transip_live_ttl_for "$dom" "$name" CNAME)"
        [[ -n "$live_ttl" ]] || die "Could not find ${name}.${dom}'s own live TTL via transip-dns list - refusing to guess one for update."
        transip-dns --username "$user" --key-file "$key_file" \
            update "$dom" "$name" CNAME "$expected" --ttl "$live_ttl"
        log "[ OK ] Updated ${name}.${dom}."
        log "      TTL is ${live_ttl}s - resolvers (including this server's own cache) may"
        log "      keep answering with the OLD value for up to that long."
    fi
}

cmd_setup()
{
    require_cmd resolvectl

    local -a domains=()
    while read -r d; do [[ -n "$d" ]] && domains+=("$d"); done < <(signed_domains)

    if [[ "${#domains[@]}" -eq 0 ]]; then
        die "No domains have a local DKIM key yet (run --all or -domain <name> first)."
    fi

    # Scope to just TARGET_DOMAIN when given (-domain <name> --setup) -
    # added 2026-11-19 after a real incident where this was typed
    # expecting one domain and every signed domain got republished
    # instead, because this loop never looked at TARGET_DOMAIN at all.
    # Omitting -domain still means "all" - but now that always asks
    # first (confirm_all_domains, functions/00-common.sh).
    if [[ -n "$TARGET_DOMAIN" ]]; then
        local found=0 d
        for d in "${domains[@]}"; do [[ "$d" == "$TARGET_DOMAIN" ]] && { found=1; break; }; done
        [[ "$found" -eq 1 ]] || die "Domain '$TARGET_DOMAIN' has no local DKIM key yet (run -domain ${TARGET_DOMAIN} first, without --setup)."
        domains=("$TARGET_DOMAIN")
    else
        confirm_all_domains "publish/update DKIM DNS records" "${domains[@]}"
    fi

    local d failed=0
    for d in "${domains[@]}"; do
        echo
        echo "=== $d ==="
        setup_txt_selector "$d" "$RSPAMD_DKIM_ED_SELECTOR" || failed=$((failed + 1))
        setup_txt_selector "$d" "$RSPAMD_DKIM_RSA_SELECTOR" || failed=$((failed + 1))
        setup_dkim_cname "$d" || failed=$((failed + 1))
    done

    echo
    if [[ "$failed" -eq 0 ]]; then
        log "[ OK ] DKIM DNS records published/up to date for ${#domains[@]} domain(s)."
    else
        err "$failed record(s) could not be published/updated automatically - see [FAIL]/error lines above."
        return 1
    fi
}

cmd_validate()
{
    require_cmd resolvectl

    local -a domains=()
    while read -r d; do [[ -n "$d" ]] && domains+=("$d"); done < <(signed_domains)

    if [[ "${#domains[@]}" -eq 0 ]]; then
        die "No domains have a local DKIM key yet (run --all or -domain <name> first)."
    fi

    if [[ -n "$TARGET_DOMAIN" ]]; then
        local found=0 d
        for d in "${domains[@]}"; do [[ "$d" == "$TARGET_DOMAIN" ]] && { found=1; break; }; done
        [[ "$found" -eq 1 ]] || die "Domain '$TARGET_DOMAIN' has no local DKIM key yet (run -domain ${TARGET_DOMAIN} first)."
        domains=("$TARGET_DOMAIN")
    fi

    local d failed=0 checked=0 domain_out domain_failed
    for d in "${domains[@]}"; do
        checked=$((checked + 1))
        domain_failed=0
        domain_out="$(
            check_txt_selector "$d" "$RSPAMD_DKIM_ED_SELECTOR" || echo "__FAIL__"
            check_txt_selector "$d" "$RSPAMD_DKIM_RSA_SELECTOR" || echo "__FAIL__"
            check_dkim_cname "$d" || echo "__FAIL__"
        )"
        domain_failed="$(grep -c '__FAIL__' <<< "$domain_out" || true)"
        domain_out="$(grep -v '__FAIL__' <<< "$domain_out" || true)"
        failed=$((failed + domain_failed))
        if [[ "$domain_failed" -gt 0 || "$BRIEF" -ne 1 ]]; then
            echo
            echo "=== $d ==="
            printf '%s\n' "$domain_out"
        fi
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
# cmd_report: standalone, copy-paste-friendly DNS record block for
# every domain that already has local DKIM keys - not a check, just
# "what to publish", matching check-dns.sh --report's own spirit but
# scoped to only what THIS script manages (DKIM TXT + CNAME).
# ============================================================

cmd_report()
{
    local -a domains=()
    while read -r d; do [[ -n "$d" ]] && domains+=("$d"); done < <(signed_domains)
    [[ "${#domains[@]}" -gt 0 ]] || die "No domains have a local DKIM key yet (run --all or -domain <name> first)."

    if [[ -n "$TARGET_DOMAIN" ]]; then
        local found=0 d
        for d in "${domains[@]}"; do [[ "$d" == "$TARGET_DOMAIN" ]] && { found=1; break; }; done
        [[ "$found" -eq 1 ]] || die "Domain '$TARGET_DOMAIN' has no local DKIM key yet (run -domain ${TARGET_DOMAIN} first)."
        domains=("$TARGET_DOMAIN")
    fi

    local d sel txt_file value
    for d in "${domains[@]}"; do
        echo "DKIM records for ${d}"
        echo "======================"
        echo
        for sel in "$RSPAMD_DKIM_ED_SELECTOR" "$RSPAMD_DKIM_RSA_SELECTOR"; do
            txt_file="$RSPAMD_DKIM_DIR/$d.$sel.txt"
            [[ -f "$txt_file" ]] || continue
            value="$(normalize_dkim_value "$(cat "$txt_file")")"
            echo "  Name:  ${sel}._domainkey.${d}"
            echo "  Type:  TXT"
            echo "  Value: \"${value}\""
            echo
        done
        echo "  Name:  dkim._domainkey.${d}"
        echo "  Type:  CNAME"
        echo "  Value: dkim-rsa._domainkey.${d}."
        echo
    done
    echo "Publish these exact records at your DNS registrar."
    echo "Re-run manage-dkim.sh --status afterward to confirm they match."
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
        --all)
            ACTION="all"; shift ;;
        -domain)
            [[ -n "${2:-}" ]] || die "-domain needs a value."
            ACTION="domain"; TARGET_DOMAIN="$2"; shift 2 ;;
        --status|--validate)
            ACTION="validate"; shift ;;
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
            echo "manage-dkim.sh: unknown option: $1 (see --help)" >&2
            exit 1 ;;
    esac
done

require_root
require_cmd grommunio-admin

run_action()
{
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
        setup)
            cmd_setup
            ;;
        report)
            cmd_report
            ;;
        *)
            show_help
            exit 1
            ;;
    esac
}

if [[ -n "$MAIL_TO" ]]; then
    [[ -n "$ACTION" ]] || die "--mail needs an action (--status, --setup or --report)."
    OUTPUT="$(run_action 2>&1)"
    printf '%s\n' "$OUTPUT"
    send_report_mail "$MAIL_TO" "manage-dkim.sh ${ACTION}" "$OUTPUT"
    log "[ OK ] Report mailed to ${MAIL_TO}."
else
    run_action
fi
