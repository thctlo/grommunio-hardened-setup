#!/usr/bin/env bash
#
# manage-mta-sts.sh
#
# Standalone management of MTA-STS (RFC 8461) policy hosting for every
# active grommunio domain. Not part of server-setup.sh's pipeline - mirrors
# manage-dkim.sh/manage-certs.sh in spirit: re-run by hand any time a
# domain is added or removed.
#
# Also manages TLSRPT (RFC 8460) - a separate but always-paired DNS TXT
# record at _smtp._tls.<domain>, telling remote senders where to mail
# their aggregate TLS-failure reports. Added 2026-11-18: an external
# scanner found it missing, and a live audit then showed it had only
# ever been set by hand for 4 of 13 active domains (one TransIP
# account) - never for the other 9 (the second TransIP account) or
# example3.nl (no TransIP account configured for it - degrades the same
# way as any other missing-credentials domain below). Entirely
# independent of this domain's own mta-sts.<domain> web hosting - pure
# DNS, no wanted_domains() gate, applies to every active domain. One
# centralized rua address for all domains (not per-domain) -
# postmaster@<first active domain> - confirmed by the operator as an existing
# alias onto the admin shared mailbox he actively reads, matching
# exactly what the 4 pre-existing live records already used.
#
# MTA-STS needs three things per domain:
#   1. A DNS TXT record at _mta-sts.<domain> ("v=STSv1; id=...") - checked
#      read-only by --status/--validate; --setup can also PUBLISH/UPDATE
#      it via the TransIP API (same accounts.d/*.ini credentials
#      manage-dane.sh/manage-dkim.sh use, matched per domain - see
#      functions/00-common.sh). On a different registrar --setup still
#      runs, checks for TransIP credentials for each domain, and when
#      missing, falls back cleanly: prints the exact record to add by
#      hand and exits non-zero for that domain, never crashes.
#   2. A certificate covering mta-sts.<domain> - handled by
#      manage-certs.sh (already extended to include this hostname).
#   3. The policy file itself, served over HTTPS at exactly
#      https://mta-sts.<domain>/.well-known/mta-sts.txt - THIS script's
#      job: writes one nginx server block + one policy file PER DOMAIN,
#      fully independent of every other domain (even though their content
#      happens to be identical right now, since every domain here shares
#      the same mail server) - deliberately not a single shared
#      file/vhost, so a future domain-specific policy (different mode,
#      different mx, different max_age) needs only that one domain's own
#      files touched, nothing else.
#
# Same scoping as manage-certs.sh: only domains whose mta-sts.<domain>
# hostname actually resolves here are included - every run recomputes the
# complete list from scratch, not from a separate state file.
#
# Starts every domain in "testing" mode deliberately (not "enforce") -
# testing mode has zero delivery risk (failures are only reported, never
# block mail), the safe default until proven working. Switch a specific
# domain to "enforce" by hand later (edit that domain's own policy file),
# once confirmed working.
#
# Each domain's policy "mx:" field must match that domain's own real MX
# record - NOT necessarily this server's own global hostname. A domain
# whose mail.<domain> collides with this server's own canonical hostname
# gets a dedicated "mx1.<domain>" MX instead (see dane_label_for() in
# functions/00-common.sh, shared with manage-dane.sh - same reasoning:
# its PTR is set to mx1.<domain> specifically so it matches Postfix's own
# HELO name). cmd_generate() computes this correctly for files it writes,
# but - by design - never touches a policy file that already exists, so
# a file written before this per-domain logic existed can be stuck with
# the wrong mx forever. --status detects that; --reconfigure fixes it.
#
# Usage:
#   manage-mta-sts.sh                Show this help (no arguments = help).
#   manage-mta-sts.sh --all          Recompute the full domain list and
#                                    write/update each domain's own policy
#                                    file + nginx server block to match.
#                                    Never overwrites an existing policy
#                                    file's content - see --reconfigure.
#   manage-mta-sts.sh -domain <name> Same, but fail loudly if this one
#                                    domain's mta-sts.<domain> hostname
#                                    does not resolve here.
#   manage-mta-sts.sh --status       Check DNS (_mta-sts TXT and _smtp._tls
#                                    TLSRPT TXT), the live-served policy
#                                    file, and that its "mx:" value matches
#                                    this domain's real MX record, for
#                                    every active domain; report what is
#                                    missing or wrong. Read-only, changes
#                                    nothing. (--validate is a kept alias.)
#   manage-mta-sts.sh --reconfigure  Like --all, but also FIXES an
#                                    existing policy file's "mx:" line if
#                                    it does not match this domain's real
#                                    MX record - the one thing --all
#                                    deliberately never touches. Preserves
#                                    that file's "mode:"/"max_age:"
#                                    exactly as they are (an enforce-mode
#                                    promotion, or a hand-tuned max_age,
#                                    survives).
#   manage-mta-sts.sh -domain <name> --enforce
#                                    Promotes just this one domain's own
#                                    policy file from "testing" to
#                                    "enforce", preserving mx/max_age
#                                    exactly. -domain must come BEFORE
#                                    --enforce (this script's own -domain
#                                    also sets an action by itself - a
#                                    later flag always wins). Only a
#                                    local file change - re-run --setup
#                                    afterward to publish the refreshed
#                                    _mta-sts TXT id so remote senders
#                                    notice the switch.
#   manage-mta-sts.sh --setup        Runs --reconfigure first (so the local
#                                    policy file/nginx side is correct),
#                                    then PUBLISHES/UPDATES each domain's
#                                    _mta-sts TXT record via TransIP to
#                                    match - a fresh id (sha256 of the
#                                    policy file, truncated) whenever the
#                                    served policy content changed since
#                                    the last publish, matching RFC 8461's
#                                    own requirement that id change
#                                    whenever the policy does. Also
#                                    PUBLISHES/UPDATES the _smtp._tls
#                                    TLSRPT TXT record for every active
#                                    domain (not just ones with mta-sts
#                                    web hosting here).
#                                    Put -domain <name> BEFORE --setup to
#                                    scope this to just that one domain -
#                                    -domain must come first, a later flag
#                                    only sets the action, it never clears
#                                    which domain was already given.
#                                    Omitting -domain always means every
#                                    domain, and now always asks for an
#                                    explicit "yes" first
#                                    (confirm_all_domains,
#                                    functions/00-common.sh) - added
#                                    2026-11-19 after a real incident in
#                                    manage-dkim.sh's own --setup where
#                                    "-domain <name> --setup" was typed
#                                    expecting one domain and every domain
#                                    got touched instead.
#   manage-mta-sts.sh --report       Not a check - prints every served
#                                    domain's own _mta-sts TXT record plus
#                                    every active domain's _smtp._tls
#                                    TLSRPT TXT record, copy-paste-ready
#                                    for a registrar that needs them added
#                                    by hand. -domain <name> before
#                                    --status/--report also scopes those
#                                    two to just that one domain.
#   --brief                          Modifier for --status/--report/
#                                    --setup: only [FAIL]/[WARN] lines
#                                    and a one-line summary, no [ OK ]
#                                    lines or served-policy dumps.
#   --mail [<address>]               Modifier for --status/--report/
#                                    --setup: also emails the exact
#                                    output via this server's own MTA.
#                                    Default recipient (no address
#                                    given): admin@<first active
#                                    domain> - the hub mailbox step 31
#                                    creates.
#
# --setup writes real DNS zone records. The operator runs this command
# themselves - an agent must never run --setup (this is a standing,
# absolute rule for every DNS zone-record change in this project, not
# specific to this script - see manage-dane.sh's own header). An agent
# may run --status/--validate freely (read-only) and should hand the
# operator the exact --setup command to run themselves.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/functions/00-common.sh"

NET_CFG="$(cfg_file 10-network-hostname)"
PRIMARY_IPV4="" PRIMARY_IPV6=""
[[ -f "$NET_CFG" ]] && source "$NET_CFG"

POLICY_ROOT="/var/www/mta-sts"
NGINX_CONF="/etc/nginx/conf.d/mta-sts.conf"
DEFAULT_MAX_AGE=604800   # 1 week
# TTL used only when PUBLISHING A NEW _mta-sts TXT record (--setup) - 5
# minutes, the operator's call 2026-11-15 (no established convention existed
# for this record before now). Updating an EXISTING record instead
# uses its own live TTL (transip_live_ttl_for, functions/00-common.sh)
# - transip-dns update requires name/type/TTL to match exactly, it
# cannot change the TTL itself.
MTA_STS_DEFAULT_TTL=300

# TTL used only when PUBLISHING A NEW _smtp._tls TLSRPT TXT record
# (--setup) - matches the 4 pre-existing live TLSRPT records' own TTL
# (confirmed 2026-11-18 via transip-dns list before this was scripted).
# Updating an EXISTING record uses its own live TTL, same reasoning as
# MTA_STS_DEFAULT_TTL above.
TLSRPT_DEFAULT_TTL=300

show_help()
{
    sed -n '3,159p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

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

# wanted_domains: every active domain whose mta-sts.<domain> hostname
# actually resolves here.
wanted_domains()
{
    local d
    local -a domains=()
    while read -r d; do [[ -n "$d" ]] && domains+=("$d"); done < <(all_active_domains)
    [[ "${#domains[@]}" -gt 0 ]] || die "No active domains found (grommunio-admin domain list)."

    for d in "${domains[@]}"; do
        if resolves_here "mta-sts.${d}"; then
            echo "$d"
        else
            log "[SKIP] $d: mta-sts.$d does not resolve to this server - excluded." >&2
        fi
    done
}

# policy_mx_for <domain>: the correct "mx:" value for that domain's own
# MTA-STS policy - its real MX hostname, via the same dane_label_for()
# this server's DANE setup uses (functions/00-common.sh), NOT this
# server's own global hostname. Using the wrong value here is exactly
# the bug --status/--reconfigure exist to catch and fix (see the header
# comment above).
policy_mx_for()
{
    local domain="$1"
    echo "$(dane_label_for "$domain").${domain}"
}

# _mta_sts_rebuild_nginx_conf: one nginx conf FILE, but one independent
# server{} block PER DOMAIN - never a shared block/shared server_name
# list, so one domain's block can diverge (e.g. its own cert, its own
# root) without touching any other domain's block. Rebuilt from scratch
# every run, matching the full current domain list exactly (a domain
# that stops resolving here is dropped here too, not left stale). Shared
# by cmd_generate and cmd_reconfigure - both need the exact same nginx
# side, only the policy-file side differs between them. Returns via the
# global $_changed (set to 1 if anything was written/reloaded).
_mta_sts_rebuild_nginx_conf()
{
    local -a domains=("$@")
    local conf_new d
    conf_new="$(mktemp)"
    {
        echo "# Managed by manage-mta-sts.sh - do not edit by hand."
        echo "# One independent server block per domain; see that script"
        echo "# for why this is deliberately not a single shared block."
        for d in "${domains[@]}"; do
            echo
            echo "server {"
            echo "    listen 443 ssl;"
            echo "    listen [::]:443 ssl;"
            echo "    http2 on;"
            echo "    server_name mta-sts.${d};"
            echo "    include /etc/grommunio-common/nginx/ssl_*.conf;"
            echo "    root ${POLICY_ROOT}/${d};"
            echo "    location /.well-known/mta-sts.txt {"
            echo "        default_type text/plain;"
            echo "    }"
            echo "    location / {"
            echo "        return 404;"
            echo "    }"
            echo "}"
        done
    } > "$conf_new"

    if ! cmp -s "$conf_new" "$NGINX_CONF" 2>/dev/null; then
        backup_file "$NGINX_CONF"
        install -m 0644 "$conf_new" "$NGINX_CONF"
        finalize_backup "$NGINX_CONF"
        _changed=1
        log "[ OK ] Wrote $NGINX_CONF with ${#domains[@]} domain-specific server block(s)."
    else
        log "[ OK ] $NGINX_CONF already up to date."
    fi
    rm -f "$conf_new"
}

# ============================================================
# cmd_generate: for every domain in scope, write/keep its own policy file
# and its own nginx server block. A domain's existing policy file is never
# overwritten if it already exists (so a hand-edited "enforce" switch, or
# a domain-specific mx/max_age, survives every re-run) - only missing
# domains get a fresh "testing" default written, with the correct
# per-domain mx (policy_mx_for). A file that already exists with the
# WRONG mx is left untouched here on purpose - see --reconfigure.
# ============================================================

cmd_generate()
{
    require_cmd resolvectl
    local only="${1:-}"

    local -a domains=()
    while read -r d; do [[ -n "$d" ]] && domains+=("$d"); done < <(wanted_domains)
    [[ "${#domains[@]}" -gt 0 ]] || die "No mta-sts.<domain> hostname resolves to this server - nothing to configure."

    # write_domains may be scoped to just $only (see header: -domain
    # <name> before --all/--setup) - domains itself never is, since
    # _mta_sts_rebuild_nginx_conf below must always see every domain or
    # it would drop every OTHER domain's server block from nginx.
    local -a write_domains=("${domains[@]}")
    if [[ -n "$only" ]]; then
        local found=0 d
        for d in "${domains[@]}"; do [[ "$d" == "$only" ]] && { found=1; break; }; done
        [[ "$found" -eq 1 ]] || die "mta-sts.$only does not resolve to this server."
        write_domains=("$only")
    fi

    local _changed=0 d policy_file mx_host

    for d in "${write_domains[@]}"; do
        install -d -m 0755 "${POLICY_ROOT}/${d}/.well-known"
        policy_file="${POLICY_ROOT}/${d}/.well-known/mta-sts.txt"
        if [[ -f "$policy_file" ]]; then
            log "[ OK ] $d: $policy_file already exists - left as-is (edit it by hand for mode/mx/max_age changes, or run --status/--reconfigure to check/fix just the mx value)."
        else
            mx_host="$(policy_mx_for "$d")"
            printf 'version: STSv1\nmode: testing\nmx: %s\nmax_age: %s\n' "$mx_host" "$DEFAULT_MAX_AGE" > "$policy_file"
            chmod 0644 "$policy_file"
            _changed=1
            log "[ OK ] $d: wrote $policy_file (mode: testing, mx: $mx_host)."
        fi
    done

    _mta_sts_rebuild_nginx_conf "${domains[@]}"

    if [[ "$_changed" -eq 1 ]]; then
        nginx -t || die "nginx -t failed after the MTA-STS config change."
        systemctl reload nginx || die "nginx did not reload."
        log "[ OK ] nginx reloaded."
    fi
}

# ============================================================
# cmd_reconfigure: like cmd_generate, but also FIXES an existing policy
# file's "mx:" line if it does not match policy_mx_for() - the one thing
# cmd_generate deliberately never touches. Preserves that file's
# "mode:"/"max_age:" exactly as they are (an enforce-mode promotion, or
# a hand-tuned max_age, survives). Missing files are created fresh,
# same as cmd_generate.
# ============================================================

cmd_reconfigure()
{
    require_cmd resolvectl
    local only="${1:-}"

    local -a domains=()
    while read -r d; do [[ -n "$d" ]] && domains+=("$d"); done < <(wanted_domains)
    [[ "${#domains[@]}" -gt 0 ]] || die "No mta-sts.<domain> hostname resolves to this server - nothing to configure."

    # write_domains may be scoped to just $only - domains itself never
    # is, same reasoning as cmd_generate() above (nginx conf rebuild
    # must always see every domain).
    local -a write_domains=("${domains[@]}")
    if [[ -n "$only" ]]; then
        local found=0 d
        for d in "${domains[@]}"; do [[ "$d" == "$only" ]] && { found=1; break; }; done
        if [[ "$found" -eq 0 ]]; then
            log "[SKIP] ${only}: mta-sts.${only} does not resolve here - nothing to reconfigure for it."
            return 0
        fi
        write_domains=("$only")
    fi

    local _changed=0 d policy_file expected_mx actual_mx mode max_age

    for d in "${write_domains[@]}"; do
        install -d -m 0755 "${POLICY_ROOT}/${d}/.well-known"
        policy_file="${POLICY_ROOT}/${d}/.well-known/mta-sts.txt"
        expected_mx="$(policy_mx_for "$d")"

        if [[ ! -f "$policy_file" ]]; then
            printf 'version: STSv1\nmode: testing\nmx: %s\nmax_age: %s\n' "$expected_mx" "$DEFAULT_MAX_AGE" > "$policy_file"
            chmod 0644 "$policy_file"
            _changed=1
            log "[ OK ] $d: wrote $policy_file (mode: testing, mx: $expected_mx)."
            continue
        fi

        actual_mx="$(grep -E '^mx:' "$policy_file" | awk '{print $2}')"
        if [[ "$actual_mx" == "$expected_mx" ]]; then
            log "[ OK ] $d: $policy_file already has the correct mx ($expected_mx) - left as-is."
            continue
        fi

        mode="$(grep -E '^mode:' "$policy_file" | awk '{print $2}')"
        max_age="$(grep -E '^max_age:' "$policy_file" | awk '{print $2}')"
        mode="${mode:-testing}"
        max_age="${max_age:-$DEFAULT_MAX_AGE}"

        backup_file "$policy_file"
        printf 'version: STSv1\nmode: %s\nmx: %s\nmax_age: %s\n' "$mode" "$expected_mx" "$max_age" > "$policy_file"
        chmod 0644 "$policy_file"
        finalize_backup "$policy_file"
        _changed=1
        log "[FIX ] $d: $policy_file had mx '$actual_mx', corrected to '$expected_mx' (mode: $mode, max_age: $max_age preserved)."
    done

    _mta_sts_rebuild_nginx_conf "${domains[@]}"

    if [[ "$_changed" -eq 1 ]]; then
        nginx -t || die "nginx -t failed after the MTA-STS config change."
        systemctl reload nginx || die "nginx did not reload."
        log "[ OK ] nginx reloaded."
    else
        log "[ OK ] Nothing needed fixing."
    fi
}

# ============================================================
# cmd_enforce <domain>: promote one domain's own policy file from
# "testing" to "enforce", preserving mx/max_age exactly - the one
# deliberate, single-domain switch cmd_generate/cmd_reconfigure never
# make on their own (they always write/keep "testing" for anything
# they touch). A domain's own policy "id" (mta_sts_expected_txt_for(),
# used by --setup) is a hash of the policy FILE's content, so changing
# mode here also changes the id the next time --setup runs - that is
# what tells remote senders to re-fetch and notice the switch.
# ============================================================

cmd_enforce()
{
    local domain="$1" policy_file mode mx max_age
    [[ -n "$domain" ]] || die "-domain <name> is required for --enforce."
    policy_file="${POLICY_ROOT}/${domain}/.well-known/mta-sts.txt"
    [[ -f "$policy_file" ]] || die "$policy_file does not exist yet - run manage-mta-sts.sh -domain ${domain} first."

    mode="$(grep -E '^mode:' "$policy_file" | awk '{print $2}')"
    mx="$(grep -E '^mx:' "$policy_file" | awk '{print $2}')"
    max_age="$(grep -E '^max_age:' "$policy_file" | awk '{print $2}')"
    [[ -n "$mx" ]] || die "$policy_file has no mx: line - something is wrong with it, fix by hand first."
    max_age="${max_age:-$DEFAULT_MAX_AGE}"

    if [[ "$mode" == "enforce" ]]; then
        log "[ OK ] $domain: $policy_file is already in enforce mode."
        return 0
    fi

    backup_file "$policy_file"
    printf 'version: STSv1\nmode: enforce\nmx: %s\nmax_age: %s\n' "$mx" "$max_age" > "$policy_file"
    chmod 0644 "$policy_file"
    finalize_backup "$policy_file"
    log "[ OK ] $domain: $policy_file switched to enforce mode (mx: $mx, max_age: $max_age preserved)."
    log "      The policy's own id changes with its content - run --setup to publish the"
    log "      refreshed _mta-sts TXT record so remote senders detect the switch."
}

# ============================================================
# cmd_status: DNS + live-served-policy + mx-correctness check, no
# changes made. (--validate is a kept alias for this same command.)
# ============================================================

cmd_status()
{
    require_cmd resolvectl
    require_cmd curl

    local -a all_domains=()
    while read -r d; do [[ -n "$d" ]] && all_domains+=("$d"); done < <(all_active_domains)
    if [[ -n "$TARGET_DOMAIN" ]]; then
        local found=0 d
        for d in "${all_domains[@]}"; do [[ "$d" == "$TARGET_DOMAIN" ]] && { found=1; break; }; done
        [[ "$found" -eq 1 ]] || die "Domain '$TARGET_DOMAIN' is not an active grommunio domain (grommunio-admin domain list)."
        all_domains=("$TARGET_DOMAIN")
    fi

    local d failed=0 txt policy_url served expected_mx actual_mx
    local domain_out domain_failed skipped tlsrpt_txt tlsrpt_expected
    for d in "${all_domains[@]}"; do
        domain_failed=0
        skipped=0
        domain_out="$(
            txt="$(resolvectl query --type=TXT "_mta-sts.${d}" 2>/dev/null | grep -o 'v=STSv1[^"]*' || true)"
            if [[ -n "$txt" ]]; then
                okline "_mta-sts.$d TXT record found: $txt"
            else
                failline "_mta-sts.$d TXT record not found."
                echo "__FAIL__"
            fi

            tlsrpt_expected="$(tlsrpt_expected_txt_for)"
            tlsrpt_txt="$(resolvectl query --type=TXT "_smtp._tls.${d}" 2>/dev/null | grep -o 'v=TLSRPTv1[^"]*' || true)"
            if [[ -n "$tlsrpt_txt" && "$tlsrpt_txt" == "$tlsrpt_expected" ]]; then
                okline "_smtp._tls.$d TLSRPT TXT record found: $tlsrpt_txt"
            elif [[ -n "$tlsrpt_txt" ]]; then
                failline "_smtp._tls.$d TLSRPT TXT record present but does not match expected ('$tlsrpt_expected'): $tlsrpt_txt"
                echo "__FAIL__"
            else
                failline "_smtp._tls.$d TLSRPT TXT record not found - run --setup to publish it."
                echo "__FAIL__"
            fi

            if resolves_here "mta-sts.${d}"; then
                okline "mta-sts.$d resolves to this server."
                policy_url="https://mta-sts.${d}/.well-known/mta-sts.txt"
                served="$(curl -sf --max-time 5 "$policy_url" 2>/dev/null || true)"
                if [[ -n "$served" ]]; then
                    if [[ "$BRIEF" -ne 1 ]]; then
                        echo "[ OK ] Policy served at $policy_url:"
                        sed 's/^/       /' <<< "$served"
                    fi

                    expected_mx="$(policy_mx_for "$d")"
                    actual_mx="$(grep -E '^mx:' <<< "$served" | awk '{print $2}' || true)"
                    if [[ "$actual_mx" == "$expected_mx" ]]; then
                        okline "Served mx ($actual_mx) matches this domain's real MX hostname."
                    else
                        failline "Served mx is '$actual_mx', should be '$expected_mx' (run --reconfigure to fix)."
                        echo "__FAIL__"
                    fi
                else
                    failline "Could not fetch $policy_url (nginx not configured? run --all first)."
                    echo "__FAIL__"
                fi
            else
                echo "[SKIP] mta-sts.$d does not resolve to this server - not ours to serve."
                echo "__SKIP__"
            fi
        )"
        domain_failed="$(grep -c '__FAIL__' <<< "$domain_out" || true)"
        skipped="$(grep -c '__SKIP__' <<< "$domain_out" || true)"
        domain_out="$(grep -vE '__FAIL__|__SKIP__' <<< "$domain_out" || true)"
        failed=$((failed + domain_failed))
        if [[ "$domain_failed" -gt 0 || ( "$BRIEF" -ne 1 && "$skipped" -eq 0 ) ]]; then
            echo
            echo "=== $d ==="
            printf '%s\n' "$domain_out"
        fi
    done

    echo
    if [[ "$failed" -eq 0 ]]; then
        log "[ OK ] No issues found for any domain whose DNS already points here."
    else
        err "$failed issue(s) found - see [FAIL] lines above."
        return 1
    fi
}

# ============================================================
# cmd_setup: cmd_reconfigure first (so the local policy file/nginx side
# is correct and the "mx:" line can't be stale), then PUBLISHES/UPDATES
# each domain's _mta-sts TXT record via TransIP (transip_account_for()
# etc., functions/00-common.sh - same per-domain account resolution
# manage-dane.sh/manage-dkim.sh use). Degrades the same way: no TransIP
# credentials for a domain means print the exact manual record and move
# on, never crash.
# ============================================================

# mta_sts_expected_txt_for <domain>: "v=STSv1; id=<hash>" - the id is a
# truncated sha256 of the domain's own served policy FILE content, not
# a timestamp or random value, so it is deterministic and only changes
# when the policy itself does - exactly what RFC 8461 requires ("id"
# MUST change whenever the policy changes, MAY stay the same
# otherwise). Prints nothing and returns 1 if the policy file doesn't
# exist yet (cmd_setup always runs cmd_reconfigure first, so this
# should not normally happen).
mta_sts_expected_txt_for()
{
    local domain="$1"
    local policy_file="${POLICY_ROOT}/${domain}/.well-known/mta-sts.txt" id
    [[ -f "$policy_file" ]] || return 1
    id="$(sha256sum "$policy_file" | cut -c1-20)"
    echo "v=STSv1; id=${id}"
}

setup_mta_sts_txt()
{
    local dom="$1" name="_mta-sts"
    local expected actual="" dns_out live_ttl user key_file

    expected="$(mta_sts_expected_txt_for "$dom")" || { err "${name}.${dom}: no local policy file yet - this should not happen after --reconfigure."; return 1; }

    if dns_out="$(resolvectl query --type=TXT "${name}.${dom}" 2>/dev/null)"; then
        actual="$(grep -o 'v=STSv1[^"]*' <<< "$dns_out" | head -1 || true)"
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
            add "$dom" "$name" TXT "$expected" --ttl "$MTA_STS_DEFAULT_TTL"
        log "[ OK ] Published ${name}.${dom}."
        log "      TTL is ${MTA_STS_DEFAULT_TTL}s - resolvers (including this server's own"
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

# ============================================================
# TLSRPT (RFC 8460) - see the header comment at the top of this file
# for why this lives here alongside MTA-STS. One centralized rua
# address for every domain, no per-domain policy file to hash (the
# expected value is static unless the rua address itself changes), and
# no wanted_domains() gate - applies to every active domain regardless
# of whether this server also hosts that domain's mta-sts.<domain>
# policy page.
# ============================================================

tlsrpt_rua_address()
{
    echo "postmaster@$(first_active_domain)"
}

tlsrpt_expected_txt_for()
{
    echo "v=TLSRPTv1; rua=mailto:$(tlsrpt_rua_address)"
}

setup_tlsrpt_txt()
{
    local dom="$1" name="_smtp._tls"
    local expected actual="" dns_out live_ttl user key_file

    expected="$(tlsrpt_expected_txt_for)"

    if dns_out="$(resolvectl query --type=TXT "${name}.${dom}" 2>/dev/null)"; then
        actual="$(grep -o 'v=TLSRPTv1[^"]*' <<< "$dns_out" | head -1 || true)"
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
            add "$dom" "$name" TXT "$expected" --ttl "$TLSRPT_DEFAULT_TTL"
        log "[ OK ] Published ${name}.${dom}."
        log "      TTL is ${TLSRPT_DEFAULT_TTL}s - resolvers (including this server's own"
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

cmd_setup()
{
    require_cmd resolvectl

    # Scope to just TARGET_DOMAIN when given (-domain <name> --setup) -
    # added 2026-11-19 after a real incident in manage-dkim.sh's own
    # --setup where this exact flag combination was typed expecting one
    # domain and every domain got touched instead, because neither
    # script's cmd_setup looked at TARGET_DOMAIN at all. Omitting
    # -domain always means every active domain - and now always asks
    # first (confirm_all_domains, functions/00-common.sh), listing the
    # exact domains that are about to get real DNS writes.
    local -a all_domains=()
    while read -r d; do [[ -n "$d" ]] && all_domains+=("$d"); done < <(all_active_domains)
    [[ "${#all_domains[@]}" -gt 0 ]] || die "No active domains found (grommunio-admin domain list)."

    if [[ -n "$TARGET_DOMAIN" ]]; then
        local found=0 d
        for d in "${all_domains[@]}"; do [[ "$d" == "$TARGET_DOMAIN" ]] && { found=1; break; }; done
        [[ "$found" -eq 1 ]] || die "Domain '$TARGET_DOMAIN' is not an active grommunio domain (grommunio-admin domain list)."
        all_domains=("$TARGET_DOMAIN")
    else
        confirm_all_domains "publish/update _mta-sts and _smtp._tls (TLSRPT) DNS records" "${all_domains[@]}"
    fi

    [[ "$BRIEF" -eq 1 ]] || log "Running --reconfigure first, so the local policy/mx side is correct..."
    cmd_reconfigure "$TARGET_DOMAIN"

    local -a domains=()
    while read -r d; do [[ -n "$d" ]] && domains+=("$d"); done < <(wanted_domains)
    if [[ -n "$TARGET_DOMAIN" ]]; then
        if printf '%s\n' "${domains[@]}" | grep -qxF "$TARGET_DOMAIN"; then
            domains=("$TARGET_DOMAIN")
        else
            log "[SKIP] ${TARGET_DOMAIN}: mta-sts.${TARGET_DOMAIN} does not resolve here - no _mta-sts TXT to publish for it, only _smtp._tls (TLSRPT) below."
            domains=()
        fi
    elif [[ "${#domains[@]}" -eq 0 ]]; then
        log "[SKIP] No mta-sts.<domain> hostname resolves to this server - no _mta-sts TXT to publish for any domain, only _smtp._tls (TLSRPT) below."
    fi

    local d failed=0 domain_out domain_failed
    for d in "${domains[@]}"; do
        domain_out="$(setup_mta_sts_txt "$d" 2>&1)" && domain_failed=0 || domain_failed=1
        failed=$((failed + domain_failed))
        if [[ "$domain_failed" -eq 1 || "$BRIEF" -ne 1 ]]; then
            echo
            echo "=== $d ==="
            printf '%s\n' "$domain_out"
        fi
    done

    local tlsrpt_failed=0
    for d in "${all_domains[@]}"; do
        domain_out="$(setup_tlsrpt_txt "$d" 2>&1)" && domain_failed=0 || domain_failed=1
        tlsrpt_failed=$((tlsrpt_failed + domain_failed))
        if [[ "$domain_failed" -eq 1 || "$BRIEF" -ne 1 ]]; then
            echo
            echo "=== $d (TLSRPT) ==="
            printf '%s\n' "$domain_out"
        fi
    done
    failed=$((failed + tlsrpt_failed))

    echo
    if [[ "$failed" -eq 0 ]]; then
        log "[ OK ] _mta-sts TXT published/up to date for ${#domains[@]} domain(s); _smtp._tls TLSRPT TXT published/up to date for ${#all_domains[@]} domain(s)."
    else
        err "$failed record(s) could not be published/updated automatically - see error lines above."
        return 1
    fi
}

# ============================================================
# cmd_report: standalone, copy-paste-friendly DNS record block for
# every domain this server actually serves MTA-STS for - not a check,
# just "what to publish", matching check-dns.sh --report's own spirit
# but scoped to only what THIS script manages (_mta-sts TXT).
# ============================================================

cmd_report()
{
    require_cmd resolvectl

    local -a domains=()
    while read -r d; do [[ -n "$d" ]] && domains+=("$d"); done < <(wanted_domains)
    if [[ -n "$TARGET_DOMAIN" ]]; then
        if printf '%s\n' "${domains[@]}" | grep -qxF "$TARGET_DOMAIN"; then
            domains=("$TARGET_DOMAIN")
        else
            domains=()
        fi
    fi

    local d expected
    if [[ "${#domains[@]}" -eq 0 ]]; then
        log "No mta-sts.<domain> hostname resolves to this server - nothing to report for MTA-STS."
    else
        for d in "${domains[@]}"; do
            expected="$(mta_sts_expected_txt_for "$d")" || { err "${d}: no local policy file yet - run --all first."; continue; }
            echo "MTA-STS record for ${d}"
            echo "========================"
            echo
            echo "  Name:  _mta-sts.${d}"
            echo "  Type:  TXT"
            echo "  Value: \"${expected}\""
            echo
        done
    fi

    local -a all_domains=()
    while read -r d; do [[ -n "$d" ]] && all_domains+=("$d"); done < <(all_active_domains)
    [[ "${#all_domains[@]}" -gt 0 ]] || die "No active domains found (grommunio-admin domain list) - nothing to report."
    if [[ -n "$TARGET_DOMAIN" ]]; then
        local found=0 d
        for d in "${all_domains[@]}"; do [[ "$d" == "$TARGET_DOMAIN" ]] && { found=1; break; }; done
        [[ "$found" -eq 1 ]] || die "Domain '$TARGET_DOMAIN' is not an active grommunio domain (grommunio-admin domain list)."
        all_domains=("$TARGET_DOMAIN")
    fi

    expected="$(tlsrpt_expected_txt_for)"
    for d in "${all_domains[@]}"; do
        echo "TLSRPT record for ${d}"
        echo "========================"
        echo
        echo "  Name:  _smtp._tls.${d}"
        echo "  Type:  TXT"
        echo "  Value: \"${expected}\""
        echo
    done

    echo "Publish these exact records at your DNS registrar."
    echo "Re-run manage-mta-sts.sh --status afterward to confirm they match."
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
            ACTION="status"; shift ;;
        --reconfigure)
            ACTION="reconfigure"; shift ;;
        --enforce)
            ACTION="enforce"; shift ;;
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
            echo "manage-mta-sts.sh: unknown option: $1 (see --help)" >&2
            exit 1 ;;
    esac
done

require_root
require_cmd grommunio-admin

run_action()
{
    case "$ACTION" in
        all)
            cmd_generate
            ;;
        domain)
            mapfile -t ALL_DOMAINS < <(all_active_domains)
            found=0
            for a in "${ALL_DOMAINS[@]}"; do [[ "$a" == "$TARGET_DOMAIN" ]] && { found=1; break; }; done
            [[ "$found" -eq 1 ]] || die "Domain '$TARGET_DOMAIN' is not an active grommunio domain (grommunio-admin domain list)."
            resolves_here "mta-sts.$TARGET_DOMAIN" || die "mta-sts.$TARGET_DOMAIN does not resolve to this server."
            cmd_generate "$TARGET_DOMAIN"
            ;;
        status)
            cmd_status
            ;;
        reconfigure)
            cmd_reconfigure "$TARGET_DOMAIN"
            ;;
        enforce)
            [[ -n "$TARGET_DOMAIN" ]] || die "--enforce requires -domain <name>."
            cmd_enforce "$TARGET_DOMAIN"
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
    send_report_mail "$MAIL_TO" "manage-mta-sts.sh ${ACTION}" "$OUTPUT"
    log "[ OK ] Report mailed to ${MAIL_TO}."
else
    run_action
fi
