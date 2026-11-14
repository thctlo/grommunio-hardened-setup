#!/usr/bin/env bash
#
# check-dns.sh
#
# Standalone, read-only DNS audit against /srv/build/docs/dns-records-reference.md's
# checklist (A/AAAA, MX, SPF, DKIM, DMARC, TLSRPT, MTA-STS, DANE, CAA,
# autoconfig/autodiscover, CalDAV/CardDAV, IMAP/POP3/submission SRV).
# Deliberately NOT part of server-setup.sh's pipeline, and deliberately
# never changes anything - DNS records live at the registrar, not on
# this server (the MTA-STS check does fetch the live policy file over
# HTTPS to confirm it is actually served, but that is still read-only).
#
# Fully registrar-agnostic: this script never writes DNS, only queries
# it (resolvectl/dig), so it works identically no matter which registrar
# or DNS provider is actually in use.
#
# Scope, by explicit request: only domains actually hosted on THIS server
# (their bare domain or mail.<domain> resolves to this server's own saved
# primary address(es), from step 10's config) are checked at all. A server
# hosting several domains will often also have older/other domains in its
# domain list whose production MX is hosted elsewhere - those are skipped
# entirely, not checked against this server's own IP (see manage-certs.sh
# for the same scoping decision and why).
#
# MX is checked for "resolves to this server", not "equals mail.<domain>"
# literally - found live 2026-10-25 on a server hosting several domains:
# a secondary domain's real MX pointed to the FIRST domain's mail
# hostname (a shared hostname across domains on one server), not its own
# mail.<domain>. Both are valid; only resolution to this server is
# actually required.
#
# Usage (run as root on the mail server itself, not the build host):
#   check-dns.sh                        Show this help (no arguments = help).
#   check-dns.sh --all                  Check every domain hosted on this server.
#   check-dns.sh -domain <name>         Check just this one domain (must be hosted here).
#   check-dns.sh --all --brief          Same, but short: only [FAIL]/[WARN]
#                                        lines and a one-line summary per
#                                        domain, no [ OK ] lines or section
#                                        headers. Combine with -domain too.
#   check-dns.sh --report <domain>      Not a check - prints a clean,
#                                        self-contained DNS setup guide for
#                                        <domain> (any domain, does not need
#                                        to be hosted here yet), with this
#                                        server's real IPs filled in, and
#                                        the domain's CURRENT live MX (if
#                                        any) alongside the recommendation.
#                                        Meant to be copy-pasted or emailed
#                                        as-is to whoever manages that
#                                        domain's DNS.
#   check-dns.sh --firstdomain          Checks THIS SERVER's own PTR
#                                        (reverse DNS), forward-confirmed
#                                        reverse DNS (FCrDNS), and whether
#                                        the PTR matches this server's own
#                                        saved hostname (NEW_FQDN, from
#                                        step 10) - no domain argument,
#                                        this is about the server's own
#                                        identity, not any one hosted
#                                        domain. Runs fine before step 10
#                                        too (auto-detects the primary
#                                        IPv4/IPv6 via the default route
#                                        if step 10 hasn't saved one yet;
#                                        the hostname-match check just
#                                        gets skipped with a note). See
#                                        dns-records-reference.md for why
#                                        this identity matters for
#                                        DANE/mx1 on whichever domain
#                                        happens to share it.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/functions/00-common.sh"

NET_CFG="$(cfg_file 10-network-hostname)"
NEW_FQDN="" NEW_DOMAIN="" PRIMARY_IPV4="" PRIMARY_IPV6=""
[[ -f "$NET_CFG" ]] && source "$NET_CFG"

# Auto-detect the primary IPv4/IPv6 when step 10 hasn't run yet (its own
# saved config always wins when present - this only fills a gap, never
# overrides it). This script is explicitly meant to be runnable BEFORE
# server-setup.sh (see docs/INSTALL.md's Quick Start: "confirm your
# server's own DNS identity is already correct" before running anything
# else) - found live 2026-11-14 that a truly fresh clone hard-failed
# here instead. `ip route get` only consults the routing table (no
# packet sent), same default-route logic step 10 itself uses to find
# the primary interface, just non-interactive (one address, not a user
# choice among several) - fine for this read-only check; nothing here
# is saved to disk.
if [[ -z "$PRIMARY_IPV4" ]]; then
    PRIMARY_IPV4="$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || true)"
    [[ -n "$PRIMARY_IPV4" ]] && log "Auto-detected primary IPv4: ${PRIMARY_IPV4} (step 10 has not saved one yet)."
fi
if [[ -z "$PRIMARY_IPV6" ]]; then
    PRIMARY_IPV6="$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | grep -oP 'src \K\S+' || true)"
    [[ -n "$PRIMARY_IPV6" ]] && log "Auto-detected primary IPv6: ${PRIMARY_IPV6} (step 10 has not saved one yet)."
fi

# Same idea for NEW_FQDN: a PTR lookup on the address just found above -
# exactly what step 10 itself would determine as this server's own
# hostname. Without this, cmd_report's own mx1-vs-mail decision (see
# there - identical check to 31-grommunio-domain.sh's
# hint_dedicated_mx_if_needed) can never fire before step 10 has run,
# even though the PTR record needed to make that call already exists
# and is exactly what --firstdomain itself checks. Found live
# 2026-11-14: --report on the domain that will become the first one
# didn't show the mx1 records it should have, pre-install.
if [[ -z "${NEW_FQDN:-}" ]]; then
    ptr_out=""
    [[ -n "$PRIMARY_IPV4" ]] && ptr_out="$(resolvectl query "$PRIMARY_IPV4" 2>/dev/null | head -n1)"
    [[ -z "$ptr_out" && -n "$PRIMARY_IPV6" ]] && ptr_out="$(resolvectl query "$PRIMARY_IPV6" 2>/dev/null | head -n1)"
    if [[ "$ptr_out" == *": "* ]]; then
        NEW_FQDN="$(sed -E 's/^[^:]+:[[:space:]]*//; s/[[:space:]]+--.*$//; s/[[:space:]]+$//; s/\.$//' <<< "$ptr_out")"
        [[ -n "$NEW_FQDN" ]] && log "Auto-detected this server's hostname from its own PTR record: ${NEW_FQDN} (step 10 has not saved one yet)."
    fi
    unset ptr_out
fi

RSPAMD_DKIM_DIR="/var/lib/rspamd/dkim"

# TLSRPT reports are centralized to one address for every domain on this
# server, by explicit choice (2026-10-30) - not per-domain postmaster@, one
# shared mailbox everything lands in.
TLSRPT_RUA="postmaster@${NEW_DOMAIN:-example.com}"

FAIL_COUNT=0
WARN_COUNT=0
BRIEF_MODE=0

show_help()
{
    sed -n '3,57p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# Colour only when writing to an actual terminal - never pollutes a
# redirected log/pipe with escape codes.
if [[ -t 1 ]]; then
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RESET=$'\033[0m'
else
    C_RED=""; C_GREEN=""; C_YELLOW=""; C_RESET=""
fi

# Required (A/AAAA, MX, SPF, DKIM, DMARC, autodiscover CNAME+SRV) use
# ok()/fail() - green/red, and fail() counts towards the script's
# overall exit status: these either break mail delivery/anti-spoofing
# outright, or (autodiscover specifically) are part of the same
# Microsoft Autodiscover protocol grommunio-sync/ActiveSync itself uses
# for client setup. Genuinely optional extras (TLSRPT, CAA, autoconfig,
# CalDAV/CardDAV, and the RFC 6186 IMAP/POP3/submission SRV records) use
# warn() instead - orange, counted separately, never fails the overall
# run on their own: nothing in grommunio depends on any of these,
# manual client configuration always works regardless. Revised
# 2026-11-05 - an earlier 2026-11-04 version of this comment
# incorrectly assumed autoconfig and the RFC 6186 SRV records were part
# of the same mechanism autodiscover uses; they are three independent,
# unrelated discovery paths.
ok()   { [[ "$BRIEF_MODE" -eq 1 ]] || echo "${C_GREEN}[ OK ]${C_RESET} $*"; }
fail() { echo "${C_RED}[FAIL]${C_RESET} $*"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
warn() { echo "${C_YELLOW}[WARN]${C_RESET} $*"; WARN_COUNT=$((WARN_COUNT + 1)); }

# Section headers (the "--- A/AAAA ---" lines) are suppressed in report
# mode too - with every [ OK ] line gone, they would be dangling labels
# with nothing under them most of the time.
section() { [[ "$BRIEF_MODE" -eq 1 ]] || echo "--- $* ---"; }

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

normalize_dkim_value()
{
    tr -d '\n' <<< "$1" | grep -oE '"[^"]*"' | tr -d '"' | tr -d '\n' | sed -E 's/;[[:space:]]*p=/; p=/; s/[[:space:]]+/ /g'
}

all_active_domains()
{
    grommunio-admin domain list 2>/dev/null | sed -nE 's/^[0-9]+: ([^ ]+) \(active\).*/\1/p'
}

hosted_domains()
{
    local d
    while read -r d; do
        [[ -n "$d" ]] || continue
        if resolves_here "$d" || resolves_here "mail.$d"; then
            echo "$d"
        fi
    done < <(all_active_domains)
}

# ============================================================
# Individual checks. Each prints its own [ OK ]/[FAIL]/[WARN] line(s).
# ============================================================

check_a_aaaa()
{
    local host="$1" label="$2"
    if resolves_here "$host"; then
        ok "$label ($host) resolves to this server."
    else
        fail "$label ($host) does not resolve to this server's primary address."
    fi
}

check_mx()
{
    local dom="$1" out target
    if ! out="$(resolvectl query --type=MX "$dom" 2>/dev/null)"; then
        fail "MX for $dom: no record found."
        return
    fi
    target="$(sed -nE 's/^[^ ]+ IN MX [0-9]+ ([^ ]+).*/\1/p' <<< "$(head -n1 <<< "$out")")"
    target="${target%.}"
    if [[ -z "$target" ]]; then
        fail "MX for $dom: record found but has no target (null MX?)."
    elif resolves_here "$target"; then
        ok "MX for $dom -> $target (resolves to this server)."
    else
        fail "MX for $dom -> $target, which does NOT resolve to this server."
    fi
}

check_spf()
{
    # mail.<domain> can be a local /etc/hosts entry (true for this
    # server's own primary hostname) - once a name is in /etc/hosts,
    # systemd-resolved answers EVERY query for it locally, including
    # non-address types it cannot actually provide, as a flat "no RR of
    # the requested type" rather than falling through to real DNS. That
    # looked exactly like a missing record even though the TXT record
    # was genuinely published - found 2026-11-05, confirmed by the same
    # query against an external resolver (1.1.1.1) finding it fine.
    # Falling back to that external resolver here avoids this one known
    # local-resolution blind spot, for this check only (the only one
    # actually hit by it so far).
    local host="$1" out value
    if ! out="$(resolvectl query --type=TXT "$host" 2>/dev/null)"; then
        if ! out="$(dig +short TXT "$host" @1.1.1.1 2>/dev/null)" || [[ -z "$out" ]]; then
            fail "SPF for $host: no TXT record found."
            return
        fi
    fi
    value="$(normalize_dkim_value "$out")"
    if [[ "$value" != v=spf1* ]]; then
        fail "SPF for $host: no v=spf1 TXT record among what DNS returned."
        return
    fi
    # RFC 7208 has no preferred mechanism - mx/a/ip4/ip6/include are all
    # equally valid, and grommunio never reads its own domain's SPF
    # record anyway (SPF is checked by OTHER servers about mail claiming
    # to be from us, not by gromox/postfix itself). Any mechanism set
    # that ends in an explicit qualifier is fine; only a record with no
    # terminating "all" mechanism is worth flagging.
    if [[ "$value" =~ [[:space:]][-~?+]?all$ ]]; then
        ok "SPF for $host: $value"
    else
        warn "SPF for $host present but has no terminating 'all' mechanism: $value"
    fi
}

check_dmarc()
{
    local dom="$1" out value
    if ! out="$(resolvectl query --type=TXT "_dmarc.${dom}" 2>/dev/null)"; then
        fail "DMARC for $dom: no _dmarc TXT record found."
        return
    fi
    value="$(normalize_dkim_value "$out")"
    if [[ "$value" == v=DMARC1* ]]; then
        ok "DMARC for $dom: $value"
    else
        warn "DMARC for $dom present but does not start with v=DMARC1: $value"
    fi
}

check_tlsrpt()
{
    local dom="$1" out value expect
    expect="v=TLSRPTv1; rua=mailto:${TLSRPT_RUA}"
    if ! out="$(resolvectl query --type=TXT "_smtp._tls.${dom}" 2>/dev/null)"; then
        warn "_smtp._tls.${dom}: no TLSRPT TXT record found - optional, reporting only."
        return
    fi
    value="$(normalize_dkim_value "$out")"
    if [[ "$value" == "$expect" ]]; then
        ok "_smtp._tls.${dom}: $value"
    else
        warn "_smtp._tls.${dom} present but does not match the expected '$expect': $value"
    fi
}

# Optional - recommended hardening, not required for mail to work.
# Mirrors manage-mta-sts.sh --validate's own checks, at the same depth
# (DNS + the live-served policy itself), kept here too so the ordinary
# DNS audit catches drift without having to remember a second tool.
check_mta_sts()
{
    # The TXT advertisement, the A/AAAA of the policy host, and the
    # live-served policy are three independent things to get right -
    # each is checked and reported regardless of whether an earlier one
    # failed. Found 2026-11-05: an earlier version returned
    # right after a missing/bad TXT record, so A/AAAA never even got
    # checked for a domain that had set those up but not yet published
    # the TXT - every other check in this script reports everything it
    # can, this one should too.
    local dom="$1" out txt policy_url served v4 v6

    if out="$(resolvectl query --type=TXT "_mta-sts.${dom}" 2>/dev/null)"; then
        txt="$(normalize_dkim_value "$out")"
        if [[ "$txt" == v=STSv1* ]]; then
            ok "_mta-sts.${dom}: $txt"
        else
            warn "_mta-sts.${dom} present but does not start with v=STSv1: $txt"
        fi
    else
        warn "_mta-sts.${dom}: no TXT record found - optional, but recommended."
    fi

    # Checked as separate A/AAAA, not the combined resolves_here() used
    # elsewhere - that one is satisfied by EITHER matching (OR logic),
    # so a host missing AAAA entirely but with a correct A record would
    # silently pass it. A receiving mail server validating MTA-STS over
    # IPv6-only connectivity would otherwise fail to fetch the policy
    # with no warning from this script at all.
    v4="$(resolvectl query --type=A "mta-sts.${dom}" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    v6="$(resolvectl query --type=AAAA "mta-sts.${dom}" 2>/dev/null | grep -oE '[0-9a-fA-F:]+:[0-9a-fA-F:]+' | head -1 || true)"
    if [[ -n "$PRIMARY_IPV4" ]]; then
        if [[ "$v4" == "$PRIMARY_IPV4" ]]; then
            ok "mta-sts.${dom} A record resolves to this server."
        else
            warn "mta-sts.${dom} has no matching A record (found: ${v4:-<none>})."
        fi
    fi
    if [[ -n "$PRIMARY_IPV6" ]]; then
        if [[ "$v6" == "$PRIMARY_IPV6" ]]; then
            ok "mta-sts.${dom} AAAA record resolves to this server."
        else
            warn "mta-sts.${dom} has no matching AAAA record (found: ${v6:-<none>})."
        fi
    fi
    if [[ -z "$v4" && -z "$v6" ]]; then
        warn "mta-sts.${dom} does not resolve at all - the policy below cannot be fetched."
        return
    fi

    policy_url="https://mta-sts.${dom}/.well-known/mta-sts.txt"
    served="$(curl -sf --max-time 5 "$policy_url" 2>/dev/null || true)"
    if [[ -z "$served" ]]; then
        warn "Could not fetch ${policy_url} (run manage-mta-sts.sh -domain ${dom})."
        return
    fi
    if grep -q '^mode: *enforce' <<< "$served"; then
        ok "Policy served at ${policy_url} (mode: enforce)."
    elif grep -q '^mode:' <<< "$served"; then
        warn "Policy served at ${policy_url} but not in enforce mode: $(grep '^mode:' <<< "$served")"
    else
        warn "Policy served at ${policy_url} but has no recognizable 'mode:' line."
    fi
}

# Optional - recommended hardening, not required for mail to work.
# Checked against the MX target actually in use (same "resolves"
# philosophy as check_mx()/check_srv() above - not a literal hostname
# match), since that is the name DANE/TLSA is looked up by.
check_dane()
{
    local dom="$1" cert="/etc/letsencrypt/live/${NEW_FQDN:-mail.example.com}/cert.pem" out target tlsa_live want_hash
    if ! out="$(resolvectl query --type=MX "$dom" 2>/dev/null)"; then
        warn "DANE for $dom: no MX record, cannot determine which hostname to check TLSA on."
        return
    fi
    target="$(sed -nE 's/^[^ ]+ IN MX [0-9]+ ([^ ]+).*/\1/p' <<< "$(head -n1 <<< "$out")")"
    target="${target%.}"
    [[ -n "$target" ]] || { warn "DANE for $dom: MX record has no target."; return; }

    # resolvectl exits non-zero when nothing is found (same as every
    # other query in this script) - guarded explicitly here too, or
    # `set -o pipefail` would kill the whole script the moment ANY
    # domain genuinely has no TLSA record, not just warn about it.
    if ! out="$(resolvectl query --type=TLSA "_25._tcp.${target}" 2>/dev/null)"; then
        warn "DANE for $dom: no TLSA record at _25._tcp.${target} - optional, but recommended (see manage-dane.sh)."
        return
    fi
    tlsa_live="$(grep -oE '[0-9]+ [0-9]+ [0-9]+ [0-9a-fA-F]+' <<< "$out" | head -1)"
    if [[ -z "$tlsa_live" ]]; then
        warn "DANE for $dom: no TLSA record at _25._tcp.${target} - optional, but recommended (see manage-dane.sh)."
        return
    fi
    if [[ -f "$cert" ]]; then
        want_hash="$(openssl x509 -in "$cert" -noout -pubkey 2>/dev/null \
            | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -hex | sed 's/^.*= //')"
        if grep -qiF "$want_hash" <<< "$tlsa_live"; then
            ok "DANE for $dom: TLSA at _25._tcp.${target} matches the current certificate."
        else
            warn "DANE for $dom: TLSA at _25._tcp.${target} does NOT match the current certificate - stale? ($tlsa_live)"
        fi
    else
        ok "DANE for $dom: TLSA record found at _25._tcp.${target} ($tlsa_live) - could not verify it matches the certificate (not found at $cert)."
    fi
}

# Optional - recommended, not required for mail to work. systemd-resolved
# on this server has DNSSEC validation globally OFF ("resolvectl dnssec"
# -> "Global: no"), so its own "Data is authenticated:" flag is always
# "no" regardless of whether a domain is actually signed - useless as a
# check here. Uses an external, validating resolver (1.1.1.1) instead
# and looks for the "ad" (Authenticated Data) flag in its reply, the
# same fallback-resolver approach check_spf() already uses for its own
# different local blind spot.
check_dnssec()
{
    local dom="$1" flags
    flags="$(dig +dnssec "$dom" A @1.1.1.1 2>/dev/null | grep -oE '^;; flags:[^;]*')"
    if grep -qw "ad" <<< "$flags"; then
        ok "DNSSEC for $dom: validated (ad flag set by an external validating resolver)."
    else
        warn "DNSSEC for $dom: not validated (no ad flag) - optional, but recommended; ask the registrar to enable zone signing."
    fi
}

check_caa()
{
    local dom="$1" out
    if ! out="$(resolvectl query --type=CAA "$dom" 2>/dev/null)"; then
        warn "CAA for $dom: no record found (any CA may issue certificates) - optional, defense-in-depth only."
        return
    fi
    if grep -qE 'CAA 0 issue "letsencrypt\.org"' <<< "$out"; then
        ok "CAA for $dom: issue letsencrypt.org present."
    else
        warn "CAA for $dom: no 'issue \"letsencrypt.org\"' record found."
    fi
    if grep -qE 'CAA 128 issuewild "letsencrypt\.org"' <<< "$out"; then
        ok "CAA for $dom: issuewild letsencrypt.org present."
    else
        warn "CAA for $dom: no 'issuewild \"letsencrypt.org\"' record found (only matters if wildcard certs are ever issued)."
    fi
}

check_cname()
{
    local host="$1" expected="$2" severity="${3:-fail}" out actual
    expected="${expected%.}"
    if ! out="$(resolvectl query --type=CNAME "$host" 2>/dev/null)"; then
        "$severity" "$host: no CNAME record found."
        return
    fi
    actual="$(sed -nE 's/^.*IN[[:space:]]+CNAME[[:space:]]+([^[:space:]]+).*/\1/p' <<< "$out" | sed 's/\.$//')"
    if [[ "$actual" == "$expected" ]]; then
        ok "$host: CNAME to $expected."
    else
        "$severity" "$host: expected CNAME to $expected, found: ${actual:-<none>}"
    fi
}

check_srv()
{
    # Checked by resolution, not literal target string - same principle
    # as check_mx(): RFC 6186/6764 (the specs that define these SRV
    # records) never mandate a specific target hostname, only that it
    # resolves to a host actually serving that port. Found 2026-11-05:
    # a domain whose SRV targets were its own bare domain (not
    # mail.<domain>) still worked completely fine, because that bare
    # domain resolves to this same server and the certificate's SAN
    # list already covers it too (checked, not assumed) - the client
    # connects to the right place and gets valid TLS either way.
    local name="$1" expect_port="$2" expect_hint="$3" severity="${4:-fail}" out line prio weight port target
    if ! out="$(resolvectl query --type=SRV "$name" 2>/dev/null)"; then
        "$severity" "$name: no SRV record found."
        return
    fi
    line="$(head -n1 <<< "$out")"
    read -r prio weight port target <<< "$(sed -nE 's/^[^ ]+ IN SRV ([0-9]+) ([0-9]+) ([0-9]+) ([^ ]+).*/\1 \2 \3 \4/p' <<< "$line")"
    target="${target%.}"
    if [[ "$port" == "$expect_port" ]] && resolves_here "$target"; then
        ok "$name: SRV $prio $weight $port $target (resolves to this server)"
    else
        "$severity" "$name: expected port $expect_port -> a host resolving to this server (e.g. $expect_hint), found port ${port:-?} -> ${target:-<none>}"
    fi
}

check_caldav_set()
{
    # CalDAV/CardDAV discovery is optional - a client that can't find
    # these just needs its account added manually, same as any other
    # provider without auto-discovery.
    local svc="$1" dom="$2" mailhost="$3" port="$4" out value
    if out="$(resolvectl query --type=TXT "_${svc}._tcp.${dom}" 2>/dev/null)"; then
        value="$(normalize_dkim_value "$out")"
        if [[ "$value" == "https://${mailhost}/dav" ]]; then
            ok "_${svc}._tcp.${dom} TXT: $value"
        else
            warn "_${svc}._tcp.${dom} TXT present but unexpected: $value"
        fi
    else
        warn "_${svc}._tcp.${dom}: no TXT record found - optional."
    fi
    check_srv "_${svc}._tcp.${dom}" "$port" "$mailhost" warn
}

check_dkim_selector()
{
    local dom="$1" sel="$2" txt_file expected out actual
    txt_file="$RSPAMD_DKIM_DIR/$dom.$sel.txt"
    if [[ ! -f "$txt_file" ]]; then
        warn "${sel}._domainkey.${dom}: no local key generated yet (run manage-dkim.sh)."
        return
    fi
    expected="$(normalize_dkim_value "$(cat "$txt_file")")"
    if ! out="$(resolvectl query --type=TXT "${sel}._domainkey.${dom}" 2>/dev/null)"; then
        fail "${sel}._domainkey.${dom}: no TXT record found."
        return
    fi
    actual="$(normalize_dkim_value "$out")"
    if [[ "$actual" == "$expected" ]]; then
        ok "${sel}._domainkey.${dom}: matches local key."
    else
        fail "${sel}._domainkey.${dom}: DNS value does not match the local key."
    fi
}

# ============================================================
# Per-domain full checklist
# ============================================================

check_domain()
{
    local dom="$1"
    local mailhost="mail.${dom}"
    local fail_before="$FAIL_COUNT" warn_before="$WARN_COUNT"

    echo
    echo "=== $dom ==="

    section "A/AAAA"
    check_a_aaaa "$dom" "bare domain"
    check_a_aaaa "$mailhost" "mail host"

    section "MX"
    check_mx "$dom"

    section "SPF"
    check_spf "$dom"
    check_spf "$mailhost"

    section "DKIM"
    check_dkim_selector "$dom" "dkim-ed"
    check_dkim_selector "$dom" "dkim-rsa"
    check_cname "dkim._domainkey.${dom}" "dkim-rsa._domainkey.${dom}"

    section "DMARC"
    check_dmarc "$dom"

    section "TLSRPT"
    check_tlsrpt "$dom"

    section "MTA-STS"
    check_mta_sts "$dom"

    section "DANE"
    check_dane "$dom"

    section "DNSSEC"
    check_dnssec "$dom"

    section "CAA"
    check_caa "$dom"

    # autodiscover (CNAME + SRV) is required - it is part of the same
    # Microsoft Autodiscover protocol grommunio-sync (ActiveSync) itself
    # uses for client setup. autoconfig (Mozilla's own, separate,
    # self-contained XML mechanism - Thunderbird-style clients only) and
    # the RFC 6186 IMAP/POP3/submission SRV records below are each
    # independent, optional discovery paths that nothing in grommunio
    # actually depends on - manual client configuration always works
    # regardless. Decided 2026-11-05, superseding the 2026-11-04 note
    # above that had conflated these two mechanisms.
    section "Mail client autoconfiguration"
    check_cname "autoconfig.${dom}" "$mailhost" warn
    check_cname "autodiscover.${dom}" "$mailhost"
    check_srv "_autodiscover._tcp.${dom}" 443 "$mailhost"

    section "CalDAV/CardDAV"
    check_caldav_set "caldav" "$dom" "$mailhost" 443
    check_caldav_set "caldavs" "$dom" "$mailhost" 443
    check_caldav_set "carddav" "$dom" "$mailhost" 443
    check_caldav_set "carddavs" "$dom" "$mailhost" 443

    section "Mail protocol service discovery (RFC 6186, optional)"
    check_srv "_imap._tcp.${dom}" 143 "$mailhost" warn
    check_srv "_imaps._tcp.${dom}" 993 "$mailhost" warn
    check_srv "_pop3._tcp.${dom}" 110 "$mailhost" warn
    check_srv "_pop3s._tcp.${dom}" 995 "$mailhost" warn
    check_srv "_submission._tcp.${dom}" 587 "$mailhost" warn
    check_srv "_submissions._tcp.${dom}" 465 "$mailhost" warn

    if [[ "$BRIEF_MODE" -eq 1 ]]; then
        local d_fail=$((FAIL_COUNT - fail_before)) d_warn=$((WARN_COUNT - warn_before))
        if [[ "$d_fail" -eq 0 && "$d_warn" -eq 0 ]]; then
            echo "${C_GREEN}$dom: OK${C_RESET}"
        else
            echo "${C_RED}$dom: ${d_fail} required issue(s), ${d_warn} optional issue(s)${C_RESET}"
        fi
    fi
}

# Prints a clean, self-contained DNS setup guide for a domain - no
# internal project history or rationale, just the records and enough
# context for an external DNS maintainer to understand why each one is
# there. Not a check: $dom does not need to be hosted here, or to exist
# in grommunio-admin at all yet - this is for setting up a BRAND NEW
# domain, before any of that happens. IPs come from this server's own
# saved primary address(es) (step 10's config) - real values, not
# placeholders.
cmd_report()
{
    local dom="$1" mailhost
    mailhost="mail.${dom}"
    [[ -n "$PRIMARY_IPV4" || -n "$PRIMARY_IPV6" ]] \
        || die "Could not determine this server's primary IPv4/IPv6 (not saved by step 10 yet, and auto-detection via 'ip route get' found nothing - check this server has a default route/network connectivity)."

    # See 31-grommunio-domain.sh's hint_dedicated_mx_if_needed (same check,
    # same reasoning): if mail.<domain> is ALSO this server's own canonical
    # hostname (found via PTR by step 10, used by Postfix as myhostname/
    # HELO), that name is the server's shared identity, not exclusive to
    # this domain - so the MX target shown below becomes mx1.<domain>
    # instead, and the DANE section explains why. If it is not this
    # server's hostname, mail.<domain> is already exclusive to this domain
    # and is used as the MX target directly, same as any other domain.
    local needs_dedicated_mx=0 mx_target="$mailhost"
    if [[ -n "${NEW_FQDN:-}" && "$NEW_FQDN" == "$mailhost" ]]; then
        needs_dedicated_mx=1
        mx_target="mx1.${dom}"
    fi

    # Unlike the rest of this function (a static suggestion list, since
    # --report explicitly supports a domain not hosted here yet), the MX
    # line is worth checking live: a domain already being migrated here
    # may already have a real MX, matching or not. A live lookup costs
    # nothing and tells the reader "already done" vs "still needed"
    # instead of only ever printing instructions. check_mx (used by
    # -domain/--all) does the same resolvectl lookup.
    local current_mx_out current_mx_target current_mx_status
    if current_mx_out="$(resolvectl query --type=MX "$dom" 2>/dev/null)"; then
        current_mx_target="$(sed -nE 's/^[^ ]+ IN MX [0-9]+ ([^ ]+).*/\1/p' <<< "$(head -n1 <<< "$current_mx_out")")"
        current_mx_target="${current_mx_target%.}"
        if [[ -z "$current_mx_target" ]]; then
            current_mx_status="currently: MX record found but has no target (null MX?)"
        elif [[ "$current_mx_target" == "$mx_target" ]]; then
            current_mx_status="currently: ${current_mx_target} - already set up as recommended"
        else
            current_mx_status="currently: ${current_mx_target} - differs from the ${mx_target} recommended below"
        fi
    else
        current_mx_status="currently: no MX record found"
    fi

    # Same reasoning as the MX id above, applied to MTA-STS's "id=" field:
    # manage-mta-sts.sh does NOT generate or manage this value (its own
    # header says so explicitly - the DNS TXT record is left entirely to
    # the admin). A hardcoded "id=1" suggestion risks being reused even
    # though RFC 8461 requires a DIFFERENT id every time the policy
    # changes for clients to refetch it. Showing the current live value
    # (if any) plus a timestamp-based suggestion that is always new and
    # never collides is more useful than a static placeholder.
    local current_sts_out current_sts_id suggested_sts_id mta_sts_status
    suggested_sts_id="$(date +%Y%m%d%H%M)"
    if current_sts_out="$(resolvectl query --type=TXT "_mta-sts.${dom}" 2>/dev/null)"; then
        current_sts_id="$(grep -oE 'id=[^";[:space:]]+' <<< "$current_sts_out" | head -1)"
        if [[ -n "$current_sts_id" ]]; then
            mta_sts_status="currently: v=STSv1; ${current_sts_id} - bump to a new id below only if the policy itself changed"
        else
            mta_sts_status="currently: a _mta-sts TXT record exists but no id= was found in it"
        fi
    else
        mta_sts_status="currently: no _mta-sts TXT record found"
    fi

    # Same "show current vs recommended" pattern as MX/MTA-STS above,
    # reusing check_dane()'s own live-verification logic (TLSA lookup at
    # _25._tcp.<mx_target>, compared against the actual certificate's
    # public key) rather than only ever printing static setup instructions.
    local dane_cert="/etc/letsencrypt/live/${NEW_FQDN:-mail.example.com}/cert.pem"
    local dane_tlsa_out dane_tlsa_live dane_want_hash dane_status
    if ! dane_tlsa_out="$(resolvectl query --type=TLSA "_25._tcp.${mx_target}" 2>/dev/null)"; then
        dane_status="currently: no TLSA record at _25._tcp.${mx_target}"
    else
        dane_tlsa_live="$(grep -oE '[0-9]+ [0-9]+ [0-9]+ [0-9a-fA-F]+' <<< "$dane_tlsa_out" | head -1)"
        if [[ -z "$dane_tlsa_live" ]]; then
            dane_status="currently: no TLSA record at _25._tcp.${mx_target}"
        elif [[ -f "$dane_cert" ]]; then
            dane_want_hash="$(openssl x509 -in "$dane_cert" -noout -pubkey 2>/dev/null \
                | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -hex | sed 's/^.*= //')"
            if grep -qiF "$dane_want_hash" <<< "$dane_tlsa_live"; then
                dane_status="currently: TLSA at _25._tcp.${mx_target} matches the current certificate - already set up"
            else
                dane_status="currently: TLSA at _25._tcp.${mx_target} does NOT match the current certificate - stale"
            fi
        else
            dane_status="currently: TLSA record found at _25._tcp.${mx_target}, could not verify it against the certificate"
        fi
    fi

    cat <<EOF
DNS records to set up for: ${dom}
(mail server: ${mailhost}, IPv4: ${PRIMARY_IPV4:-<none>}, IPv6: ${PRIMARY_IPV6:-<none>})
(MX ${current_mx_status})

-- Core mail routing --
@                       3600    A       ${PRIMARY_IPV4}
@                       3600    AAAA    ${PRIMARY_IPV6}
@                       3600    MX      10 ${mx_target}.
mail                    3600    A       ${PRIMARY_IPV4}
mail                    3600    AAAA    ${PRIMARY_IPV6}
EOF
    if [[ "$needs_dedicated_mx" -eq 1 ]]; then
        cat <<EOF
mx1                     3600    A       ${PRIMARY_IPV4}
mx1                     3600    AAAA    ${PRIMARY_IPV6}

NOTE: ${mailhost} is THIS SERVER's own hostname (its PTR/reverse-DNS
record, used by Postfix as myhostname/HELO) - not something exclusive to
${dom} alone. The MX above therefore points at mx1.${dom} instead of
${mailhost}, so this domain can get its own independent DANE/TLSA policy
later without silently sharing it with the server's own identity or any
other domain (DANE is keyed on the MX hostname, not the recipient
domain). See dns-records-reference.md for the full reasoning.
EOF
    fi

    cat <<EOF

-- SPF / DKIM / DMARC (anti-spoofing) --
@                       3600    TXT     "v=spf1 mx -all"
mail                    3600    TXT     "v=spf1 a -all"
dkim-ed._domainkey      300     TXT     (generate with: manage-dkim.sh -domain ${dom})
dkim-rsa._domainkey     300     TXT     (generate with: manage-dkim.sh -domain ${dom})
dkim._domainkey         300     CNAME   dkim-rsa._domainkey.${dom}.
_dmarc                  300     TXT     "v=DMARC1; p=quarantine; rua=mailto:admin@${dom}"

-- Certificate issuance (optional, restricts which CA may issue certs) --
@                       3600    CAA     0 issue "letsencrypt.org"
@                       3600    CAA     128 issuewild "letsencrypt.org"

-- MTA-STS + TLS reporting (recommended - enforces TLS on inbound mail) --
(_mta-sts ${mta_sts_status})
(set up the policy file + nginx with: manage-mta-sts.sh -domain ${dom})
_mta-sts                3600    TXT     "v=STSv1; id=${suggested_sts_id}"
mta-sts                 3600    A       ${PRIMARY_IPV4}
mta-sts                 3600    AAAA    ${PRIMARY_IPV6}
_smtp._tls              3600    TXT     "v=TLSRPTv1; rua=mailto:${TLSRPT_RUA}"

-- DANE (optional, only recommended if your DNS provider can be updated
   automatically - see note below) --
(DANE ${dane_status})
EOF
    if [[ "$needs_dedicated_mx" -eq 1 ]]; then
        cat <<EOF
(set up with: manage-dane.sh, see its own --status/--setup - already has
its own dedicated MX hostname, mx1.${dom}, set up above specifically so
DANE for this domain never gets tied to the server's own shared identity
or any other domain hosted here)
EOF
    else
        cat <<EOF
(set up with: manage-dane.sh, see its own --status/--setup - ${mailhost}
is already exclusive to this domain, not shared with the server's own
identity or any other domain, so no extra MX hostname is needed first)
EOF
    fi

    cat <<EOF

-- Mail client autoconfiguration (Thunderbird + Outlook) --
autoconfig              86400   CNAME   ${mailhost}.
autodiscover            86400   CNAME   ${mailhost}.
_autodiscover._tcp      86400   SRV     0 0 443 ${mailhost}.

-- CalDAV / CardDAV autodiscovery (optional) --
_caldav._tcp            86400   TXT     "https://${mailhost}/dav"
_caldav._tcp            86400   SRV     0 0 443 ${mailhost}.
_caldavs._tcp           86400   TXT     "https://${mailhost}/dav"
_caldavs._tcp           86400   SRV     0 0 443 ${mailhost}.
_carddav._tcp           86400   TXT     "https://${mailhost}/dav"
_carddav._tcp           86400   SRV     0 0 443 ${mailhost}.
_carddavs._tcp          86400   TXT     "https://${mailhost}/dav"
_carddavs._tcp          86400   SRV     0 0 443 ${mailhost}.

-- Mail protocol service discovery, RFC 6186 (optional) --
_imap._tcp              86400   SRV     0 0 143 ${mailhost}.
_imaps._tcp             86400   SRV     0 0 993 ${mailhost}.
_pop3._tcp              86400   SRV     0 0 110 ${mailhost}.
_pop3s._tcp             86400   SRV     0 0 995 ${mailhost}.
_submission._tcp        86400   SRV     0 0 587 ${mailhost}.
_submissions._tcp       86400   SRV     0 0 465 ${mailhost}.

Notes:
- DKIM: run "manage-dkim.sh -domain ${dom}" on this server first, then
  use the actual TXT values it prints in place of the two placeholder
  lines above. The "dkim._domainkey" CNAME specifically exists so
  grommunio-admin's own web interface (Domain overview) shows DKIM as
  green there - it checks that exact unqualified name, nothing else
  reads it.
- DMARC starts at p=quarantine (recommended first step); once DKIM/SPF
  are confirmed passing for real mail, consider moving to p=reject.
- MTA-STS: the "_mta-sts" TXT and "mta-sts" A/AAAA records above are
  everything needed on the DNS side. The actual policy file and nginx
  setup for mta-sts.${dom} are handled separately by running
  "manage-mta-sts.sh -domain ${dom}" on this server, once the DNS
  above is live and resolving. Bump the "id=" value (any short string,
  just needs to change) whenever the policy changes later.
- DANE: only recommended if your DNS provider can be updated
  automatically. TLSA pins to the CURRENT certificate's key, which
  Let's Encrypt rotates roughly every 90 days - update-dane-tlsa.sh
  (installed by manage-dane.sh as a certbot renewal hook, using the
  TransIP DNS API in this setup) re-publishes the TLSA record
  automatically on every renewal. Without an API your DNS provider
  supports for this, the record must be updated by hand within the
  renewal window every time - miss it even once and DANE-enforcing
  receivers will REJECT mail outright, not just warn, since the
  published TLSA no longer matches the live certificate. Do not
  enable DANE for ${dom} unless you have (or will build) the same
  kind of automation.
- grommunio-admin's own web interface (Domain overview) may show the
  "MX Records" indicator as orange/warning for this domain, even once
  everything above is set up correctly. It compares the MX hostname
  against this server's single reverse-DNS (PTR) record with a plain
  string equality check (confirmed in its own source,
  src/components/DnsHealth.tsx's getMXColor() - there is a literal
  "// TODO: Check reverse" comment there). Since one IP has only one
  PTR value, at most ONE domain's MX hostname can ever match it - every
  other domain hosted on the same server will show this same orange
  indicator no matter what its DNS says. This is a cosmetic limitation
  of that one UI indicator, not a real problem: it has no effect on
  actual mail delivery.
- The CalDAV/CardDAV and RFC 6186 blocks are optional convenience
  records - mail works fully without them, they only help some mail
  clients auto-configure themselves.
- After these records are live, verify with:
  check-dns.sh -domain ${dom}  (once this domain resolves here)
EOF
}

# cmd_firstdomain: PTR, forward-confirmed reverse DNS (FCrDNS), and a
# match against this server's own saved hostname (NEW_FQDN, from step
# 10). Takes no domain argument on purpose - this is about the SERVER's
# own identity, not about any one hosted domain (see
# 31-grommunio-domain.sh's hint_dedicated_mx_if_needed and
# dns-records-reference.md for why that identity matters: whichever
# domain's mail.<domain> happens to equal it is the one that needs a
# dedicated mx1.<domain> MX target for independent DANE). Same
# resolvectl-based lookups step 10 itself uses to find/verify the PTR
# when the server was first set up - this is the read-only, re-runnable
# version of that same check.
cmd_firstdomain()
{
    [[ -n "$PRIMARY_IPV4" || -n "$PRIMARY_IPV6" ]] \
        || die "Could not determine this server's primary IPv4/IPv6 (not saved by step 10 yet, and auto-detection via 'ip route get' found nothing - check this server has a default route/network connectivity)."

    section "PTR (reverse DNS)"
    local ptr_v4="" ptr_v6="" out rest

    if [[ -n "$PRIMARY_IPV4" ]]; then
        out="$(resolvectl query "$PRIMARY_IPV4" 2>/dev/null | head -n1)"
        if [[ "$out" == "${PRIMARY_IPV4}:"* ]]; then
            rest="${out#"${PRIMARY_IPV4}":}"
            ptr_v4="$(sed -E 's/^[[:space:]]+//; s/[[:space:]]+--.*$//; s/[[:space:]]+$//; s/\.$//' <<< "$rest")"
            ok "PTR (IPv4 ${PRIMARY_IPV4}) -> ${ptr_v4}"
        else
            fail "PTR (IPv4 ${PRIMARY_IPV4}): no reverse DNS record found - set this with your hosting provider, not in a domain's own DNS zone."
        fi
    fi

    if [[ -n "$PRIMARY_IPV6" ]]; then
        out="$(resolvectl query "$PRIMARY_IPV6" 2>/dev/null | head -n1)"
        if [[ "$out" == "${PRIMARY_IPV6}:"* ]]; then
            rest="${out#"${PRIMARY_IPV6}":}"
            ptr_v6="$(sed -E 's/^[[:space:]]+//; s/[[:space:]]+--.*$//; s/[[:space:]]+$//; s/\.$//' <<< "$rest")"
            ok "PTR (IPv6 ${PRIMARY_IPV6}) -> ${ptr_v6}"
        else
            fail "PTR (IPv6 ${PRIMARY_IPV6}): no reverse DNS record found - set this with your hosting provider, not in a domain's own DNS zone."
        fi
    fi

    if [[ -z "$ptr_v4" && -z "$ptr_v6" ]]; then
        err "No PTR record at all - cannot check FCrDNS or the hostname match below."
        return 1
    fi

    if [[ -n "$ptr_v4" && -n "$ptr_v6" && "$ptr_v4" != "$ptr_v6" ]]; then
        warn "PTR for IPv4 (${ptr_v4}) and IPv6 (${ptr_v6}) differ - unusual, worth confirming with your hosting provider."
    fi

    section "Forward-confirmed reverse DNS (FCrDNS)"
    if [[ -n "$ptr_v4" ]]; then
        out="$(resolvectl query --type=A "$ptr_v4" 2>/dev/null)"
        if grep -qF "$PRIMARY_IPV4" <<< "$out"; then
            ok "FCrDNS: ${ptr_v4} resolves back to ${PRIMARY_IPV4}"
        else
            fail "FCrDNS: ${ptr_v4} does NOT resolve back to ${PRIMARY_IPV4} - its own A record is missing or points elsewhere."
        fi
    fi
    if [[ -n "$ptr_v6" ]]; then
        out="$(resolvectl query --type=AAAA "$ptr_v6" 2>/dev/null)"
        if grep -qF "$PRIMARY_IPV6" <<< "$out"; then
            ok "FCrDNS: ${ptr_v6} resolves back to ${PRIMARY_IPV6}"
        else
            fail "FCrDNS: ${ptr_v6} does NOT resolve back to ${PRIMARY_IPV6} - its own AAAA record is missing or points elsewhere."
        fi
    fi

    section "Match against this server's configured hostname"
    local ptr_name="${ptr_v4:-$ptr_v6}"
    if [[ -z "${NEW_FQDN:-}" ]]; then
        warn "No NEW_FQDN saved from step 10 - cannot compare. Run step 10 first (or re-run it to confirm/update the hostname)."
    elif [[ "$ptr_name" == "$NEW_FQDN" ]]; then
        ok "${ptr_name} matches this server's saved hostname (NEW_FQDN=${NEW_FQDN})."
    else
        fail "${ptr_name} (from PTR) does NOT match this server's saved hostname (NEW_FQDN=${NEW_FQDN}) - hostnamectl/Postfix myhostname and the PTR disagree. Either the PTR or step 10's saved hostname needs to be corrected."
    fi

    echo
    if [[ "$FAIL_COUNT" -eq 0 && "$WARN_COUNT" -eq 0 ]]; then
        log "[ OK ] PTR/FCrDNS setup for this server looks correct."
    elif [[ "$FAIL_COUNT" -eq 0 ]]; then
        log "[ OK ] No failures ($WARN_COUNT warning(s), see above)."
    else
        err "$FAIL_COUNT failure(s), $WARN_COUNT warning(s) - see [FAIL]/[WARN] lines above."
        return 1
    fi
}

cmd_check()
{
    local -a domains=("$@")
    local d
    for d in "${domains[@]}"; do
        check_domain "$d"
    done

    echo
    if [[ "$FAIL_COUNT" -eq 0 && "$WARN_COUNT" -eq 0 ]]; then
        log "[ OK ] Every check passed for: ${domains[*]}"
    elif [[ "$FAIL_COUNT" -eq 0 ]]; then
        log "[ OK ] No failures for: ${domains[*]} ($WARN_COUNT warning(s), see above)."
    else
        err "$FAIL_COUNT failure(s), $WARN_COUNT warning(s) across: ${domains[*]} - see [FAIL]/[WARN] lines above."
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
        --brief)
            BRIEF_MODE=1; shift ;;
        --report)
            [[ -n "${2:-}" ]] || die "--report needs a domain name."
            ACTION="report"; TARGET_DOMAIN="$2"; shift 2 ;;
        --firstdomain)
            ACTION="firstdomain"; shift ;;
        -h|--help)
            show_help; exit 0 ;;
        *)
            echo "check-dns.sh: unknown option: $1 (see --help)" >&2
            exit 1 ;;
    esac
done

[[ -n "$ACTION" ]] || die "--brief needs --all or -domain <name> too (see --help)."

if [[ "$ACTION" == "report" ]]; then
    cmd_report "$TARGET_DOMAIN"
    exit 0
fi

if [[ "$ACTION" == "firstdomain" ]]; then
    require_cmd resolvectl
    cmd_firstdomain
    exit $?
fi

require_cmd grommunio-admin
require_cmd resolvectl
require_cmd curl
require_cmd openssl
require_cmd dig

case "$ACTION" in
    all)
        mapfile -t HOSTED < <(hosted_domains)
        [[ "${#HOSTED[@]}" -gt 0 ]] || die "No active domain is hosted on this server (none resolve here)."
        log "Checking ${#HOSTED[@]} domain(s) hosted here: ${HOSTED[*]}"
        cmd_check "${HOSTED[@]}"
        ;;
    domain)
        mapfile -t HOSTED < <(hosted_domains)
        found=0
        for h in "${HOSTED[@]}"; do [[ "$h" == "$TARGET_DOMAIN" ]] && { found=1; break; }; done
        [[ "$found" -eq 1 ]] || die "'$TARGET_DOMAIN' is not an active domain hosted on this server."
        cmd_check "$TARGET_DOMAIN"
        ;;
    *)
        show_help
        exit 1
        ;;
esac
