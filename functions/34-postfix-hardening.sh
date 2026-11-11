#!/usr/bin/env bash
#
# 34-postfix-hardening.sh
#
# Two small, low-risk Postfix hardening settings that grommunio-setup leaves
# at Debian's plain defaults, found during a hardening review 2026-10-22:
#
#   disable_vrfy_command      - Debian's default (no) lets anyone probe
#                                whether an address exists via VRFY (account
#                                enumeration).
#   smtpd_sender_restrictions - missing reject_unknown_sender_domain, so mail
#                                from a sender domain with no valid DNS (no
#                                MX/A record) is accepted as-is. Adding it
#                                cuts spoofing/backscatter with essentially
#                                no risk to real senders - they have working
#                                DNS.
#
# Both were applied by hand and tested live on testvps 2026-10-22 before
# being made a step here: VRFY returns "502 VRFY command is disabled"; a
# MAIL FROM with a nonexistent sender domain gets "450 ... Domain not
# found"; a real sender domain (tested with gmail.com) still passes
# through to RCPT TO normally.
#
# Idempotent: each setting is checked before being changed, so a rerun (or
# a dpkg conffile prompt that reset something else later) only touches
# what's actually still wrong - never a blind overwrite of the whole
# restriction list, in case it's been customized further by hand since.
#
# Deliberately NOT touched here, left as-is (user's own call 2026-10-22):
# milter_default_action=accept (fail-open if rspamd is ever unreachable).
#
# Second round, same day: diffed against the user's own long-running
# Debian 7 production main.cf (a different, older mail server the user runs).
# Real, concrete findings, applied by hand and tested live on testvps
# before being added here:
#
#   tls_ssl_options              - was unset. CRIME-attack mitigation
#                                   (NO_COMPRESSION) + anti-renegotiation.
#   show_user_unknown_table_name - was unset (Postfix default leaks the
#                                   internal lookup-table name in "user
#                                   unknown" bounces to external senders).
#   allow_percent_hack           - was Postfix's own default "yes" (lets
#                                   user%domain addressing bypass checks,
#                                   an old relay trick).
#   swap_bangpath                - same idea, for the old user!domain form.
#   message_size_limit           - was Debian's 10MB default; raised to
#                                   150MB (the user's own chosen value).
#   strict_rfc821_envelopes      - was Postfix's default "no"; rejects
#                                   malformed (non-RFC821) envelope syntax.
#   delay_warning_time           - was unset; sends the sender a "still
#                                   queued" notice after 4h.
#   smtpd_client_restrictions    - was completely EMPTY: no reverse-DNS
#                                   (PTR) validation on connecting clients
#                                   at all. Order (permits before the
#                                   reject_* checks) copied verbatim from
#                                   the old server's own long-proven-in-
#                                   production config, so mynetworks/SASL-
#                                   authenticated senders - including
#                                   submission/submissions, which don't
#                                   override client_restrictions - never
#                                   hit the PTR check.
#   smtpd_helo_restrictions       - added reject_unknown_helo_hostname to
#                                   the existing list.
#
# Deliberately NOT ported from that old config (architecture-superseded or
# obsolete, not simply missed - see testvps-provisioning-framework memory
# for the full reasoning): the postscreen+DNSBL block (rspamd's own
# modules cover this without hand-curated lists), check_policy_service
# policy-spf (rspamd does SPF/DKIM/DMARC itself), clamsmtp content_filter
# (different architecture; whether antivirus scanning exists at all in
# this stack is a separate, still-open question), and legacy pre-modern-
# curve TLS/cipher tuning (dh512/1024 param files, eecdh_grade, etc. -
# today's tls_preempt_cipherlist + cipher exclusions already supersede it).

step_postfix_hardening()
{
require_cmd postconf
require_cmd python3

local MAIN_CF="/etc/postfix/main.cf"
local changed=0

if [[ "$(postconf -h disable_vrfy_command)" == "yes" ]]; then
    log "[ OK ] disable_vrfy_command is already yes."
else
    backup_file "$MAIN_CF"
    postconf -e 'disable_vrfy_command = yes'
    changed=1
    log "Set disable_vrfy_command = yes (was the Debian default 'no' - VRFY allows address enumeration)."
fi

local CUR_SENDER_RESTRICTIONS
CUR_SENDER_RESTRICTIONS="$(postconf -h smtpd_sender_restrictions)"

if grep -qw 'reject_unknown_sender_domain' <<< "$CUR_SENDER_RESTRICTIONS"; then
    log "[ OK ] smtpd_sender_restrictions already has reject_unknown_sender_domain."
else
    [[ "$changed" -eq 1 ]] || backup_file "$MAIN_CF"
    local NEW_SENDER_RESTRICTIONS
    if grep -qw 'reject_non_fqdn_sender' <<< "$CUR_SENDER_RESTRICTIONS"; then
        # Insert right after reject_non_fqdn_sender - matches the no-bypass
        # placement (before permit_sasl_authenticated/permit_mynetworks)
        # this was given when first applied by hand.
        NEW_SENDER_RESTRICTIONS="$(sed -E 's/(^|,)reject_non_fqdn_sender(,|$)/\1reject_non_fqdn_sender,reject_unknown_sender_domain\2/' <<< "$CUR_SENDER_RESTRICTIONS")"
    else
        NEW_SENDER_RESTRICTIONS="reject_unknown_sender_domain${CUR_SENDER_RESTRICTIONS:+,$CUR_SENDER_RESTRICTIONS}"
    fi
    postconf -e "smtpd_sender_restrictions = ${NEW_SENDER_RESTRICTIONS}"
    changed=1
    log "Added reject_unknown_sender_domain to smtpd_sender_restrictions (was: '$CUR_SENDER_RESTRICTIONS')."
fi

# ============================================================
# Second round of scalar settings (see file header) - simple exact-match
# check-and-set, each independent of the others.
# ============================================================

local -A POSTFIX_HARDENING_SCALARS=(
    [tls_ssl_options]="NO_COMPRESSION, NO_RENEGOTIATION"
    [show_user_unknown_table_name]=no
    [allow_percent_hack]=no
    [swap_bangpath]=no
    [message_size_limit]=157286400
    [strict_rfc821_envelopes]=yes
    [delay_warning_time]=4h
)

local param want have
for param in "${!POSTFIX_HARDENING_SCALARS[@]}"; do
    want="${POSTFIX_HARDENING_SCALARS[$param]}"
    have="$(postconf -h "$param")"
    if [[ "$have" == "$want" ]]; then
        log "[ OK ] ${param} is already '${want}'."
    else
        [[ "$changed" -eq 1 ]] || backup_file "$MAIN_CF"
        postconf -e "${param} = ${want}"
        changed=1
        log "Set ${param} = '${want}' (was: '${have}')."
    fi
done

# smtpd_client_restrictions: was completely empty - a real gap, no
# reverse-DNS check on connecting clients at all. If it's already
# non-empty (customized further by hand since this step last ran), only
# append the two missing tokens - never overwrite, and never insert
# earlier than whatever's already first in the list (which is what keeps
# this safe for submission/submissions: their permit_mynetworks/
# permit_sasl_authenticated, wherever they sit, always run before an
# appended reject_* token).
local CUR_CLIENT_RESTRICTIONS NEW_CLIENT_RESTRICTIONS token
CUR_CLIENT_RESTRICTIONS="$(postconf -h smtpd_client_restrictions)"
if [[ -z "$CUR_CLIENT_RESTRICTIONS" ]]; then
    [[ "$changed" -eq 1 ]] || backup_file "$MAIN_CF"
    postconf -e 'smtpd_client_restrictions = permit_mynetworks,permit_sasl_authenticated,reject_unknown_client_hostname,reject_unknown_reverse_client_hostname'
    changed=1
    log "Set smtpd_client_restrictions (was empty - no reverse-DNS validation on connecting clients at all)."
else
    NEW_CLIENT_RESTRICTIONS="$CUR_CLIENT_RESTRICTIONS"
    for token in reject_unknown_client_hostname reject_unknown_reverse_client_hostname; do
        grep -qw "$token" <<< "$NEW_CLIENT_RESTRICTIONS" || NEW_CLIENT_RESTRICTIONS="${NEW_CLIENT_RESTRICTIONS},${token}"
    done
    if [[ "$NEW_CLIENT_RESTRICTIONS" == "$CUR_CLIENT_RESTRICTIONS" ]]; then
        log "[ OK ] smtpd_client_restrictions already has both reverse-DNS checks."
    else
        [[ "$changed" -eq 1 ]] || backup_file "$MAIN_CF"
        postconf -e "smtpd_client_restrictions = ${NEW_CLIENT_RESTRICTIONS}"
        changed=1
        log "Appended missing reverse-DNS checks to smtpd_client_restrictions (was: '$CUR_CLIENT_RESTRICTIONS')."
    fi
fi

# smtpd_helo_restrictions: same append-only approach for one new token.
local CUR_HELO_RESTRICTIONS
CUR_HELO_RESTRICTIONS="$(postconf -h smtpd_helo_restrictions)"
if grep -qw 'reject_unknown_helo_hostname' <<< "$CUR_HELO_RESTRICTIONS"; then
    log "[ OK ] smtpd_helo_restrictions already has reject_unknown_helo_hostname."
else
    [[ "$changed" -eq 1 ]] || backup_file "$MAIN_CF"
    postconf -e "smtpd_helo_restrictions = ${CUR_HELO_RESTRICTIONS:+$CUR_HELO_RESTRICTIONS,}reject_unknown_helo_hostname"
    changed=1
    log "Appended reject_unknown_helo_hostname to smtpd_helo_restrictions (was: '$CUR_HELO_RESTRICTIONS')."
fi

finalize_backup "$MAIN_CF"
if [[ "$changed" -eq 1 ]]; then
    postfix check || die "postfix check failed after the hardening changes - restore from the .bak file just written."
    systemctl reload postfix || die "postfix reload failed after the hardening changes."
    log "[ OK ] postfix reloaded."
fi

# ============================================================
# Verify what postfix actually does over a real connection, not just what
# main.cf/postconf reports.
# ============================================================

local vrfy_reply
vrfy_reply="$(python3 -I -c "
import socket
s = socket.create_connection(('127.0.0.1', 25), timeout=5)
s.recv(200)
s.sendall(b'HELO test.example\r\n')
s.recv(200)
s.sendall(b'VRFY root\r\n')
print(s.recv(200).decode(errors='replace').strip())
s.sendall(b'QUIT\r\n')
s.close()
" 2>/dev/null)"

if grep -q '^502' <<< "$vrfy_reply"; then
    log "[ OK ] VRFY is refused live: $vrfy_reply"
else
    err "[FAIL] VRFY was not refused live: $vrfy_reply"
    return 1
fi

local DOMAIN_FOR_TEST
DOMAIN_FOR_TEST="$(postconf -h myhostname | cut -d. -f2-)"
[[ -n "$DOMAIN_FOR_TEST" && "$DOMAIN_FOR_TEST" != "$(postconf -h myhostname)" ]] \
    || die "Could not derive a real domain from myhostname ('$(postconf -h myhostname)') to verify the sender-domain restriction against."

local sender_reply
sender_reply="$(python3 -I -c "
import socket
def cmd(s, data):
    s.sendall(data)
    return s.recv(300).decode(errors='replace').strip()
s = socket.create_connection(('127.0.0.1', 25), timeout=5)
s.recv(200)
cmd(s, b'HELO test.example\r\n')
cmd(s, b'MAIL FROM:<test@this-domain-does-not-exist-xyz123.invalid>\r\n')
# A bare, unqualified 'postmaster' recipient is a built-in Postfix exception
# (RFC 5321 requires it always be deliverable) and bypasses restrictions
# entirely - a real, qualified address must be used here instead, or this
# verification always passes even when the restriction is broken.
print(cmd(s, b'RCPT TO:<postmaster@${DOMAIN_FOR_TEST}>\r\n'))
s.sendall(b'QUIT\r\n')
s.close()
" 2>/dev/null)"

if grep -qE '^(450|550)' <<< "$sender_reply"; then
    log "[ OK ] A nonexistent sender domain is refused live: $sender_reply"
else
    err "[FAIL] A nonexistent sender domain was NOT refused live: $sender_reply"
    return 1
fi

local size_reply
size_reply="$(python3 -I -c "
import socket
s = socket.create_connection(('127.0.0.1', 25), timeout=5)
s.recv(200)
s.sendall(b'EHLO test.example\r\n')
print(s.recv(500).decode(errors='replace'))
s.close()
" 2>/dev/null)"

if grep -q 'SIZE 157286400' <<< "$size_reply"; then
    log "[ OK ] message_size_limit (150MB) is advertised live."
else
    err "[FAIL] EHLO does not advertise SIZE 157286400: $size_reply"
    return 1
fi

local MYHOSTNAME_FOR_TEST
MYHOSTNAME_FOR_TEST="$(postconf -h myhostname)"

local percenthack_reply
percenthack_reply="$(python3 -I -c "
import socket
def cmd(s, data):
    s.sendall(data)
    return s.recv(300).decode(errors='replace').strip()
s = socket.create_connection(('127.0.0.1', 25), timeout=5)
s.recv(200)
cmd(s, b'HELO test.example\r\n')
cmd(s, b'MAIL FROM:<test@${DOMAIN_FOR_TEST}>\r\n')
print(cmd(s, b'RCPT TO:<postmaster%${DOMAIN_FOR_TEST}@${MYHOSTNAME_FOR_TEST}>\r\n'))
s.sendall(b'QUIT\r\n')
s.close()
" 2>/dev/null)"

if grep -qE '^55[01]' <<< "$percenthack_reply"; then
    log "[ OK ] A percent-hack address is refused live: $percenthack_reply"
else
    err "[FAIL] A percent-hack address was NOT refused live: $percenthack_reply"
    return 1
fi

local strictenvelope_reply
strictenvelope_reply="$(python3 -I -c "
import socket
def cmd(s, data):
    s.sendall(data)
    return s.recv(300).decode(errors='replace').strip()
s = socket.create_connection(('127.0.0.1', 25), timeout=5)
s.recv(200)
cmd(s, b'HELO test.example\r\n')
print(cmd(s, b'MAIL FROM:<Test User <test@${DOMAIN_FOR_TEST}>>\r\n'))
s.sendall(b'QUIT\r\n')
s.close()
" 2>/dev/null)"

if grep -q '^501' <<< "$strictenvelope_reply"; then
    log "[ OK ] A malformed (non-strict) envelope address is refused live: $strictenvelope_reply"
else
    err "[FAIL] A malformed envelope address was NOT refused live: $strictenvelope_reply"
    return 1
fi

# smtpd_client_restrictions/smtpd_helo_restrictions's new reject_* checks
# can't be exercised from this host: 127.0.0.1 always matches
# permit_mynetworks first, so the actual reject path (a stranger IP with
# no/mismatched PTR, or a HELO name that doesn't resolve) is untestable
# from localhost. Only confirm the settings are in place (done above) and
# that nothing broke for the permitted path: a normal external-looking
# MAIL FROM/RCPT TO still has to succeed.
#
# Uses a throwaway test mailbox, not postmaster@domain: postmaster is only
# guaranteed to exist once 31-grommunio-domain.sh has created the domain's
# hub mailbox and aliases, so testing against it made this step depend on
# that one having already run. Found live, 2026-10-24: this failed with
# "550 User unknown" on a fresh install where the domain existed (from
# 30-grommunio-setup.sh) but no mailbox had been created yet. Same
# throwaway-mailbox pattern as 45-grommunio-files.sh's WebDAV test.
local TEST_RECIPIENT="postfixtest-$(date +%s)-$$@${DOMAIN_FOR_TEST}"

grommunio-admin user create "$TEST_RECIPIENT" >/dev/null 2>&1 \
    || die "Could not create throwaway test mailbox $TEST_RECIPIENT on $DOMAIN_FOR_TEST to verify normal mail is still accepted."

local normal_reply
normal_reply="$(python3 -I -c "
import socket
def cmd(s, data):
    s.sendall(data)
    return s.recv(300).decode(errors='replace').strip()
s = socket.create_connection(('127.0.0.1', 25), timeout=5)
s.recv(200)
cmd(s, b'HELO mail.gmail.com\r\n')
cmd(s, b'MAIL FROM:<test@gmail.com>\r\n')
reply = cmd(s, b'RCPT TO:<${TEST_RECIPIENT}>\r\n')
s.sendall(b'RSET\r\n'); s.recv(200)
s.sendall(b'QUIT\r\n')
print(reply)
s.close()
" 2>/dev/null)"

grommunio-admin user delete "$TEST_RECIPIENT" -y >/dev/null 2>&1
log "Throwaway test mailbox $TEST_RECIPIENT deleted."

if grep -q '^250' <<< "$normal_reply"; then
    log "[ OK ] A normal external-looking MAIL FROM/RCPT TO is still accepted: $normal_reply"
else
    err "[FAIL] A normal external-looking MAIL FROM/RCPT TO was unexpectedly refused: $normal_reply"
    return 1
fi
}
