#!/usr/bin/env bash
#
# 36-fail2ban-mail-jails.sh
#
# Closes a real gap found during a post-reboot log sweep: fail2ban was only
# protecting sshd (step 20), while Postfix's submission port was already
# seeing hundreds of automated SASL brute-force attempts with nothing
# banning them.
#
# Enables two STOCK fail2ban jails — deliberately not custom regexes:
#   - postfix-sasl: fail2ban's own jail.conf already ships a fully correct
#     Debian stanza for this (filter=postfix[mode=auth], logpath/backend via
#     %(postfix_log)s/%(postfix_backend)s). Verified live on testvps: its
#     regex matches our actual log line ("SASL LOGIN authentication failed:
#     generic failure, ..."). We only need to flip it on and set banaction.
#   - nginx-botsearch: also a stock jail, but its default logpath variable
#     (%(nginx_error_log)s) isn't Debian-path-overridden in
#     paths-debian.conf, so we set logpath explicitly and force backend=auto
#     (file tailing) since nginx logs to a file here, not the journal —
#     otherwise it would silently inherit backend=systemd from step 20's
#     [DEFAULT] override and never see anything.
#
# REAL BUG found and fixed 2026-09-30: the logpath we picked was itself
# wrong. nginx.conf's own top-level `error_log /var/log/nginx/error.log;`
# is NOT what's actually used — grommunio-common ships its own
# /usr/share/grommunio-common/nginx.conf, which sets
# `error_log /var/log/nginx/nginx-error.log;` at a scope that covers the
# default/catch-all server block (the one handling unmatched Host headers
# and bare-IP requests — every real grommunio location sets its OWN
# error_log, overriding this). Every per-service *-error.log we relied on
# elsewhere (nginx-web-error.log etc.) already proved this pattern; this
# one case slipped through because /var/log/nginx/error.log LOOKS like a
# plausible, existing file — it's just permanently empty (0 bytes), so
# nginx-botsearch had literally never seen a single log line, on top of its
# own block-list being too narrow for modern scanning (see the new
# nginx-catchall-scan jail below). Detection now checks grommunio-common's
# override first.
#
# findtime=1h (not the original 10m): found live 2026-09-29 that a bot
# pacing SASL attempts ~5 minutes apart against port 25 was never getting
# banned — at 10m findtime + maxretry=5, at most 2 of its attempts ever fell
# inside the same rolling window, so it could never reach the threshold no
# matter how long it kept trying. A 1h window still requires the same 5
# failures, just tolerates slower pacing before that bot (or a smarter one
# aimed at the submission port, where auth can actually succeed) ages out
# of the count. maxretry/bantime per jail are unchanged — only the window
# that was too narrow to catch a deliberately slow attacker.
#
# Explicitly NOT included here: grommunio-sync/imap/pop3/dav/web-auth
# custom filters from the community fail2ban package (Walter Hofstaedtler /
# github.com/crpb/grommunio/tree/main/setup/fail2ban). Investigated and
# found to need real work first, not a safe blind copy:
#   - its own custom postfix-sasl.conf filter is unused dead weight in its
#     own jail.local AND independently broken (malformed %(__prefix_line)
#     interpolation, and its regex only matches the literal string
#     "authentication failure", not our actual "generic failure")
#   - grommunio-sync's filter needs LOGAUTHFAIL=true in
#     grommunio-sync.conf.php first (currently false here) or it watches a
#     log that never contains what it's looking for
#   - grommunio-dav: no gromox-dav.service exists on this install at all;
#     unclear yet where/how DAV auth failures are actually logged
#   - imap/pop3/web-auth regexes are unverified against our gromox 3.11.5
#     (the web-auth filter's own comment notes it already broke once before
#     on a past grommunio version's message-format change)
# These need a live-trigger verification pass (deliberately fail a login
# against each service, check the real resulting log line) before they can
# be trusted — tracked as follow-up work, not done here.
#
# Added 2026-11-05: postfix-smtp-auth-subnet, a second jail on top of
# postfix-smtp-auth's own filter/log line. A per-IP jail cannot catch a
# distributed attacker that deliberately keeps every individual IP under
# its own maxretry (found live: ~19 IPs in one provider's /24, each doing
# 1-2 failed AUTH attempts before switching to the next) - this jail
# aggregates by network instead of by single IP, and its own ban action
# resolves the real, whois-registered CIDR via the standalone
# f2b-subnet-detect.sh script (installed to /usr/local/bin/ by this same
# step) rather than guessing a fixed mask. See that script's own header
# for the full design, and the two real gotchas found while building it
# below (fail2ban's required failure-id
# group name is "fid", not "host"; a brand new jail needs a full
# `systemctl restart fail2ban`, not just `fail2ban-client reload`).

step_fail2ban_mail_jails()
{
local OVERRIDE_FILE="/etc/fail2ban/jail.d/zz-mail-hardening.local"

require_cmd fail2ban-client
require_cmd systemctl

# whois+ipcalc: needed by f2b-subnet-detect.sh (the postfix-smtp-auth-subnet
# jail's CIDR-widening action below resolves each ban to its real,
# registered network block via live whois, rather than guessing a fixed
# mask - see that script's own header for why and the priority order).
apt-get install -y whois ipcalc >/dev/null || die "Could not install whois/ipcalc."
require_cmd whois
require_cmd ipcalc

local SUBNET_DETECT_SCRIPT="/usr/local/bin/f2b-subnet-detect.sh"
install -m 0755 "${SCRIPT_DIR}/f2b-subnet-detect.sh" "$SUBNET_DETECT_SCRIPT" \
    || die "Could not install $SUBNET_DETECT_SCRIPT."
log "[ OK ] Installed $SUBNET_DETECT_SCRIPT."

# ============================================================
# Reuse step 20's firewall backend decision so banaction matches whichever
# firewall is actually active — same pattern step 20 itself uses.
# ============================================================

local FW_CFG="$(cfg_file 20-firewall-fail2ban)"
local FW_BACKEND=""

if [[ -f "$FW_CFG" ]]; then
    # shellcheck disable=SC1090
    source "$FW_CFG"
fi

if [[ -z "${FW_BACKEND:-}" ]]; then
    err "Could not determine the firewall backend — $FW_CFG not found or empty."
    err "Run step 20 (firewall/fail2ban) first."
    return 1
fi

local banaction
case "$FW_BACKEND" in
    firewalld) banaction="firewallcmd-ipset" ;;
    ufw)       banaction="ufw" ;;
    *)         die "Unknown firewall backend in $FW_CFG: $FW_BACKEND" ;;
esac

# ============================================================
# postfix-smtp-auth-subnet's own action: same idea as every other jail's
# banaction above, but instead of banning the literal match (a bare
# "a.b.c" 3-octet prefix, not a usable address on its own) it resolves
# that prefix's real, registered network via f2b-subnet-detect.sh
# (live whois) and bans the actual CIDR. One action file per firewall
# backend, same split as the rest of this project's firewall handling.
# ============================================================

local banaction_subnet
case "$FW_BACKEND" in
    firewalld)
        banaction_subnet="firewallcmd-ipset-cidr"
        backup_file "/etc/fail2ban/action.d/${banaction_subnet}.conf"
        cat > "/etc/fail2ban/action.d/${banaction_subnet}.conf" <<EOF
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = firewall-cmd --ipset=f2b-postfix-smtp-auth-subnet --add-entry=\$(${SUBNET_DETECT_SCRIPT} <ip>.0)
actionunban = firewall-cmd --ipset=f2b-postfix-smtp-auth-subnet --remove-entry=\$(${SUBNET_DETECT_SCRIPT} <ip>.0)
EOF
        chmod 644 "/etc/fail2ban/action.d/${banaction_subnet}.conf"
        finalize_backup "/etc/fail2ban/action.d/${banaction_subnet}.conf"
        log "Wrote /etc/fail2ban/action.d/${banaction_subnet}.conf"

        # Permanent hash:net ipset + REJECT rule for this jail's ports -
        # same reasoning as firewalld_jail_sets() above it (exists before
        # fail2ban starts, survives a firewalld reload with fail2ban's own
        # restart putting bans back), but type=hash:net since this one
        # stores whole CIDR blocks, not single addresses.
        local net_set="f2b-postfix-smtp-auth-subnet" existing_sets existing_rules net_line
        existing_sets=" $(firewall-cmd --permanent --get-ipsets) "
        if [[ "$existing_sets" != *" $net_set "* ]]; then
            firewall-cmd --permanent --new-ipset="$net_set" --type=hash:net --option=maxelem=65536 --option=family=inet >/dev/null \
                || die "firewalld could not create the permanent ipset $net_set."
        fi
        net_line="ipv4 filter INPUT_direct 0 -p tcp -m multiport --dports 25,465,587 -m set --match-set $net_set src -j REJECT --reject-with icmp-port-unreachable"
        existing_rules="$(firewall-cmd --permanent --direct --get-all-rules)"
        if ! grep -qxF "$net_line" <<< "$existing_rules"; then
            # shellcheck disable=SC2086
            firewall-cmd --permanent --direct --add-rule $net_line >/dev/null \
                || die "firewalld could not add the permanent rule for $net_set."
        fi
        log "[ OK ] Permanent firewall set and rule for $net_set."
        ;;
    ufw)
        banaction_subnet="ufw-cidr"
        backup_file "/etc/fail2ban/action.d/${banaction_subnet}.conf"
        cat > "/etc/fail2ban/action.d/${banaction_subnet}.conf" <<EOF
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = ufw prepend reject from \$(${SUBNET_DETECT_SCRIPT} <ip>.0) to any port 25,465,587 comment 'f2b postfix-smtp-auth-subnet'
actionunban = ufw delete reject from \$(${SUBNET_DETECT_SCRIPT} <ip>.0) to any port 25,465,587
EOF
        chmod 644 "/etc/fail2ban/action.d/${banaction_subnet}.conf"
        finalize_backup "/etc/fail2ban/action.d/${banaction_subnet}.conf"
        log "Wrote /etc/fail2ban/action.d/${banaction_subnet}.conf"
        ;;
    *) die "Unknown firewall backend in $FW_CFG: $FW_BACKEND" ;;
esac
log "Using banaction=$banaction (firewall backend: $FW_BACKEND)"

# ============================================================
# Confirm nginx's actual configured log paths rather than assuming — this
# is exactly what tripped up the community filter package.
# ============================================================

local nginx_error_log
nginx_error_log="$(grep -hoE 'error_log[[:space:]]+[^ ;]+' /usr/share/grommunio-common/nginx.conf 2>/dev/null | awk '{print $2}' | head -n1)"
if [[ -z "$nginx_error_log" ]]; then
    nginx_error_log="$(grep -hoE 'error_log[[:space:]]+[^ ;]+' /etc/nginx/nginx.conf 2>/dev/null | awk '{print $2}' | head -n1)"
fi
nginx_error_log="${nginx_error_log:-/var/log/nginx/error.log}"

if [[ ! -f "$nginx_error_log" ]]; then
    err "nginx error log not found at $nginx_error_log — is nginx installed/configured yet?"
    return 1
fi
log "nginx error log confirmed at: $nginx_error_log"

local nginx_access_log
nginx_access_log="$(grep -hoE 'access_log[[:space:]]+[^ ;]+' /usr/share/grommunio-common/nginx.conf 2>/dev/null | awk '{print $2}' | head -n1)"
nginx_access_log="${nginx_access_log:-/var/log/nginx/nginx-access.log}"

if [[ ! -f "$nginx_access_log" ]]; then
    err "nginx access log not found at $nginx_access_log — is nginx installed/configured yet?"
    return 1
fi
log "nginx access log (catch-all) confirmed at: $nginx_access_log"

local nginx_admin_access_log
nginx_admin_access_log="$(grep -hoE 'access_log[[:space:]]+[^ ;]+' /usr/share/grommunio-admin-common/nginx.conf 2>/dev/null | awk '{print $2}' | head -n1)"
nginx_admin_access_log="${nginx_admin_access_log:-/var/log/nginx/nginx-admin-access.log}"

if [[ ! -f "$nginx_admin_access_log" ]]; then
    err "nginx admin-web access log not found at $nginx_admin_access_log — is grommunio-admin-web installed/configured yet?"
    return 1
fi
log "nginx admin-web access log confirmed at: $nginx_admin_access_log"

# ============================================================
# nginx-catchall-scan: a new, custom filter — not a stock one, not a
# path-list. nginx-botsearch's block-list only matches old-school
# signatures (wp-login.php, phpMyAdmin/roundcube-style paths) and misses
# everything actually hitting this server today (.env/.git harvesting,
# wp-json probing, generic /login /signin /register, and at least one real
# PHP-CGI RCE attempt via auto_prepend_file=php://input — all verified
# live in nginx-error.log 2026-09-30). Rather than chase an ever-changing
# path list, this bans on ANY 404 from the catch-all/default server block
# (server: _) — nothing legitimate ever hits that block at all, since every
# real grommunio endpoint is served by a specifically-matched location
# under the real hostname, so no path-list is needed and it can't go
# stale. One deliberate exclusion: Let's Encrypt's own HTTP-01 validation
# requests to /.well-known/acme-challenge/ also land here and 404 (this
# server's actual cert issuance doesn't use this webroot), so those are
# explicitly ignored rather than banning Let's Encrypt's own infrastructure
# for no benefit.
# ============================================================

local CATCHALL_FILTER="/etc/fail2ban/filter.d/nginx-catchall-scan.conf"

backup_file "$CATCHALL_FILTER"

cat > "$CATCHALL_FILTER" <<'EOF'
# Verified 2026-09-30 against real scan/exploit traffic AND a real Let's
# Encrypt HTTP-01 validation request in nginx-error.log. Bans on any 404
# from the catch-all/default server block (server: _), regardless of path —
# deliberately not a path-list, see 36-fail2ban-mail-jails.sh for why.
#
# Second failregex added 2026-09-30 (same day, later audit) after finding
# nginx logs "file not found" two different ways depending on which code
# path hits it: a literal open() failure ("open() \"...\" failed (2: No
# such file or directory)") vs an index/try_files fallback miss ("\"...\"
# is not found (2: No such file or directory)"). The first pattern alone
# was missing ~8% of real catch-all-vhost traffic, including a large,
# ongoing WordPress REST API "batch/v1" exploitation scan (probing /, /wp/,
# /blog/, /wordpress/ with spoofed wp-admin referrers) that was sailing
# through completely unbanned. Verified against the real nginx-error.log
# with `fail2ban-regex`: went from ~92% matched to 4865/4872 lines (the one
# remaining miss is a pre-SNI TLS handshake abort on server: 0.0.0.0:443 —
# a different class of event, not tied to any vhost, too low-volume to
# chase right now).
[INCLUDES]
before = common.conf

[Definition]
failregex = open\(\).*failed \(2: No such file or directory\), client: <HOST>, server: _,
            is not found \(2: No such file or directory\), client: <HOST>, server: _,
ignoreregex = request: "(GET|POST|HEAD) /\.well-known/acme-challenge/
EOF
finalize_backup "$CATCHALL_FILTER"
log "Wrote $CATCHALL_FILTER"

# ============================================================
# nginx-bad-request: a STOCK fail2ban jail — found 2026-09-30 while
# reviewing what else fail2ban ships. Its shipped regex
# (^<HOST> - \S+ \[\] "[^"]*" 400) is nearly byte-for-byte what was
# hand-built here originally as a custom "nginx-catchall-400" filter for
# exactly the same reasoning (malformed/rejected requests — bad protocol,
# path traversal, CONNECT tunneling, garbage bytes sent as HTTP — never
# trigger an nginx "open() failed" error, so they're invisible to
# error-log-based jails despite being real attack traffic, verified against
# 5 real captured lines: a path-traversal probe, the actual Apache cgi-bin
# RCE exploit CVE-2021-41773/42013, a CONNECT proxy-abuse probe, a zgrab
# banner-grab, and raw TLS bytes sent to a plaintext port). Switched to the
# stock jail instead of maintaining a duplicate — same logpath-detection
# caution as nginx-botsearch/nginx-forbidden: its own %(nginx_access_log)s
# variable isn't Debian-path-overridden either, so logpath is still set
# explicitly here rather than relying on the stock default.
#
# Explicitly NOT enabled: stock nginx-forbidden (matches nginx's own
# "access forbidden by rule" deny-rule message). Checked first — even
# though this config does have real `deny all;` rules (grommunio-web,
# grommunio-auth, grommunio-dav), that exact message never appears in
# nginx-error.log (grep count: 0). Our real 403 traffic
# (POST /auth/callback -> 403) comes from grommunio-web's own application
# logic, not nginx's access-control layer, so this jail would silently
# never match anything here — the same "stock filter doesn't fit our
# actual traffic" problem as nginx-botsearch's block-list, just confirmed
# BEFORE enabling it this time instead of after.
# ============================================================

# ============================================================
# grommunio-admin-web-scan: unlike the catch-all jails above, this ONE genuinely
# needs a path-list, because status code can't distinguish real use from
# scanning here. Found 2026-09-30: grommunio-admin-web's SPA fallback route
# serves index.html (200 OK) for ANY unmatched path — so a scanner probing
# /.git/config, /.npmrc, /server-status etc. gets a 200 "success" response
# identical in shape to real admin-web traffic, and nginx never logs an
# error (no failed open()), making it invisible to both jails above.
# Deliberately NOT fixing this by changing admin-web's nginx fallback
# behavior itself — that fallback is legitimately needed for the SPA's own
# client-side routing (deep links like /users, /domains), and narrowing it
# risks breaking real functionality. This list is exactly what's actually
# been observed probing this server; it WILL need updating if new probe
# paths show up, unlike the two jails above.
# ============================================================

local ADMIN_SCAN_FILTER="/etc/fail2ban/filter.d/grommunio-admin-web-scan.conf"

backup_file "$ADMIN_SCAN_FILTER"

cat > "$ADMIN_SCAN_FILTER" <<'EOF'
# Verified 2026-09-30 against real probes from a known mass-scanner
# (user-agent "l9scan", leakix.net) and a curl-based probe, both of which
# got 200 OK from admin-web's SPA fallback route despite hitting paths that
# don't exist. Unlike the catch-all jails, this genuinely needs a
# path-list — see 36-fail2ban-mail-jails.sh for why. Not exhaustive by
# design: this is exactly what's been observed probing this server, add to
# it as new probe paths show up.
#
# Re-verified 2026-09-30 (later same day) after discovering this filter had
# NEVER actually matched anything, including its own listed paths: it was
# missing the datepattern below, so fail2ban's auto-detection failed on
# nginx's bracketed timestamp, the "[]" in failregex (which expects the
# date already stripped) never matched the real "[date]" left in place, and
# every line was silently missed. Copied verbatim from the stock
# nginx-bad-request filter, which handles the same log format correctly.
# The earlier "verification" above was a false positive from testing with
# a bare single-line string instead of a real file — single-line mode
# doesn't reproduce this failure. Lesson: always verify custom filters
# with `fail2ban-regex <realfile> <filterfile>`, never a bare string.
[INCLUDES]
before = common.conf

[Definition]
failregex = ^<HOST> -\S* \S+ \[\] "(GET|POST|HEAD) /(\.git|\.env\S*|\.npmrc|\.DS_Store|\.github|info\.php|trace\.axd|server-status|server-info)\S* HTTP/\d\.\d"
ignoreregex =

datepattern = {^LN-BEG}%%ExY(?P<_sep>[-/.])?%%m(?P=_sep)%%d[T ]%%H:%%M:%%S(?:[.,]%%f)?(?:\s*%%z)?
              ^[^\[]*\[({DATE})
              {^LN-BEG}
EOF
finalize_backup "$ADMIN_SCAN_FILTER"
log "Wrote $ADMIN_SCAN_FILTER"

# ============================================================
# Write the override (never touch jail.conf/jail.local, same convention as
# step 20's zz-hardening.local — this is a SEPARATE file so each step owns
# its own).
# ============================================================

# postfix-smtp-auth: failed AUTH attempts on port 25 (smtpd without SASL
# lines). Postfix logs these only as "disconnect ... auth=0/N" (N >= 1), so the
# stock postfix-sasl jail never sees them. Verified 2026-10-04 with
# fail2ban-regex against the Postfix journal (38 matches, one attacker).
SMTP_AUTH_FILTER="/etc/fail2ban/filter.d/postfix-smtp-auth.conf"
backup_file "$SMTP_AUTH_FILTER"
cat > "$SMTP_AUTH_FILTER" <<'EOF'
[Definition]
failregex = disconnect from \S*\[<HOST>\].*\bauth=0/[1-9]
ignoreregex =
EOF
chmod 644 "$SMTP_AUTH_FILTER"
finalize_backup "$SMTP_AUTH_FILTER"
log "Wrote $SMTP_AUTH_FILTER"

# postfix-smtp-auth-subnet: same log line as postfix-smtp-auth above, but
# captures only the first 3 octets as a named group "fid" (fail2ban's
# own required name for a custom failure identity - NOT <HOST>, and NOT
# a group literally named "host" either: that gets rejected with "No
# failure-id group", confirmed live) so many different IPs in the
# same /24-ish block all count toward ONE ban decision instead of each
# resetting its own counter. Found live 2026-11-05: ~19 different IPs in
# DMZHOST's 92.118.39.0/24 each made 1-2 failed AUTH attempts then moved
# to the next IP - deliberately staying under postfix-smtp-auth's own
# maxretry=5 per IP, so that jail alone never saw an attack at all even
# though the campaign was real and sustained. This jail's own actionban
# (firewallcmd-ipset-cidr / ufw-cidr, see below) widens the ban to the
# IP's real registered network via live whois, not a guessed /24 - a
# provider's actual announced block can be smaller or larger than that.
SMTP_AUTH_SUBNET_FILTER="/etc/fail2ban/filter.d/postfix-smtp-auth-subnet.conf"
backup_file "$SMTP_AUTH_SUBNET_FILTER"
cat > "$SMTP_AUTH_SUBNET_FILTER" <<'EOF'
[Definition]
failregex = disconnect from \S*\[(?P<fid>\d+\.\d+\.\d+)\.\d+\].*\bauth=0/[1-9]
ignoreregex =
EOF
chmod 644 "$SMTP_AUTH_SUBNET_FILTER"
finalize_backup "$SMTP_AUTH_SUBNET_FILTER"
log "Wrote $SMTP_AUTH_SUBNET_FILTER"

# nginx-large-body: nginx's own client_max_body_size rejection ("client
# intended to send too large body") was otherwise unbanned noise. Confirmed
# malicious 2026-10-21, not just oversized-but-legitimate traffic: the same
# unusual size (1,054,492 bytes) hit from 3 different source IPs within
# minutes, all User-Agent "fasthttp" (a Go library used almost exclusively
# by scan/scripting tools, never a real browser), all blind POSTs to the
# bare "/" on a mail server front-end with no upload endpoint there - a
# scripted/botnet signature, not an accident. Verified with fail2ban-regex
# against the real captured lines (8 matches).
# postfix-postscreen: catches postscreen's own cheap protocol-violation
# tests (PREGREET/pipelining/non-SMTP-command/bare-newline, see
# 34-postfix-tls.sh for why these are enabled with action=drop). NOTE: no
# leading ^ anchor on these patterns - found live 2026-10-30 that postfix
# logs these messages with the literal CR/LF bytes still embedded in the
# text, and anchoring broke the match against the systemd-journal backend
# specifically (a plain-file fail2ban-regex test matched fine with the
# anchor; only the journal backend needed it removed - not fully
# understood why, but confirmed live both ways, this is the version that
# actually works against the real journal). Verified with fail2ban-regex
# AND a live trigger against the real postfix (3/3 matches, then a real
# "Ignore <own IP> by ignoreself rule" in fail2ban's own log - proof the
# filter matched, exempted only because the test ran from this box's own
# public IP).
POSTSCREEN_FILTER="/etc/fail2ban/filter.d/postfix-postscreen.conf"
backup_file "$POSTSCREEN_FILTER"
cat > "$POSTSCREEN_FILTER" <<'EOF'
# Fail2Ban filter for postfix's postscreen front-end (port 25 only).
# Catches the four cheap protocol-violation tests enabled 2026-10-30, all
# set to action=drop: PREGREET (client talks before the real greeting),
# COMMAND PIPELINING, NON-SMTP COMMAND, BARE NEWLINE (same documented
# postscreen log format, same <TAG> ... from [IP]:port structure). No
# leading ^ anchor - see 36-fail2ban-mail-jails.sh for why.
[INCLUDES]
before = common.conf

[Definition]
failregex = PREGREET \d+ after [\d.]+ from \[<HOST>\]:\d+:
            COMMAND PIPELINING from \[<HOST>\]:\d+
            COMMAND COUNT LIMIT from \[<HOST>\]:\d+
            NON-SMTP COMMAND from \[<HOST>\]:\d+:
            BARE NEWLINE from \[<HOST>\]:\d+:
ignoreregex =
EOF
chmod 644 "$POSTSCREEN_FILTER"
finalize_backup "$POSTSCREEN_FILTER"
log "Wrote $POSTSCREEN_FILTER"

LARGE_BODY_FILTER="/etc/fail2ban/filter.d/nginx-large-body.conf"
backup_file "$LARGE_BODY_FILTER"
cat > "$LARGE_BODY_FILTER" <<'EOF'
[Definition]
failregex = client intended to send too large body: \d+ bytes, client: <HOST>,
ignoreregex =
EOF
chmod 644 "$LARGE_BODY_FILTER"
finalize_backup "$LARGE_BODY_FILTER"
log "Wrote $LARGE_BODY_FILTER"

backup_file "$OVERRIDE_FILE"

cat > "$OVERRIDE_FILE" <<EOF
# Managed by server-setup.sh / 36-fail2ban-mail-jails.sh — do not edit
# Debian-shipped jail.conf/jail.local. This file is the override layer.
#
# postfix-sasl and nginx-botsearch are stock fail2ban jails/filters
# (verified against this server's actual log lines/paths); no custom
# regexes here.

[postfix-sasl]
enabled = true
banaction = ${banaction}
bantime = 1h
findtime = 1h
maxretry = 5

[postfix-abuse]
enabled = true
filter = postfix[mode=aggressive]
backend = systemd
journalmatch = _SYSTEMD_UNIT=postfix.service
banaction = ${banaction}
# bantime widened to 24h (2026-11-05, same reasoning as postfix-smtp-auth's
# own widening the same day): findtime is already 8h, so a 1h ban was just
# churn - old failures keep counting toward the next ban regardless.
bantime = 24h
findtime = 8h
maxretry = 3
# REAL GAP FOUND AND FIXED 2026-10-23: the user spotted repeated "improper
# command pipelining after CONNECT" lines from the same IP (152.32.250.21,
# reconnecting ~every 0.3-0.4s, sending a raw TLS ClientHello instead of
# STARTTLS) that nothing was banning. Neither postfix-sasl (filter=
# postfix[mode=auth], only matches actual SASL AUTH failures) nor
# postfix-smtp-auth (its own narrower filter, only matches a
# disconnect/auth=0 pattern) covers this - it is a different failure
# category (protocol/connection abuse, not an auth attempt at all).
#
# Checked with fail2ban-regex against the real journal, not guessed, and
# escalated the mode twice as the real scale became clear:
#   mode=normal:     731 matching lines (the pipelining/reject/milter-
#                     reject/too-many-errors prefixes).
#   mode=ddos:        988 matching lines - a MOSTLY DIFFERENT set (PREGREET/
#                     HANGUP/COMMAND LIMIT/slow lost-connection-after-X
#                     prefixes), not a subset of mode=normal's hits.
#   mode=aggressive:  1762 matching lines - normal + ddos + auth combined
#                     (some overlap with postfix-sasl's own auth coverage
#                     is expected and harmless - just two jails agreeing
#                     faster on the same bad actor).
# Settled on mode=aggressive rather than normal alone, since normal was
# already shown to miss a comparable-sized second category (ddos-prefixed
# lines) that a real scanner just as plausibly produces.
#
# maxretry=3 chosen to match nginx-catchall-scan's reasoning: this pattern
# is dominated by fast automated scanning (confirmed: 10+ hits in ~3
# seconds from a single IP), not slow deliberate pacing.
#
# findtime WIDENED to 8h on 2026-10-30 (was 1h, as predicted right above
# this very comment): a full-log sweep found IPs (92.118.39.65/.58) with
# 16-17 hits each, never banned, spaced 4-7h apart - confirmed via raw
# timestamps as deliberate pacing just outside the old 1h window, the
# same lesson postfix-smtp-auth already learned the hard way below.

[postfix-smtp-auth]
enabled = true
filter = postfix-smtp-auth
backend = systemd
journalmatch = _SYSTEMD_UNIT=postfix.service
banaction = ${banaction}
# bantime=24h (not 1h): widened 2026-11-05 to match findtime below - at
# findtime=24h a 1h ban was pointless churn (the admin's own catch, see
# postfix-smtp-auth-subnet just below, added the same day with bantime=24h
# from the start). Old failures stay counted for the full 24h window
# regardless of ban state, so a 1h ban never actually let a real repeat
# offender back in cleanly anyway - this just stops the repeated
# ban/unban/re-ban cycle in the logs.
bantime = 24h
# findtime=24h (not 1h): found live on testvps 2026-10-08 that several IPs
# (91.92.243.20, 64.89.161.83, 160.250.128.49, 178.16.54.250, 178.16.53.59)
# failed SMTP auth 60-300+ times each over many hours, spaced ~20+ minutes
# apart - slow enough that at findtime=1h they never hit maxretry=5 and were
# never banned. maxretry stays 5 (the admin's decision: widen the window,
# keep the retry count as-is) - only the window widens, so a real but slow
# repeat offender now accumulates across a full day instead of resetting
# every hour.
findtime = 24h
maxretry = 5

[postfix-smtp-auth-subnet]
enabled = true
filter = postfix-smtp-auth-subnet
backend = systemd
journalmatch = _SYSTEMD_UNIT=postfix.service
banaction = ${banaction_subnet}
bantime = 24h
findtime = 24h
# maxretry higher than postfix-smtp-auth's own 5: this jail aggregates
# failures across every IP in roughly the same /24, so the count climbs
# much faster than any single attacker ever would on their own - 15
# distinct failed-AUTH log lines from the same block within a day is
# already far outside anything a real, single residential/business
# connection produces.
maxretry = 15

[postfix-postscreen]
enabled = true
filter = postfix-postscreen
backend = systemd
journalmatch = _SYSTEMD_UNIT=postfix.service
banaction = ${banaction}
bantime = 1d
findtime = 1h
maxretry = 2

[nginx-botsearch]
enabled = true
backend = auto
logpath = ${nginx_error_log}
banaction = ${banaction}
bantime = 1h
findtime = 1h
maxretry = 2

[nginx-catchall-scan]
enabled = true
backend = auto
logpath = ${nginx_error_log}
banaction = ${banaction}
# bantime widened to 24h (2026-11-05, same reasoning as postfix-smtp-auth's
# own widening the same day): findtime is already 12h, so a 1h ban was just
# churn - old failures keep counting toward the next ban regardless.
bantime = 24h
# findtime widened from 1h (2026-10-30): a full-log sweep found several IPs
# (e.g. 2a01:7c8:d005:8a::1, 9 hits) spread 3-18h apart over days, confirmed
# via raw timestamps as deliberate pacing just outside the old 1h window -
# same evasion pattern already fixed for sshd/postfix-abuse/nginx-bad-request.
findtime = 12h
maxretry = 3

[nginx-bad-request]
enabled = true
backend = auto
logpath = ${nginx_access_log}
banaction = ${banaction}
# bantime widened to 24h (2026-11-05, same reasoning as postfix-smtp-auth's
# own widening the same day): findtime is already 6h, so a 1h ban was just
# churn - old failures keep counting toward the next ban regardless.
bantime = 24h
# findtime widened from 1h (2026-10-30): a full-log sweep found
# 45.135.193.193 with 14 hits here (and another 14 in grommunio-admin-400
# from the same requests), spread hours apart over several days -
# deliberate pacing just outside the old 1h window, confirmed via raw
# timestamps.
findtime = 6h
maxretry = 3

[grommunio-admin-web-scan]
enabled = true
backend = auto
logpath = ${nginx_admin_access_log}
banaction = ${banaction}
bantime = 1h
findtime = 1h
maxretry = 3

# Option A from the 2026-09-30 admin-web scanning discussion: same reuse of
# the stock nginx-bad-request filter as the jail above, just pointed at
# admin-web's own log instead of the main vhost's. Catches the malformed/
# empty/TLS-garbage subset of admin-web scanning that grommunio-admin-web-scan
# above can't (that one is a path-list and none of these hit a listed path).
# Does NOT catch scanners that get a clean 200 on GET / (visionheight.com,
# Palo Alto Cortex Xpanse, etc.) — no status/content-based filter can, since
# a real visitor's first request looks identical. Shipped DISABLED by
# default per the user's explicit request — enable by flipping this to
# Enabled 2026-10-01: a full filter-vs-real-log audit found the scanning
# against admin-web had grown far beyond what the path-list
# (grommunio-admin-web-scan) can ever cover — of 485 lines it missed in one
# day, 405 were 200-status SPA-fallback responses (uncatchable by any
# status-based filter, path-list is the only lever) and 65 were genuine
# 400s (malformed requests, protocol confusion, open-proxy abuse attempts)
# that THIS jail catches. User explicitly rejected the more complete fix
# (restricting admin-web to the IP whitelist, option C from the original
# discussion below) — open access to admin-web is a hard requirement, not
# just an unexplored option. So this jail is now enabled by default: a
# partial but real improvement (catches the 400 subset) that doesn't
# compromise open access.
[grommunio-admin-400]
enabled = true
filter = nginx-bad-request
backend = auto
logpath = ${nginx_admin_access_log}
banaction = ${banaction}
bantime = 1h
findtime = 1h
# Lowered from 3 (2026-10-30, by request): a real targeted login burst
# against the 'admin' account (109.36.129.19, 2026-10-28) hit this jail
# once and grommunio-admin-api 3 times - neither jail's own threshold was
# reached (each counts independently, not combined), so no ban happened at
# all despite 4 failed admin-login attempts in under a minute. This jail
# specifically targets a named, real account, not generic scanning - a
# lower threshold here has no legitimate-user risk.
maxretry = 2

# Added 2026-10-21: nginx's client_max_body_size rejection, otherwise
# unbanned - see filter.d/nginx-large-body.conf for why this was confirmed
# malicious (not just an oversized-but-legitimate upload) before adding it.
[nginx-large-body]
enabled = true
backend = auto
logpath = ${nginx_error_log}
banaction = ${banaction}
bantime = 1h
findtime = 1h
maxretry = 3
EOF
chmod 644 "$OVERRIDE_FILE"
finalize_backup "$OVERRIDE_FILE"
log "Wrote $OVERRIDE_FILE"

# ============================================================
# Validate, apply, verify
# ============================================================

log "Validating fail2ban configuration..."
fail2ban-client -t

if [[ "$banaction" == "firewallcmd-ipset" ]]; then
    firewalld_jail_sets postfix-sasl=25,465,587,110,143,993,995 postfix-smtp-auth=25,465,587 nginx-botsearch=80,443 nginx-bad-request=80,443 nginx-catchall-scan=80,443 nginx-large-body=80,443 grommunio-admin-web-scan=80,443 grommunio-admin-400=80,443
    firewall-cmd --reload >/dev/null
fi

log "Restarting fail2ban..."
systemctl restart fail2ban
sleep 1

local verify_failed=0
for jail in postfix-sasl postfix-smtp-auth nginx-botsearch nginx-catchall-scan nginx-bad-request nginx-large-body grommunio-admin-web-scan grommunio-admin-400; do
    if fail2ban-client status "$jail" >/dev/null 2>&1; then
        log "[ OK ] jail active: $jail"
    else
        err "[FAIL] jail not active: $jail"
        verify_failed=1
    fi
done

[[ "$verify_failed" -eq 0 ]] || die "One or more mail-protection jails failed to start — see errors above."

echo
echo "============================================================"
echo " Done"
echo "============================================================"
echo
fail2ban-client status
echo
}
