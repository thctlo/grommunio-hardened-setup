#!/usr/bin/env bash
#
# 37-fail2ban-gromox-jails.sh
#
# Adds fail2ban protection for the gromox/grommunio services that were
# left uncovered after 36-fail2ban-mail-jails.sh (postfix, nginx-botsearch):
# IMAP, POP3, WebDAV/CalDAV/CardDAV, ActiveSync (grommunio-sync),
# grommunio-web's own login form, the admin-api control panel, and the
# generic gromox-http HTTP auth path (EWS/RPC/OAB/Autodiscover).
#
# Naming convention (settled 2026-09-30, for future packaging — each jail
# should be named after the exact binary package/service it protects, so
# that package can ship its own filter.d/jail.d snippet later):
#   gromox-imap, gromox-pop3, gromox-http    -> package "gromox"
#   grommunio-web-auth                        -> package "grommunio-web"
#   grommunio-dav                             -> package "grommunio-dav"
#   grommunio-sync                            -> package "grommunio-sync"
#   grommunio-admin-api                       -> package "grommunio-admin-api"
#   grommunio-admin-web-scan (in step 36)      -> package "grommunio-admin-web"
# Generic, not-tied-to-one-package jails (sshd, postfix-sasl, nginx-*) live
# in step 20/36 instead and keep their own generic names.
#
# findtime=1h on every jail here (not the original 10m) — same fix applied
# to 36-fail2ban-mail-jails.sh the same day, for the same reason: a bot
# pacing attempts a few minutes apart can otherwise never accumulate
# maxretry failures inside a 10-minute window no matter how long it keeps
# trying, since older attempts age out before newer ones arrive. maxretry
# and bantime per jail are unchanged, including grommunio-sync's
# deliberately higher maxretry=9 (mobile device re-registration retries).
#
# Source material: github.com/crpb/grommunio/tree/main/setup/fail2ban
# (Walter Hofstaedtler's community fail2ban package). Its wrapper install.sh
# was NOT used (runs a full apt dist-upgrade, edits jail.local directly, and
# extracts a third-party tarball straight into / unreviewed). Instead, each
# filter's regex was extracted and verified with `fail2ban-regex` against a
# REAL log line captured by deliberately triggering a failed login against
# this server's actual gromox 3.11.5 + Debian 13 install (see
# testvps-provisioning-framework memory for the full before/after). Result:
#
#   - gromox-imap / gromox-pop3: Walter's original regex required the
#     literal text "rejected:" — our IMAP daemon actually logs "rejecting"
#     (present participle), so his filter never matched IMAP at all. Fixed
#     to accept both forms and verified against both a real captured line
#     and a synthetic ::ffff:-mapped IPv4 line (confirms <HOST> correctly
#     strips the IPv4-mapping prefix).
#   - grommunio-web-auth: Walter's regex used a bare `*` where he meant
#     ".*" (a very easy regex mistake — bare `*` just means "zero or more
#     of the preceding character", not "any characters"). It required
#     "MAPI" to be followed immediately by nothing but extra spaces before
#     "client:", which never happens in the real nginx error log line.
#     Fixed and verified against a real captured line.
#   - grommunio-dav: Walter's original regex works correctly as captured,
#     verified against a real triggered failure. Kept unchanged, including
#     his ignoreregex for the log's own "main Uncaught exception" trailer
#     line that follows every DAV auth failure (confirmed present in our
#     own capture too — would double-count without it).
#   - grommunio-sync: Walter's original regex works correctly as captured,
#     but ONLY once LOGAUTHFAIL is turned on in grommunio-sync's own config
#     (off by default under grommunio-setup) — this step turns it on.
#
# Two more jails added afterward, not from Walter's package — found by
# independently checking what else on this server had zero fail2ban
# coverage despite being internet-facing:
#   - grommunio-admin-api: the admin control panel (full control over
#     domains/mailboxes/everything) logs failed logins cleanly
#     ("Failed login attempt for user 'X' from 'IP'") but had no jail at
#     all. Verified against a real triggered failure.
#   - gromox-http: a single generic "HTTP auth rejected" line gromox-http itself logs
#     for EWS, RPC (Outlook), OAB, and Autodiscover — all of which proxy
#     through it and had no jail individually. Verified against a real
#     triggered EWS failure. Note: a failed /web login can end up counted
#     by both this jail and grommunio-web-auth (grommunio-
#     web's own PHP layer logs its own failure too) — harmless redundancy,
#     not double-ban-worthy, just means either jail can trip first.
#
# All real log lines this was verified against, and the fail2ban-regex
# commands used, are recorded in the testvps-provisioning-framework memory
# entry for 2026-09-28, not repeated here.

step_fail2ban_gromox_jails()
{
local FILTER_DIR="/etc/fail2ban/filter.d"
local OVERRIDE_FILE="/etc/fail2ban/jail.d/zz-gromox-hardening.local"
local SYNC_CONF="/etc/grommunio-sync/grommunio-sync.conf.php"

require_cmd fail2ban-client
require_cmd systemctl

# ============================================================
# Reuse step 20's firewall backend decision, same as step 36.
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
log "Using banaction=$banaction (firewall backend: $FW_BACKEND)"

# ============================================================
# Prerequisite: LOGAUTHFAIL must be on for grommunio-sync's filter to have
# anything to match. Detect current state, only edit if needed, back up
# first, reload php-fpm so the change actually takes effect.
# ============================================================

if [[ ! -f "$SYNC_CONF" ]]; then
    err "$SYNC_CONF not found — is grommunio-sync installed? Run grommunio-setup first."
    return 1
fi

if grep -qE "define\('LOGAUTHFAIL', *true\)" "$SYNC_CONF"; then
    log "LOGAUTHFAIL already enabled in $SYNC_CONF."
else
    backup_file "$SYNC_CONF"
    sed -i "s/define('LOGAUTHFAIL', *false)/define('LOGAUTHFAIL', true)/" "$SYNC_CONF"
    if ! grep -qE "define\('LOGAUTHFAIL', *true\)" "$SYNC_CONF"; then
        die "Failed to enable LOGAUTHFAIL in $SYNC_CONF — its format may have changed; check manually."
    fi
    finalize_backup "$SYNC_CONF"
    log "Enabled LOGAUTHFAIL in $SYNC_CONF."
    if systemctl is-active --quiet php8.4-fpm; then
        systemctl reload php8.4-fpm
        log "Reloaded php8.4-fpm so grommunio-sync picks up the change."
    fi
fi

# ============================================================
# Confirm the nginx log exists before wiring filters to it, and create the
# lazily-written service logs (grommunio-sync.log, dav.log) so their jails
# have a file to tail.
# ============================================================

if [[ ! -f /var/log/nginx/nginx-web-error.log ]]; then
    err "Expected log file not found: /var/log/nginx/nginx-web-error.log"
    err "Is nginx/grommunio-web actually in use yet on this server?"
    return 1
fi

# grommunio-sync.log and dav.log are created lazily by their services (on the
# first logged event). Create them empty with the owner the service uses, so
# fail2ban has a file to tail from the start. The service appends to them.
mkdir -p /var/log/grommunio-sync
touch /var/log/grommunio-sync/grommunio-sync.log
chown grosync:grosync /var/log/grommunio-sync/grommunio-sync.log 2>/dev/null || true

mkdir -p /var/log/grommunio-dav
touch /var/log/grommunio-dav/dav.log 2>/dev/null || true
chown grodav:grodav /var/log/grommunio-dav/dav.log 2>/dev/null || true

# ============================================================
# Filter files — never touch fail2ban's own shipped filter.d files, these
# are new grommunio-specific ones.
# ============================================================

write_filter()
{
    local file="$1"; shift
    backup_file "$file"
    cat > "$file"
    finalize_backup "$file"
    log "Wrote $file"
}

write_filter "${FILTER_DIR}/gromox-imap.conf" <<'EOF'
# Verified 2026-09-28 against a real gromox-imap failed-login log line.
# Walter Hofstaedtler's original regex required "rejected:" — this gromox
# version logs "rejecting" instead; fixed to accept both.
[INCLUDES]
before = common.conf

[Definition]
failregex = rhost=\[<HOST>\]\S* user=\S+.*\breject(?:ed|ing)\b
ignoreregex =

[Init]
journalmatch = _SYSTEMD_UNIT=gromox-imap.service
EOF

write_filter "${FILTER_DIR}/gromox-pop3.conf" <<'EOF'
# Verified 2026-09-28 against a real gromox-pop3 failed-login log line.
[INCLUDES]
before = common.conf

[Definition]
failregex = rhost=\[<HOST>\]\S* user=\S+.*\breject(?:ed|ing)\b
ignoreregex =

[Init]
journalmatch = _SYSTEMD_UNIT=gromox-pop3.service
EOF

write_filter "${FILTER_DIR}/grommunio-web-auth.conf" <<'EOF'
# Verified 2026-09-28 against a real grommunio-web failed-login log line
# (nginx-web-error.log). Walter Hofstaedtler's original regex used a bare
# "*" where he meant ".*" (a common regex slip), so it never matched.
[INCLUDES]
before = common.conf

[Definition]
failregex = authentication failure at MAPI.*client: <HOST>
ignoreregex =
EOF

write_filter "${FILTER_DIR}/grommunio-dav.conf" <<'EOF'
# Verified 2026-09-28 against a real grommunio-dav failed-login log line
# (dav.log). failregex/ignoreregex kept as Walter Hofstaedtler originally
# wrote them — they already match this gromox version correctly.
# ignoreregex targets the "main Uncaught exception" trailer line that
# follows every DAV auth failure (present in our own capture too).
# datepattern added: dav.log's "28.09.2026 21:06:58" format was NOT
# recognized by fail2ban's automatic date-detection at all (confirmed via
# `fail2ban-regex` — zero date template hits across every real line),
# which would make every match get evaluated as "right now" instead of its
# real time — harmless for live detection but explicit is safer.
[INCLUDES]
before = common.conf

[Definition]
failregex = dav.*user.\S*.*IP.(<HOST>)
ignoreregex = .*main Uncaught exception$
datepattern = %%d.%%m.%%Y %%H:%%M:%%S
EOF

write_filter "${FILTER_DIR}/grommunio-sync.conf" <<'EOF'
# Verified 2026-09-28 against a real grommunio-sync failed-login log line
# (grommunio-sync.log), once LOGAUTHFAIL was enabled. Kept as Walter
# Hofstaedtler originally wrote it — matches correctly as-is.
# Timezone fixed properly 2026-10-01 (was previously an accepted quirk): the
# log has no timezone marker and is written in UTC while the server runs
# CEST, so fail2ban misread every timestamp as 2 hours in the past and
# logged a "timezone problem" warning on every single line. The jail's
# `logtimezone = UTC` setting below is fail2ban's own documented option for
# exactly this situation (a log with no embedded timezone, confirmed via
# `man jail.conf`) — it tells fail2ban the log's true timezone instead of
# letting it guess, which fixes the root cause rather than just living with
# the warning. Confirmed live: a fresh real log line after this change
# produced zero timezone warnings.
[INCLUDES]
before = common.conf

[Definition]
failregex = IP: <HOST> failed to authenticate user
ignoreregex =
EOF

write_filter "${FILTER_DIR}/grommunio-admin-api.conf" <<'EOF'
# Verified 2026-09-28 against a real grommunio-admin-api failed-login log
# line (journal). Not from Walter Hofstaedtler's package — the admin
# control panel had no fail2ban coverage anywhere before this.
#
# Second failregex added 2026-09-30 after real endpoint-enumeration traffic
# (GET /api/v1/endpoints, /api/v1/openapi.json, /api/v1/query/-/healthy,
# etc., all 404) was found completely unmatched by the login-only pattern
# above — the scanner never attempts a login at all, so it never produces
# the "Failed login attempt" line. Verified against real journal lines via
# `fail2ban-regex <dumped-journal-file> <this-file>`. Deliberately excludes
# 401 responses: those come from real endpoints hit without a token, which
# could plausibly happen during a legitimate token-refresh race, whereas a
# 404 means the path doesn't exist at all — no real admin-web frontend
# should ever request a genuinely nonexistent API route. Note the real log
# line has NO quotes around the IP ("from 93.1.2.3 -> 404"), unlike the
# login-failure line above ("from '<HOST>'") — easy to miss if copying the
# quoting style from the first pattern.
[INCLUDES]
before = common.conf

[Definition]
failregex = Failed login attempt for user '\S+' from '<HOST>'
            from <HOST> -> 404
ignoreregex =

[Init]
journalmatch = _SYSTEMD_UNIT=grommunio-admin-api.service
EOF

write_filter "${FILTER_DIR}/gromox-http.conf" <<'EOF'
# Verified 2026-09-28 against a real triggered EWS failed-login log line
# (journal). Not from Walter Hofstaedtler's package. gromox-http logs one
# generic "HTTP auth rejected" line for every protocol it backs, so this
# single filter also covers RPC (Outlook), OAB and Autodiscover, none of
# which had individual coverage before this. A failed /web login can also
# match this (gromox-http sits underneath grommunio-web too) in addition
# to grommunio-web-auth above — harmless redundancy, not fixed.
[INCLUDES]
before = common.conf

[Definition]
failregex = rhost=\[<HOST>\]\S* user=\S+ HTTP auth rejected:
ignoreregex =

[Init]
journalmatch = _SYSTEMD_UNIT=gromox-http.service
EOF

# ============================================================
# Jail override — separate file from steps 20 and 36, same convention.
# maxretry/bantime for sync intentionally higher (matches Walter's own
# tuning): mobile device re-registration can legitimately retry several
# times before giving up, so a low threshold there causes false positives.
# ============================================================

backup_file "$OVERRIDE_FILE"

cat > "$OVERRIDE_FILE" <<EOF
# Managed by server-setup.sh / 37-fail2ban-gromox-jails.sh — do not edit
# Debian-shipped jail.conf/jail.local. This file is the override layer.
#
# Filters here are grommunio-specific and were verified against real log
# lines captured on this server (see filter.d/grommunio-*.conf headers and
# the testvps-provisioning-framework memory entry for 2026-09-28).

[gromox-imap]
enabled = true
backend = systemd
port = imap,imaps
banaction = ${banaction}
bantime = 2h
findtime = 1h
maxretry = 3

[gromox-pop3]
enabled = true
backend = systemd
port = pop3,pop3s
banaction = ${banaction}
bantime = 2h
findtime = 1h
maxretry = 3

[grommunio-web-auth]
enabled = true
backend = auto
logpath = /var/log/nginx/nginx-web-error.log
port = http,https
banaction = ${banaction}
bantime = 1h
findtime = 1h
maxretry = 5

[grommunio-dav]
enabled = true
backend = auto
logpath = /var/log/grommunio-dav/dav.log
port = http,https
banaction = ${banaction}
bantime = 2h
findtime = 1h
maxretry = 3

[grommunio-sync]
enabled = true
backend = auto
logpath = /var/log/grommunio-sync/grommunio-sync.log
port = http,https
banaction = ${banaction}
bantime = 1h
findtime = 1h
maxretry = 9
logtimezone = UTC

[grommunio-admin-api]
enabled = true
backend = systemd
port = 8080,8443
banaction = ${banaction}
bantime = 2h
findtime = 1h
# Lowered from 5 (2026-10-30, by request) - see the matching comment next
# to grommunio-admin-400 in 36-fail2ban-mail-jails.sh for why: a real
# targeted login burst against 'admin' hit this jail 3 times and
# grommunio-admin-400 once, neither jail's own threshold was reached since
# they count independently, so no ban happened despite 4 failed attempts
# on a named real account in under a minute.
maxretry = 2

[gromox-http]
enabled = true
backend = systemd
port = http,https
banaction = ${banaction}
bantime = 1h
findtime = 1h
maxretry = 5
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
    firewalld_jail_sets grommunio-web-auth=80,443 grommunio-dav=80,443 grommunio-sync=80,443 grommunio-admin-api=8080,8443 gromox-http=80,443 gromox-imap=143,993 gromox-pop3=110,995
    firewall-cmd --reload >/dev/null
fi

log "Restarting fail2ban..."
systemctl restart fail2ban
sleep 1

local verify_failed=0
for jail in gromox-imap gromox-pop3 grommunio-web-auth grommunio-dav grommunio-sync grommunio-admin-api gromox-http; do
    if fail2ban-client status "$jail" >/dev/null 2>&1; then
        log "[ OK ] jail active: $jail"
    else
        err "[FAIL] jail not active: $jail"
        verify_failed=1
    fi
done

[[ "$verify_failed" -eq 0 ]] || die "One or more gromox-protection jails failed to start — see errors above."

echo
echo "============================================================"
echo " Done"
echo "============================================================"
echo
fail2ban-client status
echo
}
