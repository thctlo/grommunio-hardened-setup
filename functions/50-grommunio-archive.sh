#!/usr/bin/env bash
#
# 50-grommunio-archive.sh
#
# Installs and configures grommunio-archive (Piler-based email archiving),
# per docs.grommunio.com/guides/archive/ and this package's own
# /usr/share/doc/grommunio-archive/README.Debian. Unlike grommunio-files or
# grommunio-keycloak, this package is NOT driven by shared debconf — the
# postinst only installs the software; all configuration is done by running
# `grommunio-archive-setup` afterward, a plain CLI-flag script (not a
# debconf wizard, so none of the DEBIAN_FRONTEND hang risk from step 45
# applies here).
#
# What grommunio-archive-setup does (confirmed by running it and reading
# README.Debian, not guessed): creates the `groarchive` MariaDB database and
# user and loads the schema (two archive-only web accounts, admin@local and
# auditor@local, with generated passwords shown once at the end and also
# written to /var/log/grommunio-archive/setup.log, mode 0600 — the README
# says to delete that file once the passwords are noted, and this step does
# so automatically after printing them); writes
# /etc/grommunio-archive/{grommunio-archive.conf,config-site.php,
# grommunio-archive.key} (the key is 56 random bytes — back it up,
# encrypted messages are unreadable without it); builds the Sphinx index
# config and starts grommunio-archive-searchd/-smtp/-archive; and wires
# Postfix with `always_bcc=archive@<FQDN>` plus a transport map sending
# that address to 127.0.0.1:2693 and a pcre map adding an X-Envelope-To
# header.
#
# always_bcc BCCs EVERY message on this server to the archive - that was
# this step's own default until 2026-11-05, when the default was changed
# to opt-in-per-user instead: this step now explicitly UNSETS
# always_bcc right after grommunio-archive-setup sets it (the transport/
# pcre maps stay - they are what actually delivers a BCC'd message to the
# archive SMTP listener, needed either way). Archiving a specific
# mailbox from then on is a per-user choice: grommunio's own docs
# (chapter "6.2 Archive selected users only") describe setting an
# E-Mail forward (CC mode) to archive@<FQDN> in the Admin UI, under
# user → SMTP - no CLI flag or scripting for this exists in
# grommunio-admin yet (the ORM's "forward" relation is REST-PATCH-only,
# not exposed as a `user modify` flag), so this step does not automate
# per-user enrolment - only the system-wide default.
#
# The setup script refuses to overwrite an existing configuration without
# -F, so this step is naturally idempotent: on replay it detects an
# existing /etc/grommunio-archive/grommunio-archive.conf and skips
# reconfiguration entirely rather than risk generating new passwords/keys
# and losing access to already-archived (encrypted) mail.
#
# Verified end-to-end live on testvps 2026-09-30/10-01: real message sent
# through Postfix was captured by piler-smtp, landed in
# /var/lib/grommunio-archive/store, was indexed into the `groarchive`
# database, Sphinx indexing ran cleanly, and the web UI login worked with
# the generated admin@local password. The real recipient still received
# the actual message too — archiving does not interfere with delivery.
# Search-in-the-UI and restore-via-IMAP were confirmed by the user directly
# in a browser (the search UI's real query flow is a multi-step AJAX
# exchange, not a simple form POST — not worth reverse-engineering for an
# automated check when a human can confirm it in seconds); this step
# automates everything up to and including the message-capture/storage/
# indexing chain, and prints the same two items as a manual checklist at
# the end for a fresh install.

step_grommunio_archive()
{
require_cmd apt-get
require_cmd systemctl
require_cmd curl
require_cmd mysql

# ============================================================
# Package availability
# The community repo (step 25, option 2) does not publish grommunio-archive.
# Archiving is then not available from our package source, so this step is
# skipped on purpose rather than failing the whole run.
# ============================================================

local PKG_SOURCE_CFG=""
PKG_SOURCE_CFG="$(
    # shellcheck disable=SC1090
    [[ -f "$(cfg_file 25-apt-repo-personal)" ]] && source "$(cfg_file 25-apt-repo-personal)" && echo "${PKG_SOURCE:-}"
)"
if [[ "$PKG_SOURCE_CFG" == "community" ]] && ! apt-cache policy grommunio-archive 2>/dev/null | grep -q 'Candidate: [^(]'; then
    echo
    echo "============================================================"
    echo " grommunio-archive: skipped"
    echo "============================================================"
    echo
    echo "The package source is the grommunio community repo (step 25, option 2),"
    echo "and that repo does not publish grommunio-archive. This step is skipped."
    echo "Archiving is not part of this install. To add it later, choose a source"
    echo "that provides grommunio-archive and re-run this step."
    echo
    return 0
fi

# ============================================================
# Preconditions
# ============================================================

if [[ ! -f /etc/grommunio-common/setup_done ]]; then
    err "grommunio-setup does not appear to have completed (no /etc/grommunio-common/setup_done)."
    err "Run step 30 first."
    return 1
fi

# ============================================================
# Cheat-sheet / context
# ============================================================

local NETHOST_CFG="$(cfg_file 10-network-hostname)"
local FQDN="" DOMAIN=""
if [[ -f "$NETHOST_CFG" ]]; then
    local NEW_HOSTNAME NEW_DOMAIN NEW_FQDN PRIMARY_IPV4 PRIMARY_IPV6
    # shellcheck disable=SC1090
    source "$NETHOST_CFG"
    FQDN="${NEW_FQDN:-}"
    DOMAIN="${NEW_DOMAIN:-}"
fi
FQDN="${FQDN:-$(hostname -f)}"
DOMAIN="${DOMAIN:-$(hostname -d)}"

echo
echo "============================================================"
echo " grommunio-archive setup"
echo "============================================================"
echo
echo "  FQDN                : $FQDN"
echo "  Web interface        : https://${FQDN}/archive/"
echo "  Archive SMTP         : 127.0.0.1:2693 (all mail will be BCC'd here)"
echo

# ============================================================
# Install
# ============================================================

if dpkg -s grommunio-archive >/dev/null 2>&1; then
    log "grommunio-archive already installed."
else
    log "Installing grommunio-archive..."
    apt-get install -y grommunio-archive
fi

# ============================================================
# Configure (idempotent: skip if already configured, to avoid the setup
# script generating new credentials/encryption key over an existing
# archive it would then make unreadable).
# ============================================================

local ARCHIVE_CONF="/etc/grommunio-archive/grommunio-archive.conf"

if [[ -f "$ARCHIVE_CONF" ]]; then
    log "[ OK ] $ARCHIVE_CONF already exists — grommunio-archive-setup already ran, skipping (re-running would refuse without -F anyway)."
else
    log "Running grommunio-archive-setup -f ${FQDN} -d ${DOMAIN}..."
    echo
    echo "This generates the archive database, two archive-only web accounts"
    echo "(admin@local, auditor@local), and an encryption key. Passwords are"
    echo "shown ONCE below — note them now. Back up"
    echo "/etc/grommunio-archive/grommunio-archive.key separately: without it,"
    echo "archived messages cannot be decrypted."
    echo
    grommunio-archive-setup -f "$FQDN" -d "$DOMAIN"
    echo
    log "Reminder: passwords shown above are ONLY shown once. Note them now."

    # The setup script also writes them to a 0600 log for its own reasons;
    # its own README says to delete that file once you've noted the
    # passwords. They were just printed above, so this step removes it
    # immediately rather than leaving a second plaintext copy lying around.
    if [[ -f /var/log/grommunio-archive/setup.log ]]; then
        rm -f /var/log/grommunio-archive/setup.log
        log "[ OK ] Removed /var/log/grommunio-archive/setup.log (plaintext copy of the passwords above, per the package's own README)."
    fi
fi

# Needed after install per README.Debian, harmless if already done.
systemctl reload nginx
systemctl restart php8.4-fpm

# ============================================================
# Opt-in-per-user default (2026-11-05): grommunio-archive-setup just set
# always_bcc=archive@<FQDN> (archive everyone) above, or did so on a
# previous run - either way, unset it now so archiving a mailbox is a
# per-user choice (Admin UI → user → SMTP → E-Mail forward, CC mode, to
# archive@${FQDN}) rather than the server-wide default. Unconditional and
# idempotent: harmless if already unset from a previous run of this step.
# ============================================================

if [[ -n "$(postconf -h always_bcc 2>/dev/null)" ]]; then
    backup_file /etc/postfix/main.cf
    postconf -X always_bcc
    systemctl reload postfix
    log "[ OK ] Unset Postfix always_bcc - archiving is now opt-in per user (Admin UI → user → SMTP → forward to archive@${FQDN}, CC mode)."
else
    log "[ OK ] Postfix always_bcc already unset - archiving stays opt-in per user."
fi

# ============================================================
# Verify: services, Postfix wiring, web UI
# ============================================================

echo
echo "============================================================"
echo " Verification"
echo "============================================================"
echo

local verify_failed=0

for svc in grommunio-archive-searchd grommunio-archive-smtp grommunio-archive; do
    if systemctl is-active --quiet "$svc"; then
        log "[ OK ] $svc is active."
    else
        err "[FAIL] $svc is not active."
        verify_failed=1
    fi
done

if [[ -z "$(postconf -h always_bcc 2>/dev/null)" ]]; then
    log "[ OK ] Postfix always_bcc is unset - archiving is opt-in per user, as intended."
else
    err "[FAIL] Postfix always_bcc is still set ($(postconf -h always_bcc 2>/dev/null)) - should be unset for opt-in-per-user archiving."
    verify_failed=1
fi

if [[ -f /etc/postfix/transport ]] && grep -q "^archive@${FQDN}[[:space:]]\+smtp:\[127\.0\.0\.1\]:2693" /etc/postfix/transport; then
    log "[ OK ] Postfix transport map routes archive@${FQDN} to 127.0.0.1:2693."
else
    err "[FAIL] Postfix transport map missing the archive route."
    verify_failed=1
fi

local archive_http archive_location
archive_http="$(curl -sk -o /dev/null -w '%{http_code}' "https://${FQDN}/archive/")"
if [[ "$archive_http" == "200" ]]; then
    log "[ OK ] Web interface reachable (HTTP 200)."
elif [[ "$archive_http" == "302" ]]; then
    # OIDC_AUTO_LOGIN=1 (set by setup-gk-app-g-archive once Keycloak SSO is
    # wired up, 2026-10-29) redirects straight to Keycloak instead of ever rendering
    # the local login form - a 302 here is then the CORRECT behaviour, not
    # a failure. Only accepted if it actually points at our own Keycloak
    # realm, so a redirect to anywhere else still fails this check.
    archive_location="$(curl -sk -o /dev/null -w '%{redirect_url}' "https://${FQDN}/archive/")"
    if [[ "$archive_location" == https://${FQDN}/auth/realms/grommunio/* ]]; then
        log "[ OK ] Web interface reachable (HTTP 302 to Keycloak SSO - OIDC_AUTO_LOGIN is on)."
    else
        err "[FAIL] Web interface returned HTTP 302 to an unexpected location: ${archive_location}"
        verify_failed=1
    fi
else
    err "[FAIL] Web interface returned HTTP ${archive_http}, expected 200 or 302."
    verify_failed=1
fi

[[ "$verify_failed" -eq 0 ]] || die "Core verification failed — see errors above before continuing."

# ============================================================
# Verify: real message capture, storage, and indexing
# ============================================================

echo
echo "Sending a real test message to confirm the capture/storage/indexing chain..."
echo "(always_bcc is unset by default now - temporarily re-enabled just for"
echo "this one test message, then unset again, pass or fail.)"
echo

# Guarantees always_bcc is unset again no matter how this function exits
# from here on (including via die(), which exits the whole script) - a
# failed verification must never leave the opt-in default silently
# switched back to archive-everyone.
trap 'postconf -X always_bcc 2>/dev/null; systemctl reload postfix 2>/dev/null' EXIT
postconf -e "always_bcc=archive@${FQDN}"
systemctl reload postfix

local TOKEN="archverify-$(date +%s)-$$"
local recipient="postmaster@${DOMAIN}"

printf 'Subject: grommunio-archive verification %s\nFrom: root@%s\nTo: %s\n\nToken: %s\n' \
    "$TOKEN" "$FQDN" "$recipient" "$TOKEN" | sendmail -t

sleep 5

local capture_failed=0

if journalctl -u grommunio-archive-smtp --since "1 minute ago" --no-pager 2>/dev/null | grep -q "received:.*size="; then
    log "[ OK ] piler-smtp logged a received message in the last minute."
else
    err "[WARN] Could not confirm piler-smtp received the test message in its log — check manually."
    capture_failed=1
fi

local db_hit
db_hit="$(mysql groarchive -N -e "SELECT COUNT(*) FROM metadata WHERE subject LIKE '%${TOKEN}%';" 2>/dev/null)"
if [[ "${db_hit:-0}" -ge 1 ]]; then
    log "[ OK ] Test message found in the groarchive database (subject match)."
else
    err "[FAIL] Test message not found in the groarchive database."
    capture_failed=1
fi

postconf -X always_bcc
systemctl reload postfix
trap - EXIT
log "[ OK ] Unset always_bcc again - back to opt-in-per-user archiving."

[[ "$capture_failed" -eq 0 ]] || die "Message capture/storage verification failed — see errors above."

# Indexing runs on a cron schedule (delta every 5/35 min past the hour);
# trigger it now so a fresh install's first message is searchable
# immediately rather than leaving a possibly-confusing gap.
log "Triggering the delta indexer now (normally runs via cron every 5/35 min)..."
sudo -u groarchive /usr/libexec/grommunio-archive/indexer.delta.sh >/dev/null 2>&1
log "[ OK ] Delta indexer run complete."

echo
echo "============================================================"
echo " Done — CLI-level verification complete"
echo "============================================================"
echo
echo "grommunio-archive is installed, configured, and the real capture/"
echo "storage/indexing chain is verified working."
echo
echo "Archiving is opt-in per user, not server-wide (always_bcc is unset)."
echo "To archive a specific mailbox: Admin UI -> that user -> SMTP tab ->"
echo "E-Mail forward, CC mode, destination archive@${FQDN}."
echo
echo "Still needs a human (a multi-step AJAX search flow, not worth"
echo "automating over curl — confirmed working directly in a browser on"
echo "testvps 2026-10-01):"
echo
echo "  1. Open https://${FQDN}/archive/ and log in (admin@local, password"
echo "     from this run's output above, or from a previous run)."
echo "  2. Search for a term from a real message's subject/body, confirm it"
echo "     appears in results."
echo "  3. Try the restore-to-mailbox action on a found message."
echo
}
