#!/usr/bin/env bash
#
# 30-grommunio-setup.sh
#
# Installs grommunio-setup from the personal repo (functions/25-apt-repo-personal.sh
# must have run first) and launches its interactive dialog wizard.
#
# This step does NOT try to drive the wizard's dialog UI automatically.
# That was tried by hand during earlier live testing (tmux + send-keys,
# parsing ANSI escape codes to find which button had focus) and works, but
# is fragile and tied to the exact dialog layout of whatever grommunio-setup
# version is installed. For a script meant to be replayed across different
# servers and versions, it is more robust to prep everything the wizard
# needs and then hand control to a human for the actual Q&A — exactly like
# running any other interactive installer.
#
# What this step DOES automate:
#   - Installs mariadb-client BEFORE grommunio-setup. This works around a
#     real, reproducible bug found during live testing: grommunio-setup's
#     "removealldata" reinstall path calls a raw `mysql` command to drop the
#     old database before the script's own mariadb-client install step
#     runs, which crashes with "mysql: command not found" on a clean box
#     (or one where /etc/grommunio-common/setup_done survived a purge as an
#     untracked runtime marker). Installing mariadb-client up front avoids
#     hitting that branch at all. The underlying bug itself is still
#     unfixed in the package and should be patched there eventually.
#   - Remembers the answers you plan to give the wizard (FQDN, domain, TLS
#     choice, relay) purely as a cheat-sheet printed before launch — it does
#     NOT feed them into the wizard for you.

step_grommunio_setup()
{
local CFG="$(cfg_file 30-grommunio-setup)"
local SAVED_FQDN="" SAVED_DOMAIN="" SAVED_TLS="" SAVED_RELAY=""
local SETUP_FQDN="" SETUP_DOMAIN="" SETUP_TLS="" SETUP_RELAY=""

require_cmd apt-get

# ============================================================
# Load saved cheat-sheet, if any
# ============================================================

if [[ -f "$CFG" ]]; then
    # shellcheck disable=SC1090
    source "$CFG"
    SAVED_FQDN="${SETUP_FQDN:-}"
    SAVED_DOMAIN="${SETUP_DOMAIN:-}"
    SAVED_TLS="${SETUP_TLS:-}"
    SAVED_RELAY="${SETUP_RELAY:-}"
    SETUP_FQDN=""; SETUP_DOMAIN=""; SETUP_TLS=""; SETUP_RELAY=""
    [[ -n "$SAVED_FQDN" ]] && log "Found saved answer cheat-sheet: $CFG"
fi

# Pull the FQDN/domain already decided in step 10, if it ran, to default the
# prompts below instead of asking blank for something we already know.
local NETHOST_CFG="$(cfg_file 10-network-hostname)"
local DETECTED_FQDN="" DETECTED_DOMAIN=""
if [[ -f "$NETHOST_CFG" ]]; then
    local NEW_HOSTNAME NEW_DOMAIN NEW_FQDN PRIMARY_IPV4 PRIMARY_IPV6
    # shellcheck disable=SC1090
    source "$NETHOST_CFG"
    DETECTED_FQDN="${NEW_FQDN:-}"
    DETECTED_DOMAIN="${NEW_DOMAIN:-}"
fi

echo
echo "============================================================"
echo " grommunio-setup wizard — answer cheat-sheet"
echo "============================================================"
echo
echo "This is only a reminder printed before the wizard starts. You still"
echo "type these into the wizard's own dialog screens yourself."
echo

if [[ -n "$SAVED_FQDN" || -n "$SAVED_DOMAIN" || -n "$SAVED_TLS" || -n "$SAVED_RELAY" ]]; then
    log "Using saved cheat-sheet (delete $CFG to be asked again):"
    SETUP_FQDN="$SAVED_FQDN"
    SETUP_DOMAIN="$SAVED_DOMAIN"
    SETUP_TLS="$SAVED_TLS"
    SETUP_RELAY="$SAVED_RELAY"
else
    read -r -p "Mail server FQDN, e.g. mail.example.com [${DETECTED_FQDN:-skip}]: " SETUP_FQDN
    SETUP_FQDN="${SETUP_FQDN:-$DETECTED_FQDN}"
    read -r -p "Mail domain, e.g. example.com [${DETECTED_DOMAIN:-skip}]: " SETUP_DOMAIN
    SETUP_DOMAIN="${SETUP_DOMAIN:-$DETECTED_DOMAIN}"
    read -r -p "TLS choice (letsencrypt/self-signed/own-ca/import) [letsencrypt]: " SETUP_TLS
    SETUP_TLS="${SETUP_TLS:-letsencrypt}"
    echo
    echo "An outbound relay means this server hands all outgoing mail to"
    echo "another SMTP server (your ISP's, or a provider like SendGrid/"
    echo "Mailgun) instead of delivering it directly to each recipient's"
    echo "mail server via MX lookup. You need this when your own IP has no"
    echo "(matching) reverse DNS/PTR record, is on a residential/dynamic"
    echo "range, or your provider blocks outbound port 25 — all of which"
    echo "make direct delivery likely to be marked as spam or refused"
    echo "outright. Not needed when this server has a proper PTR record"
    echo "and unrestricted outbound port 25 (the usual case on a real VPS"
    echo "with correctly configured reverse DNS, like this one)."
    echo
    read -r -p "Outbound relay? (y/n) [n]: " SETUP_RELAY
    SETUP_RELAY="${SETUP_RELAY:-n}"
fi

echo
echo "  FQDN         : ${SETUP_FQDN:-<not set>}"
echo "  Domain       : ${SETUP_DOMAIN:-<not set>}"
echo "  TLS          : ${SETUP_TLS:-<not set>}"
echo "  Relay        : ${SETUP_RELAY:-<not set>}"
echo
echo "  Optional feature applications screen (checkboxes): enable ALL THREE -"
echo "  grommunio-chat, grommunio-files, grommunio-keycloak. This project's"
echo "  later steps (SSO, boot order, the chat/files setup scripts) assume"
echo "  all three are installed."
echo

# ============================================================
# Prerequisite: mariadb-client, BEFORE grommunio-setup, to dodge the known
# removealldata/mysql bug.
# ============================================================

log "Ensuring mariadb-client is installed (dodges a known grommunio-setup bug on the reinstall path)..."
apt-get install -y mariadb-client

# ============================================================
# Prerequisite: mariadb-server must be INSTALLED AND RUNNING before the
# wizard's database-credentials step, or it fails with a connection error.
# Found live 2026-10-02 during a backup/restore reprovisioning test: the
# server package can already be installed (e.g. left over from a prior
# run) but stopped, and grommunio-setup's wizard does not start it itself
# — it just tries to connect and fails. Installing mariadb-client alone
# (above) does not guarantee the server is running either. Always check.
# ============================================================

log "Ensuring mariadb-server is installed and running before launching the wizard..."
apt-get install -y mariadb-server
systemctl enable --now mariadb

if ! mysqladmin ping --silent 2>/dev/null; then
    die "mariadb is not responding after enable --now. Check: systemctl status mariadb"
fi
log "mariadb is running and responding."

# ============================================================
# Install grommunio-setup itself
# ============================================================

if ! command -v grommunio-setup >/dev/null 2>&1; then
    log "Installing grommunio-setup..."
    apt-get install -y grommunio-setup
else
    log "grommunio-setup already installed."
fi
require_cmd grommunio-setup

# ============================================================
# Warn if this looks like a re-run
# ============================================================

if [[ -f /etc/grommunio-common/setup_done ]]; then
    echo
    echo "============================================================"
    echo " WARNING: this server already has a setup_done marker"
    echo "============================================================"
    echo
    echo "/etc/grommunio-common/setup_done exists, so grommunio-setup will"
    echo "offer its 'removealldata' reinstall path. mariadb-client is already"
    echo "installed above, which works around the known crash there, but"
    echo "double-check you actually intend to wipe and reinstall this mail"
    echo "server before continuing."
    echo
fi

echo
echo "============================================================"
echo " Launch grommunio-setup"
echo "============================================================"
echo
echo "The wizard will now take over this terminal. Answer its dialog"
echo "screens yourself using the cheat-sheet above."
echo

local CONFIRM
read -r -p "Launch grommunio-setup now? [y/N]: " CONFIRM
if [[ ! "${CONFIRM,,}" =~ ^(y|yes)$ ]]; then
    echo; echo "Not launched. Nothing else was changed."; return 0
fi

local WIZARD_EXIT=0
grommunio-setup || WIZARD_EXIT=$?

echo
if [[ "$WIZARD_EXIT" -eq 0 ]]; then
    log "grommunio-setup exited successfully (status 0)."
    save_cfg "$CFG" \
        "SETUP_FQDN=$SETUP_FQDN" \
        "SETUP_DOMAIN=$SETUP_DOMAIN" \
        "SETUP_TLS=$SETUP_TLS" \
        "SETUP_RELAY=$SETUP_RELAY"
    log "Saved answer cheat-sheet for replay: $CFG"
else
    err "grommunio-setup exited with status $WIZARD_EXIT."
    err "Cheat-sheet was NOT saved. Re-run this step once the wizard has completed successfully."
    return "$WIZARD_EXIT"
fi

echo
echo "============================================================"
echo " Done"
echo "============================================================"
echo
echo "Check service status yourself, e.g.:"
echo "  systemctl status gromox-http gromox-zcore gromox-delivery-queue"
echo "  systemctl status mariadb nginx"
echo
}
