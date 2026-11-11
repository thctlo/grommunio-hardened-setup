#!/usr/bin/env bash
#
# 45-grommunio-files.sh
#
# Installs and configures grommunio-files (Nextcloud-based), folding in
# everything found doing this manually on testvps 2026-09-29 (see
# testvps-provisioning-framework memory for the full writeup).
#
# REAL BUG, general lesson for this whole framework: installing without
# `DEBIAN_FRONTEND=noninteractive` explicitly exported hung this package's
# postinst completely (survived over an hour, even a session restart). Root
# cause: its .config script found shared/grommunio/admin-password empty and
# looped back to re-ask via `db_input high` — and because DEBIAN_FRONTEND
# was never exported, debconf's frontend-fallback chain (Dialog -> Readline
# -> Teletype -> Noninteractive) tried Teletype first, which blocks forever
# reading from a non-tty SSH pipe, before ever reaching Noninteractive. `-y`
# alone does not prevent this. This step always exports it explicitly and
# preseeds every value the postinst needs BEFORE installing, so the
# fallback chain never has anything left to ask about.
#
# Exact debconf templates needed (confirmed via templates.dat on testvps,
# not guessed): shared/grommunio/admin-password (password),
# shared/grommunio/admin-password-again (password),
# shared/grommunio/auto-config (boolean), shared/grommunio/site-fqdn
# (string), shared/grommunio/site-domain (string),
# shared/grommunio-files/endpoint-url (string),
# shared/grommunio-files/config-office-force (boolean, left false — no
# ONLYOFFICE/Office integration installed on this repo).
#
# The admin password is NOT retrievable after the fact (same as step 40's
# audience-mapper section) — debconf's password-type templates are cleared
# once consumed. Unlike that section, this one is NOT safely skippable:
# without a real value, the exact hang above is a real risk. So this
# prompts for it and, if left blank, does not attempt the install at all —
# it prints the equivalent manual commands and returns, same as any other
# unmet precondition in this framework.
#
# Two "off by default" gaps found and fixed, same pattern as the `smtp`
# privilege bit found off-by-default for new mailboxes earlier
# (step 37/testvps-provisioning-framework): neither `privFiles` (per-user,
# gates whether a mailbox can use Files at all) nor
# PLUGIN_FILES_USER_DEFAULT_ENABLE (system-wide, gates the
# attach-from-Files/save-to-Files integration inside grommunio Web) are on
# by default after install. Also `grommunio-files-cron.service`/`.timer`
# ship disabled.
#
# privFiles is a per-user attribute — this step only grants it to `admin`
# (the one account guaranteed to exist after grommunio-setup) so the admin
# can use/test Files immediately, and prints a reminder that any other
# mailbox needs the same flag granted individually
# (`grommunio-admin user modify <user> --privFiles true`), same as `smtp`.
# There is no system-wide "default privileges for new users" setting to
# flip instead — confirmed these are hardcoded creation defaults, not a
# configurable policy, while investigating the `smtp` gap earlier.
#
# Verification uses the same method as the SMTP AUTH positive-path test
# (2026-09-28): a throwaway test mailbox with a freshly generated password
# (never the user's real credentials), a real WebDAV PUT+GET round-trip via
# curl against `https://<fqdn>/files/remote.php/dav/files/<user>/<file>`
# (URL prefix confirmed via
# /usr/share/grommunio-common/nginx/locations.d/grommunio-files.conf), then
# deleted afterward. Proves the DAV-backed `user_external` auth path
# actually works end to end, not just that the service started.
#
# Explicitly OUT of scope here (separate backlog items):
# Keycloak/OIDC SSO for Files (the `user_oidc` "use login from grommunio"
# toggle) — a distinct, optional layer on top of this, see
# next-session-overview memory for why it might be wanted. Attach-from-
# Files/save-to-Files UI check, sharing-to-another-user check, and the
# Office-file-graceful-fallback check are all separate manual checklist
# items already verified directly by the user, not automated here.

step_grommunio_files()
{
require_cmd apt-get
require_cmd systemctl
require_cmd curl
require_cmd debconf-set-selections
require_cmd grommunio-admin

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

local already_installed=0
if dpkg -s grommunio-files >/dev/null 2>&1; then
    already_installed=1
fi

echo
echo "============================================================"
echo " grommunio-files setup"
echo "============================================================"
echo
echo "  FQDN                : $FQDN"
echo "  Site domain         : $DOMAIN"
echo "  Endpoint URL         : https://${FQDN}/files"
echo "  Already installed?   : $([[ "$already_installed" -eq 1 ]] && echo yes || echo no)"
echo

if [[ "$already_installed" -eq 0 ]]; then
    echo "Installing requires the shared grommunio admin password (the SAME one"
    echo "grommunio-setup showed you at the end of step 30 — not a new one)."
    echo "Without it, the postinst can hang completely (see this file's header"
    echo "comment for why) — so this step will not attempt the install blind."
    echo

    local ADMIN_PASSWORD="$SHARED_ADMIN_PASSWORD"
    if [[ -z "$ADMIN_PASSWORD" ]]; then
        read -r -s -p "Shared grommunio admin password (leave blank to skip the install): " ADMIN_PASSWORD
        echo
    fi

    if [[ -z "$ADMIN_PASSWORD" ]]; then
        log "Skipped. Install manually later with (fill in the real password):"
        echo "  debconf-set-selections <<EOF"
        echo "  grommunio-files shared/grommunio/admin-password password <PASSWORD>"
        echo "  grommunio-files shared/grommunio/admin-password-again password <PASSWORD>"
        echo "  grommunio-files shared/grommunio/auto-config boolean true"
        echo "  grommunio-files shared/grommunio/site-fqdn string ${FQDN}"
        echo "  grommunio-files shared/grommunio/site-domain string ${DOMAIN}"
        echo "  grommunio-files shared/grommunio-files/endpoint-url string https://${FQDN}/files"
        echo "  grommunio-files shared/grommunio-files/config-office-force boolean false"
        echo "  EOF"
        echo "  export DEBIAN_FRONTEND=noninteractive"
        echo "  apt-get install -y grommunio-files"
        return 1
    fi

    debconf-set-selections <<EOF
grommunio-files shared/grommunio/admin-password password ${ADMIN_PASSWORD}
grommunio-files shared/grommunio/admin-password-again password ${ADMIN_PASSWORD}
grommunio-files shared/grommunio/auto-config boolean true
grommunio-files shared/grommunio/site-fqdn string ${FQDN}
grommunio-files shared/grommunio/site-domain string ${DOMAIN}
grommunio-files shared/grommunio-files/endpoint-url string https://${FQDN}/files
grommunio-files shared/grommunio-files/config-office-force boolean false
EOF
    log "Preseeded shared debconf values for grommunio-files."

    log "Installing grommunio-files (this can take a while)..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y grommunio-files
    unset ADMIN_PASSWORD
else
    log "grommunio-files already installed — skipping install, checking config only."
fi

# ============================================================
# Config fixups: privFiles (admin), PLUGIN_FILES_USER_DEFAULT_ENABLE, cron
# ============================================================

echo
echo "============================================================"
echo " Config fixups"
echo "============================================================"
echo

# Check-before-write: re-running `user modify --privFiles true` on the
# `admin` account when it's ALREADY true fails with a real gromox/exmdb
# error ("Prefix has type mismatch") — found live while testing this step's
# replay path. `admin` is a special account (no real mailbox/maildir), and
# re-applying an already-set privilege bit to it appears to hit a backend
# quirk rather than being a harmless no-op like it is for a normal mailbox.
if grommunio-admin user query privFiles -f "username=admin" 2>/dev/null | grep -q True; then
    log "[ OK ] privFiles already set on 'admin'."
elif grommunio-admin user modify admin --privFiles true >/dev/null 2>&1; then
    log "[ OK ] privFiles granted to 'admin'."
else
    err "[WARN] Could not set privFiles on 'admin' — check manually with: grommunio-admin user query username privFiles -f username=admin"
fi
log "Note: privFiles is per-user. Grant it to any other mailbox that needs Files with:"
log "  grommunio-admin user modify <user> --privFiles true"

local WEB_FILES_CFG="/etc/grommunio-web/config-files.php"
if [[ -f "$WEB_FILES_CFG" ]]; then
    if grep -q "PLUGIN_FILES_USER_DEFAULT_ENABLE'.*true" "$WEB_FILES_CFG"; then
        log "[ OK ] PLUGIN_FILES_USER_DEFAULT_ENABLE already true in $WEB_FILES_CFG."
    else
        backup_file "$WEB_FILES_CFG"
        sed -i -E "s/(PLUGIN_FILES_USER_DEFAULT_ENABLE'\s*,\s*)false/\1true/" "$WEB_FILES_CFG"
        finalize_backup "$WEB_FILES_CFG"
        if grep -q "PLUGIN_FILES_USER_DEFAULT_ENABLE'.*true" "$WEB_FILES_CFG"; then
            log "[ OK ] Set PLUGIN_FILES_USER_DEFAULT_ENABLE = true in $WEB_FILES_CFG."
            systemctl restart php8.4-fpm
            systemctl reload nginx
        else
            err "[WARN] Could not confirm PLUGIN_FILES_USER_DEFAULT_ENABLE is now true — check $WEB_FILES_CFG manually."
        fi
    fi
else
    err "[WARN] $WEB_FILES_CFG not found — is grommunio-web installed?"
fi

if systemctl is-enabled --quiet grommunio-files-cron.timer 2>/dev/null && systemctl is-active --quiet grommunio-files-cron.timer 2>/dev/null; then
    log "[ OK ] grommunio-files-cron.timer already enabled and active."
else
    systemctl enable --now grommunio-files-cron.service grommunio-files-cron.timer
    log "[ OK ] Enabled grommunio-files-cron.service/.timer."
fi

# ============================================================
# Verify: package/service state
# ============================================================

echo
echo "============================================================"
echo " Verification"
echo "============================================================"
echo

local verify_failed=0

if dpkg -s grommunio-files >/dev/null 2>&1; then
    log "[ OK ] grommunio-files package installed."
else
    err "[FAIL] grommunio-files package not installed."
    verify_failed=1
fi

if systemctl is-active --quiet grommunio-files-cron.timer; then
    log "[ OK ] grommunio-files-cron.timer is active."
else
    err "[FAIL] grommunio-files-cron.timer is not active."
    verify_failed=1
fi

[[ "$verify_failed" -eq 0 ]] || die "Core verification failed — see errors above before continuing."

# ============================================================
# Verify: real WebDAV round-trip via a throwaway test mailbox — same
# method as the SMTP AUTH positive-path test (2026-09-28). Never uses a
# real user's credentials.
#
# Files authenticates via user_external/BasicAuth against grommunio-dav's
# own /dav/ endpoint, which gates access on privDav (NOT just privFiles) —
# confirmed by reading GrommunioDavBackend.php's isGdavEnabled(), so the
# test mailbox needs --privDav true, not false, or every attempt 401s with
# a generic "Username or password was incorrect" even though the real
# username/password check passed (dav.log's DEBUG level shows "Auth: OK"
# immediately followed by "is disabled for grommunio-dav" — two genuinely
# different checks, easy to conflate from the 401 alone).
#
# REAL BUG FOUND while building this test, worth knowing generally, not
# just for this script: isGdavEnabled() (and grommunio-web's equivalent
# isGwebEnabled()) reads PR_EC_ENABLED_FEATURES_L, which zcore computes
# from zs_get_info()->privbits — a value cached PER USERNAME inside
# gromox-zcore's own running process, not re-read from the database per
# request (confirmed by reading store_object.cpp in our own gromox 3.11.5
# source). Deleting and recreating a mailbox with the SAME address, then
# changing its privDav bit, does NOT pick up the change — zcore keeps
# serving whatever privbits it cached the first time it ever saw that
# username, until gromox-zcore itself is restarted. This is NOT a
# mysql_adaptor cache-lifetime issue (confirmed: neither waiting past the
# default 1-minute lifetime nor restarting gromox-http fixed it) — only a
# `systemctl restart gromox-zcore` or, more simply, a username zcore has
# never seen before, resolves it (confirmed both independently). This
# likely also applies to a REAL existing mailbox: flipping privDav/privWeb/
# privEas on a user zcore already has cached may need a zcore restart to
# actually take effect. This step sidesteps the whole question by giving
# the test mailbox a unique, timestamp-suffixed address every run, so it
# is always a username zcore has never cached anything for.
# ============================================================

echo
echo "Running a real WebDAV round-trip test (throwaway mailbox, not a real user)..."
echo

local TEST_USER="grofilestest-$(date +%s)-$$@${DOMAIN}"
local TEST_PASSWORD
# tr gets SIGPIPE when head closes; under pipefail that kills the step silently.
TEST_PASSWORD="$({ tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20; } 2>/dev/null || true)Aa1!"
local TEST_FILE_CONTENT="grommunio-files verification $(date -Is)"
local dav_verify_failed=0

if grommunio-admin user create "$TEST_USER" --privFiles true --privDav true --privWeb false --privEas false >/dev/null 2>&1; then
    if printf '%s\n' "$TEST_PASSWORD" | grommunio-admin passwd --password-stdin "$TEST_USER" >/dev/null 2>&1; then
        local dav_url="https://${FQDN}/files/remote.php/dav/files/${TEST_USER}/f2b-verify-$$.txt"
        # A real file, not `-T <(process substitution)`: curl can't determine
        # Content-Length from a pipe, and the upload silently stores an empty
        # body despite returning 201 — found live while building this test.
        local tmpfile
        tmpfile="$(mktemp)"
        printf '%s' "$TEST_FILE_CONTENT" > "$tmpfile"

        if curl -sk -u "${TEST_USER}:${TEST_PASSWORD}" -T "$tmpfile" "$dav_url" -o /dev/null -w '%{http_code}' | grep -qE '^(200|201|204)$'; then
            local downloaded
            downloaded="$(curl -sk -u "${TEST_USER}:${TEST_PASSWORD}" "$dav_url")"
            if [[ "$downloaded" == "$TEST_FILE_CONTENT" ]]; then
                log "[ OK ] WebDAV PUT+GET round-trip succeeded, content matched exactly."
            else
                err "[FAIL] WebDAV download content did not match what was uploaded."
                dav_verify_failed=1
            fi
        else
            err "[FAIL] WebDAV upload did not return a success status."
            dav_verify_failed=1
        fi
        rm -f "$tmpfile"
    else
        err "[FAIL] Could not set password on throwaway test mailbox."
        dav_verify_failed=1
    fi

    grommunio-admin user delete "$TEST_USER" -y >/dev/null 2>&1
    log "Throwaway test mailbox $TEST_USER deleted."
else
    err "[FAIL] Could not create throwaway test mailbox $TEST_USER."
    dav_verify_failed=1
fi

unset TEST_PASSWORD

[[ "$dav_verify_failed" -eq 0 ]] || die "WebDAV verification failed — see errors above."

# ============================================================
# REAL BUG FOUND 2026-10-29, in the package itself (not ours):
# /usr/lib/systemd/system/grommunio-files-cron.timer (which its own
# description calls "Run Nextcloud cron.php every 5 minutes") only has
# `OnBootSec=120` in its [Timer] section - no `OnUnitActiveSec=` or
# `OnCalendar=` to make it repeat. Confirmed live: it ran exactly once,
# 120s after boot on 2026-10-25, and never again since (`systemctl
# list-timers` showed "NEXT: -", no scheduled run, 3 days of inactivity).
# Nextcloud's own documentation requires cron.php every 5 minutes for
# background jobs (trash/versions cleanup, file scanning, federated
# sharing, notifications) - none of that has been running at all.
# Fixed via a drop-in (not editing the package file directly), adding
# the missing repeat interval while leaving OnBootSec alone. Idempotent:
# only writes/reloads if the drop-in doesn't already match.
# ============================================================
FILES_CRON_DROPIN_DIR="/etc/systemd/system/grommunio-files-cron.timer.d"
FILES_CRON_DROPIN="$FILES_CRON_DROPIN_DIR/override.conf"
FILES_CRON_DROPIN_NEW="$(mktemp)"
cat > "$FILES_CRON_DROPIN_NEW" <<'DROPIN'
# Managed by 45-grommunio-files.sh. The package's own timer
# (grommunio-files-cron.timer) only has OnBootSec=120 - it fires once at
# boot and never repeats, despite its own description saying "every 5
# minutes" (Nextcloud's own documented requirement for cron.php). Adds
# the missing repeat interval.
[Timer]
OnUnitActiveSec=5min
DROPIN
install -d "$FILES_CRON_DROPIN_DIR"
if ! cmp -s "$FILES_CRON_DROPIN_NEW" "$FILES_CRON_DROPIN" 2>/dev/null; then
    backup_file "$FILES_CRON_DROPIN"
    install -m 0644 "$FILES_CRON_DROPIN_NEW" "$FILES_CRON_DROPIN"
    finalize_backup "$FILES_CRON_DROPIN"
    systemctl daemon-reload
    systemctl restart grommunio-files-cron.timer || die "Could not restart grommunio-files-cron.timer after fixing its interval."
    log "[ OK ] grommunio-files-cron.timer: added the missing 5-minute repeat interval."
else
    log "[ OK ] grommunio-files-cron.timer: 5-minute repeat interval already set."
fi
rm -f "$FILES_CRON_DROPIN_NEW"
if [[ -z "$(systemctl show grommunio-files-cron.timer -p NextElapseUSecRealtime --value)" ]]; then
    die "grommunio-files-cron.timer still shows no scheduled next run after the fix - check the drop-in."
else
    log "[ OK ] grommunio-files-cron.timer now has a scheduled next run."
fi

echo
echo "============================================================"
echo " Done"
echo "============================================================"
echo
echo "grommunio-files installed/configured and verified via a real WebDAV round-trip."
echo "Not covered by this step (separate backlog items): Keycloak/OIDC SSO for Files,"
echo "and the UI-level attach-from-Files/sharing/Office-fallback checks (already"
echo "verified manually)."
echo
}
