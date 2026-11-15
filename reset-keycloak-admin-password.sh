#!/usr/bin/env bash
#
# reset-keycloak-admin-password.sh
#
# Resets the Keycloak MASTER REALM admin password (the login for
# https://<hostname>/auth/admin/master/console/, kcadm.sh's own saved
# session) - NOT the "shared grommunio admin password" grommunio-setup
# shows once during step 30 and grommunio-auth's postinst scripts
# preseed into debconf for every grommunio-* package (that one is a
# different login entirely, see functions/40-grommunio-keycloak.sh's
# own comments).
#
# Why this script exists: the master-admin password is auto-generated
# during Keycloak's own first-boot bootstrap and is, BY DESIGN, never
# shown again and never written to disk anywhere - debconf masks it
# ("(password omitted)") and no config file holds it. The only way back
# in once it's lost (which it always is, since nobody ever saw it) is
# the official Keycloak recovery path: start a temporary admin user
# directly against the database (bypassing the HTTP API entirely),
# log in as that temporary user, reset the REAL admin's password, then
# delete the temporary user. Found and used live 2026-11-15 on testvps
# after the saved password file didn't survive a server reinstall -
# written up as a script afterward so the next time doesn't need to be
# worked out by hand again.
#
# Usage (run as root on the mail server itself, not the build host):
#   reset-keycloak-admin-password.sh    Reset the master-realm admin
#                                        password to a freshly generated
#                                        one, save it to
#                                        /root/cfg-server/keycloak-admin-password.txt
#                                        (0600 - the exact path
#                                        manage-mfa.sh's own kc()
#                                        auto-relogin already expects),
#                                        and leave kcadm.sh's saved
#                                        session (/root/.keycloak/kcadm.config)
#                                        logged in as the real admin
#                                        with the new password.
#
# Safe to re-run any time the password is lost again, or just to rotate
# it - every run generates a brand new password and a brand new
# temporary bootstrap user, and always cleans the temporary user up
# before exiting, success or failure.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/functions/00-common.sh"

KC_SH="/opt/grommunio-keycloak/bin/kc.sh"
KCADM="/opt/grommunio-keycloak/bin/kcadm.sh"
KC_CONFIG="/root/.keycloak/kcadm.config"
KC_SERVER="http://localhost:9080/auth"
KC_ADMIN_PW_FILE="/root/cfg-server/keycloak-admin-password.txt"

show_help()
{
    sed -n '3,42p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    show_help
    exit 0
fi

require_root
[[ -x "$KC_SH" ]] || die "kc.sh not found at $KC_SH - is grommunio-keycloak installed?"
[[ -x "$KCADM" ]] || die "kcadm.sh not found at $KCADM - is grommunio-keycloak installed?"
require_cmd openssl
require_cmd python3

TEMP_USER="tempadmin-$(openssl rand -hex 4)"
TEMP_PW="$(openssl rand -base64 24)"
NEW_PW="$(openssl rand -base64 24)"
TEMP_KC_CONFIG="$(mktemp)"

cleanup()
{
    rm -f "$TEMP_KC_CONFIG"
}
trap cleanup EXIT

log "Creating a temporary bootstrap admin ($TEMP_USER) directly against the database..."
TEMP_ADMIN_PW="$TEMP_PW" "$KC_SH" bootstrap-admin user \
    --username "$TEMP_USER" --password:env TEMP_ADMIN_PW --no-prompt \
    || die "kc.sh bootstrap-admin failed - see output above."
log "[ OK ] Temporary bootstrap admin created."

log "Logging in as the temporary admin..."
"$KCADM" config credentials --server "$KC_SERVER" --realm master \
    --user "$TEMP_USER" --password "$TEMP_PW" --config "$TEMP_KC_CONFIG" >/dev/null \
    || die "Could not log in as the temporary bootstrap admin."

log "Looking up the real 'admin' user in the master realm..."
ADMIN_ID="$("$KCADM" get users -r master -q username=admin --config "$TEMP_KC_CONFIG" 2>/dev/null \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d[0]["id"] if d else "")')"
[[ -n "$ADMIN_ID" ]] || die "Could not find a user named 'admin' in the master realm - nothing to reset."

log "Resetting the real admin's password..."
"$KCADM" update "users/${ADMIN_ID}/reset-password" -r master \
    -s type=password -s "value=${NEW_PW}" -s temporary=false -n --config "$TEMP_KC_CONFIG" \
    || die "Could not reset the real admin's password."
log "[ OK ] Real admin password reset."

log "Removing the temporary bootstrap admin..."
TEMP_ID="$("$KCADM" get users -r master -q username="$TEMP_USER" --config "$TEMP_KC_CONFIG" 2>/dev/null \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d[0]["id"] if d else "")')"
if [[ -n "$TEMP_ID" ]]; then
    "$KCADM" delete "users/${TEMP_ID}" -r master --config "$TEMP_KC_CONFIG" \
        || err "Could not delete the temporary bootstrap admin ($TEMP_USER) - remove it by hand via the admin console."
else
    err "Could not find the temporary bootstrap admin's own id to delete it - remove '$TEMP_USER' by hand via the admin console."
fi

log "Verifying the new password and refreshing kcadm.sh's saved session ($KC_CONFIG)..."
"$KCADM" config credentials --server "$KC_SERVER" --realm master \
    --user admin --password "$NEW_PW" --config "$KC_CONFIG" >/dev/null \
    || die "New password was set, but logging in with it just now failed - something is wrong, check by hand."

umask 077
printf '%s\n' "$NEW_PW" > "$KC_ADMIN_PW_FILE"
chmod 600 "$KC_ADMIN_PW_FILE"

log "[ OK ] Done. New master-realm admin password saved to $KC_ADMIN_PW_FILE (root-only)."
log "      kcadm.sh's own saved session is already logged in with it."
