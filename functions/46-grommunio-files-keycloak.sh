#!/usr/bin/env bash
#
# 46-grommunio-files-keycloak.sh
#
# Sets up Keycloak/OIDC SSO for grommunio-files (Nextcloud's `user_oidc`
# app), mirroring step 40's approach for grommunio-web SSO. This is
# ADDITIVE, not a replacement: the existing `user_external`/BasicAuth-via-
# DAV backend from step 45 keeps working unchanged — Nextcloud supports
# multiple simultaneous auth backends, so this just adds a "Login with
# grommunio" button alongside the existing username/password form.
#
# CRITICAL BUG FOUND AND AVOIDED while building this, 2026-10-01: user_oidc
# defaults to `uniqueUid=true`, which constructs the Nextcloud user ID as
# `hash('sha256', "<providerId>_0_<mapped-uid-value>")` (confirmed by
# reading lib/Service/LocalIdService.php in our grommunio-files package,
# not guessed). With that default, a real user's FIRST OIDC login would
# silently create a brand-new, disconnected Nextcloud account under a
# hashed ID, invisible to and disconnected from their existing
# DAV-provisioned account and files — no error, just silent data
# inaccessibility. This step ALWAYS passes --unique-uid=0, which makes
# LocalIdService use the raw mapped value directly as the Nextcloud user
# ID. This only produces the correct, continuity-preserving result because
# Keycloak's real `username` attribute for grommunio users (confirmed via
# `kcadm get users`) is the full email address, e.g. "user@example.com",
# identical to the existing user_external-provisioned Nextcloud user IDs —
# so `--mapping-uid=preferred_username` (which reflects that `username`
# attribute) lines up exactly. If a future grommunio-keycloak version ever
# changes what `username`/`preferred_username` contains, this whole
# assumption needs re-verifying before relying on it again.
#
# The redirect URI needed is NOT the intuitive `/files/apps/user_oidc/code`
# — Nextcloud generates `/files/index.php/apps/user_oidc/code` (the
# `index.php/` is present even though the site otherwise looks like it has
# pretty URLs), confirmed live by hitting a 400 "invalid redirect_uri" from
# Keycloak with the naive guess first. Both variants are registered here so
# it's robust either way.
#
# Verified end-to-end 2026-10-01: a throwaway test mailbox with one
# pre-existing file (uploaded via the OLD DAV login) was, after OIDC login,
# shown the SAME pre-existing file — confirmed live in a browser by the
# user, proving the user-ID mapping is correct and doesn't fragment
# accounts. A bare CLI-created test account hit Keycloak's "verify profile"
# required action (missing first/last name — real accounts created through
# normal provisioning already have one, so this is not expected to affect
# real users) which wasn't worth automating past over
# curl; the browser check above is what actually proved correctness.

step_grommunio_files_keycloak()
{
require_cmd systemctl
require_cmd curl

# ============================================================
# Preconditions
# ============================================================

if ! dpkg -s grommunio-files >/dev/null 2>&1; then
    err "grommunio-files is not installed. Run step 45 first."
    return 1
fi
if ! dpkg -s grommunio-keycloak >/dev/null 2>&1; then
    err "grommunio-keycloak is not installed. Run step 40 first."
    return 1
fi

local KCADM
KCADM="$(dpkg -L grommunio-keycloak 2>/dev/null | grep -E 'bin/kcadm\.sh$' | head -n1 || true)"
if [[ -z "$KCADM" || ! -x "$KCADM" ]]; then
    err "Could not locate kcadm.sh from the grommunio-keycloak package."
    return 1
fi

local OCC="/usr/share/grommunio-files/occ"
local OCC_USER="grofiles"

# ============================================================
# Cheat-sheet / context
# ============================================================

local NETHOST_CFG="$(cfg_file 10-network-hostname)"
local FQDN=""
if [[ -f "$NETHOST_CFG" ]]; then
    local NEW_HOSTNAME NEW_DOMAIN NEW_FQDN PRIMARY_IPV4 PRIMARY_IPV6
    # shellcheck disable=SC1090
    source "$NETHOST_CFG"
    FQDN="${NEW_FQDN:-}"
fi
FQDN="${FQDN:-$(hostname -f)}"

local CLIENT_ID="grommunio-files"
local PROVIDER_ID="grommunio"

echo
echo "============================================================"
echo " Keycloak SSO for grommunio-files"
echo "============================================================"
echo
echo "  FQDN            : $FQDN"
echo "  Keycloak client  : $CLIENT_ID (realm grommunio)"
echo "  Redirect URIs    : /files/index.php/apps/user_oidc/code, /files/apps/user_oidc/code"
echo "  This is ADDITIVE : the existing DAV-based login keeps working."
echo

# ============================================================
# Check if already configured (idempotent)
# ============================================================

local existing_provider
existing_provider="$(sudo -u "$OCC_USER" php "$OCC" user_oidc:provider "$PROVIDER_ID" --output=json 2>/dev/null || true)"

if echo "$existing_provider" | grep -q "\"clientId\":\"${CLIENT_ID}\""; then
    if echo "$existing_provider" | grep -q '"uniqueUid":false'; then
        # Already configured: re-apply and re-verify the settings below (all
        # idempotent). Returning here used to skip the bearer and logout
        # settings, which is how they went missing on re-runs.
        log "[ OK ] user_oidc provider '$PROVIDER_ID' already configured for $CLIENT_ID with uniqueUid=false. Re-checking its settings."
    else
        die "user_oidc provider '$PROVIDER_ID' exists but uniqueUid is NOT false — this is the account-fragmentation bug described in this file's header. Fix manually with: sudo -u $OCC_USER php $OCC user_oidc:provider $PROVIDER_ID --unique-uid=0"
    fi
fi

# ============================================================
# Keycloak client: create if missing, or reuse if it already exists
# ============================================================

ADMIN_PASSWORD="$SHARED_ADMIN_PASSWORD"
if [[ -z "$ADMIN_PASSWORD" ]]; then
    read -r -s -p "Shared grommunio admin password (leave blank to skip): " ADMIN_PASSWORD
    echo
fi

if [[ -z "$ADMIN_PASSWORD" ]]; then
    log "Skipped. Set up manually later — see this file's header comment for the exact settings needed (client, audience mapper, --unique-uid=0)."
    return 0
fi

if ! "$KCADM" config credentials --server http://localhost:9080/auth --realm master --user admin --password "$ADMIN_PASSWORD" >/dev/null 2>&1; then
    err "kcadm.sh authentication failed — wrong password, or Keycloak not reachable on localhost:9080."
    unset ADMIN_PASSWORD
    return 1
fi
unset ADMIN_PASSWORD

local CLIENT_UUID
CLIENT_UUID="$("$KCADM" get clients -r grommunio -q "clientId=${CLIENT_ID}" --fields id 2>/dev/null | grep -oE '"[a-f0-9-]{36}"' | tr -d '"' || true)"

if [[ -z "$CLIENT_UUID" ]]; then
    log "Creating Keycloak client '$CLIENT_ID'..."
    CLIENT_UUID="$("$KCADM" create clients -r grommunio -s clientId="$CLIENT_ID" \
        -s name="$CLIENT_ID" -s description="Client for grommunio Files SSO" \
        -s rootUrl="https://${FQDN}" \
        -s 'redirectUris=["/files/index.php/apps/user_oidc/code","/files/apps/user_oidc/code"]' \
        -s 'webOrigins=["+"]' \
        -s enabled=true -s publicClient=false -s clientAuthenticatorType=client-secret \
        -s standardFlowEnabled=true -s implicitFlowEnabled=false -s directAccessGrantsEnabled=false \
        -s serviceAccountsEnabled=false -s frontchannelLogout=true \
        -i 2>&1)"
    log "[ OK ] Created client, UUID $CLIENT_UUID."
else
    log "[ OK ] Client '$CLIENT_ID' already exists (UUID $CLIENT_UUID), reusing it."
fi

# Audience mapper — same gap as grommunio-web's client in step 40, fixed
# preemptively here rather than waiting to hit the same symptom again.
local existing_mapper
existing_mapper="$("$KCADM" get "clients/${CLIENT_UUID}/protocol-mappers/models" -r grommunio 2>/dev/null | grep -c 'oidc-audience-mapper' || true)"
if [[ "${existing_mapper:-0}" -gt 0 ]]; then
    log "[ OK ] Audience mapper already exists on '$CLIENT_ID'."
else
    "$KCADM" create "clients/${CLIENT_UUID}/protocol-mappers/models" -r grommunio \
        -s name="${CLIENT_ID}-self-audience" -s protocol=openid-connect -s protocolMapper=oidc-audience-mapper \
        -s "config.\"included.client.audience\"=${CLIENT_ID}" -s 'config."id.token.claim"=true' \
        -s 'config."access.token.claim"=true' -s 'config."introspection.token.claim"=true' >/dev/null 2>&1
    log "[ OK ] Created audience mapper on '$CLIENT_ID'."
fi

# Post-logout redirect: Files sends the user back to its own URL after logout.
# Keycloak rejects that with "invalid_redirect_uri" unless it is listed on the
# client, so the logout button fails without this. Set on every run (idempotent).
"$KCADM" update "clients/${CLIENT_UUID}" -r grommunio \
    -s 'attributes."post.logout.redirect.uris"=https://'"${FQDN}"'/files/*' >/dev/null 2>&1 \
    || die "Could not set the post-logout redirect URI on '$CLIENT_ID'. Logout from Files will fail with invalid_redirect_uri."
log "[ OK ] Post-logout redirect URI set on '$CLIENT_ID' (https://${FQDN}/files/*)."

local CLIENT_SECRET
CLIENT_SECRET="$("$KCADM" get "clients/${CLIENT_UUID}/client-secret" -r grommunio 2>/dev/null | grep '"value"' | sed -E 's/.*"value" *: *"([^"]+)".*/\1/' || true)"
if [[ -z "$CLIENT_SECRET" ]]; then
    die "Could not retrieve the client secret for '$CLIENT_ID'."
fi

# ============================================================
# Configure the user_oidc provider — --unique-uid=0 is not optional, see
# this file's header comment for exactly why.
# ============================================================

# --check-bearer=1: the Files "add account" with grommunio login sends the
# Keycloak bearer token to WebDAV; without this Files answers 401.
# --bearer-provisioning=0: do not create accounts automatically from tokens.
sudo -u "$OCC_USER" php "$OCC" user_oidc:provider "$PROVIDER_ID" \
    --clientid="$CLIENT_ID" \
    --clientsecret="$CLIENT_SECRET" \
    --discoveryuri="https://${FQDN}/auth/realms/grommunio/.well-known/openid-configuration" \
    --mapping-uid=preferred_username \
    --mapping-email=email \
    --mapping-display-name=name \
    --unique-uid=0 \
    --check-bearer=1 \
    --bearer-provisioning=0
unset CLIENT_SECRET

# ============================================================
# Verify
# ============================================================

echo
echo "============================================================"
echo " Verification"
echo "============================================================"
echo

local verify_json
verify_json="$(sudo -u "$OCC_USER" php "$OCC" user_oidc:provider "$PROVIDER_ID" --output=json 2>/dev/null || true)"

if echo "$verify_json" | grep -q "\"clientId\":\"${CLIENT_ID}\""; then
    log "[ OK ] Provider '$PROVIDER_ID' configured with client '$CLIENT_ID'."
else
    die "Provider verification failed — clientId mismatch or provider missing."
fi

if echo "$verify_json" | grep -q '"checkBearer":true'; then
    log "[ OK ] checkBearer is on — the Files 'add account' with grommunio login can authenticate."
else
    die "checkBearer is NOT on — Files 'add account' with grommunio login will fail with 401. Fix with: sudo -u $OCC_USER php $OCC user_oidc:provider $PROVIDER_ID --check-bearer=1 --bearer-provisioning=0"
fi

if echo "$verify_json" | grep -q '"uniqueUid":false'; then
    log "[ OK ] uniqueUid is false — existing user_external accounts will be matched correctly, not fragmented."
else
    die "uniqueUid is NOT false after configuration — this is the critical bug described in this file's header. Do not let anyone log in via SSO until this is fixed."
fi

echo
echo "Still needs a human: log in at https://${FQDN}/files/ with a"
echo "\"grommunio\" SSO button using a REAL mailbox that already has files"
echo "(uploaded via the old DAV login), and confirm those same files are"
echo "visible after SSO login — that's the proof the mapping is correct."
echo "A brand-new test account with no first/last name set may hit"
echo "Keycloak's \"verify profile\" prompt on first login; real accounts"
echo "created through normal provisioning shouldn't."
echo
}
