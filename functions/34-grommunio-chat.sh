#!/usr/bin/env bash
#
# 34-grommunio-chat.sh
#
# Installs grommunio-chat v10 (Mattermost-based) on PostgreSQL, when chosen.
# Community source only: the chat package is in the grommunio community repo.
#
# Asked first, every time:
#   1. Install chat? (default no). If no, the step ends here.
#   2. Set up Keycloak SSO for chat (default yes). It uses grommunio's own
#      official adaptor path (grommunio-auth-manage -o setup -s grommunio-chat),
#      not a hand-rolled Keycloak client. SSO login is fully working, unlicensed
#      (confirmed 2026-10-31 - an earlier "needs a Mattermost licence"
#      assumption here was WRONG, see chat_keycloak_sso below for the real bug).
#
# What it does when chat is chosen:
#   - installs PostgreSQL (chat v10 needs it; gromox does not support it)
#   - preseeds debconf with the correct owner format
#     (owner = package name, then template, type and value). The shared admin
#     password is asked for here and is never saved to disk by this step.
#   - installs grommunio-chat-v10 (database 'grochat', listen 127.0.0.1:8065,
#     public URL https://<FQDN>/chat, admin API connection written by the package)
#   - turns off the mattermost-ai plugin (its licence check fails on every start)
#   - checks chat answers through nginx at /chat
#   - runs the official Keycloak SSO setup, then fixes the one known bug in it
#     (see chat_keycloak_sso below) and adds the id/username claim mappers
#
# Listen address is 127.0.0.1 on purpose: 'localhost' resolves to ::1 first, and
# a service that listens on IPv4 only is then unreachable for half the requests
# (this is what broke Keycloak SSO on 2026-10-03).
#
# Boot order and the readiness unit (grommunio-chat-ready) are set by step 60.
#
# Known, not solved here:
#   - the package's postinst names a 'grommunio-chat-db-configure' command that
#     is not in the package; the database is created by dbconfig-common instead.

# Wires up Keycloak SSO for chat via grommunio's own official adaptor
# (setup-gk-app-g-chat, run through grommunio-auth-manage). That script is
# correct in every respect except one: it writes GitLabSettings.Scope as
# "openid profile email", and Mattermost's own getSSOProvider() silently
# redirects any OAuth service whose Scope contains the literal substring
# "openid" to a separate OpenID Connect provider - one that grommunio-chat-v10
# never compiles in (confirmed via `strings` on the live binary and via
# grommunio's own chat source, github.com/grommunio/grommunio-chat). That
# makes the GitLab-OAuth2-as-Keycloak-tunnel trick (the officially intended
# v10 mechanism - its own comment says so) silently fail with "... SSO through
# OAuth 2.0 not available on this server." Fix: drop "openid" from the Scope
# string afterwards; Keycloak still returns full userinfo without it.
#
# Also adds the two claim mappers grommunio's adaptor never creates (needed
# since grommunio-admin-api's OAuth parser requires a numeric "id" claim, which
# Keycloak's own UUID user id cannot provide):
#   - "id": long, sourced from the existing per-user "dbId" attribute (already
#     set by grommunio's own Keycloak user provisioning - this is grommunio's
#     own numeric user id, not something this function creates)
#   - "username": string, sourced from the Keycloak username property
# And ensures the realm's user profile allows unmanaged attributes, or "dbId"
# silently fails to be read by the mapper.
chat_keycloak_sso()
{
    local CHAT_ADMIN_PASSWORD="$1"
    local CHAT_CFG="/etc/grommunio-chat/config.json"
    local KCADM REALM="grommunio"
    KCADM="$(dpkg -L grommunio-keycloak 2>/dev/null | grep -E 'bin/kcadm\.sh$' | head -n1 || true)"
    [[ -n "$KCADM" && -x "$KCADM" ]] || die "kcadm.sh not found: install grommunio-keycloak first (step 40)."

    log "Setting up Keycloak SSO for chat (official grommunio-auth-manage path)..."
    GSETUP_ADMIN_PASSWORD="$CHAT_ADMIN_PASSWORD" \
        grommunio-auth-manage -o setup -s grommunio-chat -f noninteractive >/dev/null 2>&1 \
        || die "grommunio-auth-manage could not set up the Keycloak client for grommunio-chat."
    [[ "$(jq -r '.GitLabSettings.Enable' "$CHAT_CFG" 2>/dev/null)" == "true" ]] \
        || die "grommunio-auth-manage ran but GitLabSettings.Enable is not true in $CHAT_CFG."

    # The one-line fix for the Scope bug above.
    backup_file "$CHAT_CFG"
    jq '.GitLabSettings.Scope = "profile email"' "$CHAT_CFG" > "${CHAT_CFG}.new" \
        && mv "${CHAT_CFG}.new" "$CHAT_CFG"
    chown grochat:grochat "$CHAT_CFG"
    chmod 0640 "$CHAT_CFG"
    finalize_backup "$CHAT_CFG"
    systemctl restart grommunio-chat
    log "[ OK ] GitLabSettings.Scope fixed (no longer contains 'openid')."

    "$KCADM" config credentials --server http://127.0.0.1:9080/auth --realm master --user admin \
        --password "$CHAT_ADMIN_PASSWORD" >/dev/null 2>&1 \
        || die "kcadm.sh could not log in as admin (wrong password?)."

    # Realm must allow unmanaged attributes, or the "dbId" attribute the id
    # mapper reads from is silently dropped on every user update.
    if [[ "$("$KCADM" get users/profile -r "$REALM" 2>/dev/null | jq -r '.unmanagedAttributePolicy // ""')" != "ENABLED" ]]; then
        local PROFILE_TMP="$(mktemp)"
        "$KCADM" get users/profile -r "$REALM" 2>/dev/null \
            | jq '.unmanagedAttributePolicy = "ENABLED"' > "$PROFILE_TMP"
        "$KCADM" update users/profile -r "$REALM" -f "$PROFILE_TMP" >/dev/null 2>&1 \
            || die "Could not set unmanagedAttributePolicy=ENABLED on realm $REALM."
        rm -f "$PROFILE_TMP"
        log "[ OK ] Realm $REALM now allows unmanaged user attributes."
    else
        log "[ OK ] Realm $REALM already allows unmanaged user attributes."
    fi

    local CID
    CID="$("$KCADM" get clients -r "$REALM" -q clientId=grommunio-chat --fields id 2>/dev/null | jq -r '.[0].id // ""')"
    [[ -n "$CID" ]] || die "Keycloak client grommunio-chat has no id after setup."

    local existing
    existing="$("$KCADM" get "clients/${CID}/protocol-mappers/models" -r "$REALM" 2>/dev/null | jq -r '.[].name')"

    if ! grep -qx "id" <<<"$existing"; then
        local MAPPER_TMP="$(mktemp)"
        cat > "$MAPPER_TMP" <<'EOF'
{
  "name": "id",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-usermodel-attribute-mapper",
  "consentRequired": false,
  "config": {
    "user.attribute": "dbId",
    "claim.name": "id",
    "jsonType.label": "long",
    "id.token.claim": "true",
    "access.token.claim": "true",
    "userinfo.token.claim": "true"
  }
}
EOF
        "$KCADM" create "clients/${CID}/protocol-mappers/models" -r "$REALM" -f "$MAPPER_TMP" >/dev/null 2>&1 \
            || die "Could not create the 'id' claim mapper on grommunio-chat."
        rm -f "$MAPPER_TMP"
        log "[ OK ] Added the 'id' claim mapper (long, from the dbId attribute)."
    else
        log "[ OK ] The 'id' claim mapper already exists."
    fi

    if ! grep -qx "username" <<<"$existing"; then
        local MAPPER_TMP="$(mktemp)"
        cat > "$MAPPER_TMP" <<'EOF'
{
  "name": "username",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-usermodel-property-mapper",
  "consentRequired": false,
  "config": {
    "user.attribute": "username",
    "claim.name": "username",
    "jsonType.label": "String",
    "id.token.claim": "true",
    "access.token.claim": "true",
    "userinfo.token.claim": "true"
  }
}
EOF
        "$KCADM" create "clients/${CID}/protocol-mappers/models" -r "$REALM" -f "$MAPPER_TMP" >/dev/null 2>&1 \
            || die "Could not create the 'username' claim mapper on grommunio-chat."
        rm -f "$MAPPER_TMP"
        log "[ OK ] Added the 'username' claim mapper."
    else
        log "[ OK ] The 'username' claim mapper already exists."
    fi

    log "[ OK ] Keycloak SSO for chat is ready and working (grommunio SSO button)."
}

step_grommunio_chat()
{
require_cmd apt-get
require_cmd jq
require_cmd curl
require_cmd openssl

local NET_CFG="$(cfg_file 10-network-hostname)"
local FQDN=""
if [[ -f "$NET_CFG" ]]; then
    # shellcheck disable=SC1090
    source "$NET_CFG"
    FQDN="${NEW_FQDN:-}"
fi
[[ -n "$FQDN" ]] || die "No FQDN in $NET_CFG (run step 10 first)."

echo
echo "============================================================"
echo " grommunio Chat (v10)"
echo "============================================================"
echo
read -r -p "Install grommunio-chat (v10)? [y/N]: " CHAT_CHOICE
if [[ ! "${CHAT_CHOICE:-N}" =~ ^[Yy]$ ]]; then
    log "Chat not chosen. Nothing installed."
    return 0
fi

read -r -p "Set up Keycloak SSO for chat (grommunio SSO button)? [Y/n]: " KC_CHOICE
local WANT_KC_CLIENT=1
[[ "${KC_CHOICE:-Y}" =~ ^[Nn]$ ]] && WANT_KC_CLIENT=0

# The shared admin password: from this run (step 30), or asked for once.
shared_admin_password_get "Shared grommunio admin password (same as the wizard): "
local CHAT_ADMIN_PASSWORD="$SHARED_ADMIN_PASSWORD"
[[ -n "$CHAT_ADMIN_PASSWORD" ]] || die "No shared admin password was given."

# ============================================================
# 1. PostgreSQL
# ============================================================

export DEBIAN_FRONTEND=noninteractive
if ! dpkg -s postgresql >/dev/null 2>&1; then
    log "Installing PostgreSQL..."
    apt-get install -y postgresql || die "Could not install PostgreSQL."
fi
systemctl enable --now postgresql
systemctl is-active --quiet postgresql || die "PostgreSQL is not active."
log "[ OK ] PostgreSQL is active."

# ============================================================
# 2. Preseed debconf (owner first: owner template type value)
# ============================================================

if dpkg -s grommunio-chat-v10 >/dev/null 2>&1; then
    log "grommunio-chat-v10 is already installed; not reinstalling."
else
    local DB_PASSWORD
    DB_PASSWORD="$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 24)"
    log "Preseeding chat answers..."
    {
        echo "grommunio-chat-v10 shared/grommunio/site-fqdn string ${FQDN}"
        echo "grommunio-chat-v10 shared/grommunio/auto-config boolean true"
        echo "grommunio-chat-v10 shared/grommunio-chat/endpoint-url string https://${FQDN}/chat"
        echo "grommunio-chat-v10 shared/grommunio-chat/listen-address string 127.0.0.1:8065"
        echo "grommunio-chat-v10 shared/grommunio-chat/api-tls-verify boolean true"
        echo "grommunio-chat-v10 shared/grommunio/admin-password password ${CHAT_ADMIN_PASSWORD}"
        echo "grommunio-chat-v10 shared/grommunio/admin-password-again password ${CHAT_ADMIN_PASSWORD}"
        echo "grommunio-chat-v10 grommunio-chat-v10/database-type select pgsql"
        echo "grommunio-chat-v10 grommunio-chat-v10/dbconfig-install boolean true"
        echo "grommunio-chat-v10 grommunio-chat-v10/db/dbname string grochat"
        echo "grommunio-chat-v10 grommunio-chat-v10/db/app-user string grochat"
        echo "grommunio-chat-v10 grommunio-chat-v10/pgsql/method select Unix socket"
        echo "grommunio-chat-v10 grommunio-chat-v10/pgsql/app-pass password ${DB_PASSWORD}"
        echo "grommunio-chat-v10 grommunio-chat-v10/app-password-confirm password ${DB_PASSWORD}"
    } | debconf-set-selections
    unset DB_PASSWORD

    log "Installing grommunio-chat-v10 (this takes a minute)..."
    apt-get install -y grommunio-chat-v10 || die "Could not install grommunio-chat-v10."
fi

# ============================================================
# 3. Settings after install: AI plugin off, chat listening
# ============================================================

local CHAT_CFG="/etc/grommunio-chat/config.json"
[[ -s "$CHAT_CFG" ]] || die "$CHAT_CFG was not written by the package."

backup_file "$CHAT_CFG"
jq '.PluginSettings.PluginStates["mattermost-ai"] = ((.PluginSettings.PluginStates["mattermost-ai"] // {}) + {"Enable": false})' \
    "$CHAT_CFG" > "${CHAT_CFG}.new" && mv "${CHAT_CFG}.new" "$CHAT_CFG"
chown grochat:grochat "$CHAT_CFG"
chmod 0640 "$CHAT_CFG"
finalize_backup "$CHAT_CFG"
log "[ OK ] mattermost-ai plugin is off."

systemctl enable grommunio-chat >/dev/null 2>&1 || true
systemctl restart grommunio-chat

# ============================================================
# 4. Checks: listening, answering through nginx, admin API connection
# ============================================================

local waited=0
until ss -ltn | grep -q '127.0.0.1:8065'; do
    sleep 2; waited=$((waited + 2))
    (( waited < 120 )) || die "Chat is not listening on 127.0.0.1:8065 after ${waited}s."
done
log "[ OK ] Chat listens on 127.0.0.1:8065 (after ${waited}s)."

local code=""
for _ in $(seq 1 30); do
    code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 --resolve "${FQDN}:443:127.0.0.1" "https://${FQDN}/chat/api/v4/system/ping" || true)"
    [[ "$code" == "200" ]] && break
    sleep 2
done
[[ "$code" == "200" ]] || die "Chat does not answer through nginx at https://${FQDN}/chat (last code: ${code})."
log "[ OK ] Chat answers through nginx at https://${FQDN}/chat."

[[ -f /etc/grommunio-admin-api/conf.d/chat.yaml ]] \
    || die "The admin API chat connection (conf.d/chat.yaml) was not written."
log "[ OK ] The admin API chat connection is written."

# Users get chat accounts only when their domain has a chat team. Domains are
# created with chat off (step 31), so turn chat on for every active domain.
local dom
while read -r dom; do
    [[ -n "$dom" ]] || continue
    if grommunio-admin domain show "$dom" 2>/dev/null | grep -qE '^\s+chatID: \S+'; then
        log "[ OK ] Domain $dom already has a chat team."
    else
        grommunio-admin domain modify "$dom" --chat true >/dev/null 2>&1 \
            || die "Could not turn on chat for domain $dom."
        log "[ OK ] Turned on chat for domain $dom."
    fi
done < <(grommunio-admin domain list 2>/dev/null | sed -nE 's/^[0-9]+: ([^ ]+) \(active\).*/\1/p')

# ============================================================
# 5. Keycloak SSO for chat
# ============================================================

local KCADM_PATH
KCADM_PATH="$(dpkg -L grommunio-keycloak 2>/dev/null | grep -E 'bin/kcadm\.sh$' | head -n1 || true)"
if (( WANT_KC_CLIENT )); then
    if [[ -n "$KCADM_PATH" && -x "$KCADM_PATH" ]]; then
        chat_keycloak_sso "$CHAT_ADMIN_PASSWORD"
    else
        log "Keycloak SSO for chat is set up by step 40, once Keycloak is installed."
    fi
fi

unset CHAT_ADMIN_PASSWORD
log "[ OK ] grommunio Chat is installed. Login: https://${FQDN}/chat - via grommunio SSO"
log "       (Keycloak) for users whose domain has Keycloak enabled; other users get a"
log "       local account with a random password (set one with grommunio-admin)."
}
