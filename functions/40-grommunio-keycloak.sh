#!/usr/bin/env bash
#
# 40-grommunio-keycloak.sh
#
# Installs and configures Keycloak SSO for grommunio, per
# docs.grommunio.com/guides/sso-keycloak/ — the guide our own
# grommunio-keycloak/grommunio-auth packages were built to satisfy, and per
# LIVE-TEST-PROMPT.md flagged as "the most important phase... not tested
# end-to-end anywhere yet."
#
# CORRECTION vs. the original design of this step: the docs describe a
# separate interactive wizard (/usr/share/grommunio-auth/setup-grommunio-auth.sh).
# That script does not exist as a standalone entry point in this packaging —
# the entire realm/client/user-federation setup runs automatically as part
# of `apt-get install`, driven by debconf (shared/grommunio/auto-config=true
# in this repo's packages, same mechanism grommunio-setup itself uses to
# share its FQDN/admin-password across packages). There is nothing to
# "launch" after install; this step just needs to preseed the one debconf
# value that actually matters and then verify.
#
# The one thing debconf does NOT get right by default: the "restricted auth
# paths" protection the docs describe for /auth/admin, /auth/metrics,
# /auth/health is a real preseedable value
# (shared/grommunio-keycloak/allow-from-networks), but its OWN default is
# "0.0.0.0/0 ::/0" (allow everyone) — found live on testvps after a first,
# unpreseeded install, and fixed there with debconf-set-selections +
# dpkg-reconfigure. This step preseeds it correctly BEFORE installing, using
# step 20's saved SSH whitelist, so a fresh install gets it right the first
# time instead of needing that same manual fix.
#
# Also found: the Keycloak realm's master-admin password is NOT a new
# password to discover — shared/grommunio/admin-password is the same shared
# debconf variable grommunio-setup itself populates, so it's the same admin
# password already recorded from grommunio-setup's completion screen (step
# 30). No new credential exists to look for.
#
# The grommunio-web OIDC client ships with directAccessGrantsEnabled=false
# (confirmed in /etc/grommunio-auth/grommunio-client-web.json) — this is a
# deliberate, good security default (no resource-owner-password-credentials
# grant), NOT a bug, even though the upstream docs suggest enabling it "for
# testing". This step does not fight that default or enable it temporarily;
# real end-to-end verification is the browser-based Authorization Code flow
# a human has to drive (see the printed checklist at the end), plus the
# unauthenticated discovery-endpoint check this step does automate.
#
# Also found live 2026-09-29, via real end-to-end browser testing: the
# postinst setup creates the realm/client/federation but NOT a self-audience
# mapper on the client, so token introspection fails with "invalid_token,
# reason=Client 'X' is not in the token audience" the moment anything (e.g.
# gromox-zcore verifying a bearer token) introspects a token this client
# issued. Fixed here via kcadm.sh, idempotently (checks for an existing
# oidc-audience-mapper first). This needs the shared grommunio admin
# password, which — like everywhere else in this framework — is prompted
# for and never persisted to /root/cfg-server; leaving it blank skips the
# fix and prints the equivalent manual kcadm.sh command instead.

step_grommunio_keycloak()
{
require_cmd apt-get
require_cmd systemctl
require_cmd curl
require_cmd debconf-set-selections

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
local FQDN=""
if [[ -f "$NETHOST_CFG" ]]; then
    local NEW_HOSTNAME NEW_DOMAIN NEW_FQDN PRIMARY_IPV4 PRIMARY_IPV6
    # shellcheck disable=SC1090
    source "$NETHOST_CFG"
    FQDN="${NEW_FQDN:-}"
fi
FQDN="${FQDN:-$(hostname -f)}"

local FW_CFG="$(cfg_file 20-firewall-fail2ban)"
local -a WHITELIST_IPS=()
if [[ -f "$FW_CFG" ]]; then
    # shellcheck disable=SC1090
    source "$FW_CFG"
fi

# Admin paths (/auth/admin, /auth/metrics, /auth/health) are restricted to
# localhost by default. The admin CLI (kcadm) already talks to Keycloak on
# localhost:9080 and never goes through nginx, so nothing here needs an
# external IP. Reach the admin console over an SSH tunnel if needed.
local -a ALLOW_NETWORKS=("127.0.0.1/32" "::1/128")

echo
echo "============================================================"
echo " grommunio Keycloak SSO setup"
echo "============================================================"
echo
echo "This is NOT an interactive wizard — apt-get install configures the"
echo "whole realm/client/user-federation automatically via debconf, reusing"
echo "the FQDN and admin password grommunio-setup already established."
echo
echo "  FQDN                     : $FQDN"
if [[ "${#ALLOW_NETWORKS[@]}" -gt 0 ]]; then
    echo "  Restricted auth paths     : ${ALLOW_NETWORKS[*]} (localhost only, see step header)"
else
    echo "  Restricted auth paths     : none saved from step 20 — will default to 0.0.0.0/0 ::/0 (open)"
fi
echo "  Realm master admin login : same admin password grommunio-setup showed you (step 30) — not a new one"
echo
echo "IMPORTANT: once installed, /etc/gromox/keycloak.json will exist, and"
echo "grommunio Web switches ALL web logins to Keycloak SSO from that point"
echo "on — there is no separate on/off toggle. Revert with DISABLE_KEYCLOAK=true"
echo "in /etc/grommunio-web/config.php if needed."
echo

if [[ "${#ALLOW_NETWORKS[@]}" -gt 0 ]]; then
    local networks_str="${ALLOW_NETWORKS[*]}"
    debconf-set-selections <<< "grommunio-keycloak shared/grommunio-keycloak/allow-from-networks string ${networks_str}"
    log "Preseeded shared/grommunio-keycloak/allow-from-networks = ${networks_str}"
else
    log "No saved SSH whitelist from step 20 — leaving allow-from-networks at its own default (0.0.0.0/0 ::/0). Fix later with: debconf-set-selections + dpkg-reconfigure grommunio-keycloak."
fi

# ============================================================
# The admin password drives realm creation: grommunio-auth's configure_auth
# returns silently when shared/grommunio/admin-password is empty, so no
# grommunio realm, no grommunio-web/grommunio-files clients, and no
# keycloak.json/bearer_pubkey get written. debconf clears this value once
# consumed, so it must be supplied fresh each time the realm is missing.
# Never persisted to /root/cfg-server.
# ============================================================

if [[ ! -f /etc/gromox/keycloak.json ]]; then
    shared_admin_password_get "Shared grommunio admin password (same one grommunio-setup just showed you): "
    KC_ADMIN_PASSWORD="$SHARED_ADMIN_PASSWORD"
    if [[ -z "$KC_ADMIN_PASSWORD" ]]; then
        die "Admin password is required to create the grommunio Keycloak realm. Re-run and enter it."
    fi
    debconf-set-selections <<< "grommunio-auth shared/grommunio/admin-password password ${KC_ADMIN_PASSWORD}"
    debconf-set-selections <<< "grommunio-auth shared/grommunio/admin-password-again password ${KC_ADMIN_PASSWORD}"
    debconf-set-selections <<< "grommunio-keycloak shared/grommunio/admin-password password ${KC_ADMIN_PASSWORD}"
    debconf-set-selections <<< "grommunio-keycloak shared/grommunio/admin-password-again password ${KC_ADMIN_PASSWORD}"
    unset KC_ADMIN_PASSWORD
    log "Preseeded shared/grommunio/admin-password for grommunio-auth and grommunio-keycloak."

    # Stale dbconfig-common state from an earlier install/purge makes the
    # database step skip CREATE DATABASE while still creating the user.
    # Clear it only when the database is actually missing.
    if ! mysql -N -e "SHOW DATABASES LIKE 'grommunio_keycloak';" 2>/dev/null | grep -q grommunio_keycloak; then
        log "grommunio_keycloak database is missing — clearing stale dbconfig-common state and orphaned user."
        rm -f /etc/dbconfig-common/grommunio-keycloak.conf /etc/dbconfig-common/grommunio-keycloak-grommuniodb.conf
        mysql -e "DROP USER IF EXISTS 'grommunio_keycloak'@'localhost';"
    fi
fi

# ============================================================
# Install (or, if already installed, reconfigure so the preseeded value
# above actually takes effect — apt-get install alone is a no-op on an
# already-installed package and won't re-run debconf).
# ============================================================

if dpkg -s grommunio-keycloak >/dev/null 2>&1 && dpkg -s grommunio-auth >/dev/null 2>&1; then
    log "grommunio-keycloak/grommunio-auth already installed — reconfiguring to apply the preseeded value..."
    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure grommunio-keycloak
else
    log "Installing grommunio-auth, grommunio-keycloak, grommunio-keycloak-grommuniodb..."
    apt-get install -y grommunio-auth grommunio-keycloak grommunio-keycloak-grommuniodb
fi

# ============================================================
# Verify: files, ownership, service, port
# ============================================================

echo
echo "============================================================"
echo " Verification"
echo "============================================================"
echo

local verify_failed=0

# Self-healing, not just reporting: found live 2026-11-07 that
# /etc/gromox/keycloak.json had silently regressed to 600 (root-only,
# written that way by some other setup/reconfiguration run outside this
# step) - the groweb-group php-fpm pool that actually needs to read this
# file to decide whether to redirect to Keycloak then couldn't, and
# grommunio-web silently fell back to its native login form with no
# error anywhere. A WARN-only check would have reported this but left it
# broken; this now actively corrects owner/mode on a mismatch so a
# re-run of this step is also a repair tool, not just a report.
check_file()
{
    local file="$1" owner="$2" mode="$3"
    if [[ ! -f "$file" ]]; then
        err "[FAIL] missing: $file"
        verify_failed=1
        return
    fi
    local actual_owner actual_mode
    actual_owner="$(stat -c '%U:%G' "$file")"
    actual_mode="$(stat -c '%a' "$file")"
    if [[ "$actual_owner" == "$owner" && "$actual_mode" == "$mode" ]]; then
        log "[ OK ] $file ($actual_owner $actual_mode)"
    else
        err "[WARN] $file was $actual_owner $actual_mode (expected $owner $mode) - fixing..."
        chown "$owner" "$file" || die "Could not chown $file to $owner."
        chmod "$mode" "$file" || die "Could not chmod $file to $mode."
        log "[ OK ] Fixed $file to $owner $mode."
    fi
}

check_file /etc/grommunio-keycloak/keycloak.conf groauth:groauth 640
check_file /etc/grommunio-keycloak/grommunio.properties groauth:groauth 640
check_file /etc/gromox/keycloak.json root:groweb 640
check_file /etc/gromox/bearer_pubkey root:root 644

# ============================================================
# Server-level safety net for the keycloak.json permission regression
# (see fix-keycloak-json-perm.sh for the full root cause): the
# check_file call above only re-asserts the permission when THIS step is
# re-run by hand. Any future install/upgrade of grommunio-auth,
# grommunio-pkg-bits, grommunio-chat-v10, grommunio-files,
# grommunio-archive, or grommunio-admin-api/-web fires
# grommunio-auth's own dpkg trigger and silently re-breaks this file,
# completely independently of this step ever running again.
#
# A fix inside one specific package's own postinst/trigger handling
# cannot GUARANTEE it runs after grommunio-auth's trigger within the
# same apt transaction - dpkg does not guarantee processing order
# between independently-interested packages on the same watched
# directory. DPkg::Post-Invoke is the one hook apt guarantees runs after
# a transaction's dpkg run (and all its trigger processing) has fully
# finished - so this is a server-level safety net, not scoped to one
# package, installed once here and then self-sufficient.
# ============================================================

local HOOK_SCRIPT="/usr/local/sbin/fix-keycloak-json-perm.sh"
local HOOK_CONF="/etc/apt/apt.conf.d/99-grommunio-keycloak-json-fix"

backup_file "$HOOK_SCRIPT"
install -m 0755 "${SCRIPT_DIR}/fix-keycloak-json-perm.sh" "$HOOK_SCRIPT" \
    || die "Could not install $HOOK_SCRIPT."
finalize_backup "$HOOK_SCRIPT"

backup_file "$HOOK_CONF"
cat > "$HOOK_CONF" <<EOF
// Re-asserts /etc/gromox/keycloak.json's permission after every apt
// transaction, on this server - see $HOOK_SCRIPT and
// docs/bugreports/grommunio-auth-keycloak-json-cp-a-ignores-umask.md.
// "|| true": a failure here must never fail or block an unrelated apt
// transaction - matches the same guarantee already built into the
// script itself.
DPkg::Post-Invoke { "${HOOK_SCRIPT} || true"; };
EOF
chmod 644 "$HOOK_CONF"
finalize_backup "$HOOK_CONF"
log "[ OK ] Installed $HOOK_SCRIPT and the apt Post-Invoke hook ($HOOK_CONF)."

if systemctl is-active --quiet grommunio-keycloak; then
    log "[ OK ] grommunio-keycloak.service is active."
else
    err "[FAIL] grommunio-keycloak.service is not active."
    verify_failed=1
fi

# Keycloak (a JVM app) takes several seconds to bind its port after a
# (re)start — poll instead of checking once immediately.
local waited=0 port_up=0
while (( waited < 30 )); do
    if ss -ltn 2>/dev/null | grep -q ':9080'; then
        port_up=1
        break
    fi
    sleep 2
    waited=$((waited + 2))
done

if [[ "$port_up" -eq 1 ]]; then
    log "[ OK ] port 9080 (Keycloak, localhost-only) is listening (after ${waited}s)."
else
    err "[FAIL] port 9080 is not listening after ${waited}s."
    verify_failed=1
fi

# nginx upstream for Keycloak must point at 127.0.0.1, not "localhost".
# "localhost" resolves to ::1 first, but Keycloak only listens on IPv4, so
# nginx gets intermittent "connection refused" and SSO logins fail. The file
# is written by the grommunio-auth debconf setup, so it is checked and fixed
# here on every run.
local KC_UPSTREAM="/etc/grommunio-common/nginx/upstreams.d/grommunio-auth.conf"
if [[ -f "$KC_UPSTREAM" ]] && grep -q 'server localhost:9080;' "$KC_UPSTREAM"; then
    backup_file "$KC_UPSTREAM"
    sed -i 's/server localhost:9080;/server 127.0.0.1:9080;/' "$KC_UPSTREAM"
    finalize_backup "$KC_UPSTREAM"
    log "Pointed the nginx Keycloak upstream at 127.0.0.1:9080 (was localhost)."
    nginx -t >/dev/null 2>&1 && systemctl reload nginx
    sleep 2   # reload is asynchronous; let the new workers take over
fi

if [[ -f "$KC_UPSTREAM" ]] && grep -q 'server 127.0.0.1:9080;' "$KC_UPSTREAM"; then
    local kc_fail=0 kc_code
    for _ in 1 2 3 4 5; do
        # up to three tries per request, a moment apart, before counting it as a failure
        kc_code=""
        for _try in 1 2 3; do
            kc_code="$(curl -sk -o /dev/null -w '%{http_code}' -H "Host: ${FQDN:-$(hostname -f)}" \
                https://127.0.0.1/auth/realms/grommunio/.well-known/openid-configuration || true)"
            [[ "$kc_code" == "200" ]] && break
            sleep 1
        done
        [[ "$kc_code" == "200" ]] || kc_fail=1
    done
    if [[ "$kc_fail" -eq 0 ]]; then
        log "[ OK ] Keycloak answers through nginx (5 of 5 requests returned 200)."
    else
        err "[FAIL] Keycloak requests through nginx are not all returning 200 (last code: $kc_code)."
        verify_failed=1
    fi
else
    err "[FAIL] nginx Keycloak upstream is not set to 127.0.0.1:9080 ($KC_UPSTREAM)."
    verify_failed=1
fi

# auth_allow.conf: confirm it's actually restricted, not the wide-open default.
if [[ -f /etc/grommunio-common/nginx/auth_allow.conf ]]; then
    if grep -q '0.0.0.0/0' /etc/grommunio-common/nginx/auth_allow.conf; then
        err "[WARN] /etc/grommunio-common/nginx/auth_allow.conf still allows 0.0.0.0/0 — /auth/admin, /auth/metrics, /auth/health are open to the internet."
    else
        log "[ OK ] /etc/grommunio-common/nginx/auth_allow.conf is restricted: $(tr '\n' ' ' < /etc/grommunio-common/nginx/auth_allow.conf)"
    fi
fi

[[ "$verify_failed" -eq 0 ]] || die "Core verification failed — see errors above before continuing."

# ============================================================
# Verify: discovery endpoint (unauthenticated, always reachable)
# ============================================================

local discovery_json issuer
discovery_json="$(curl -ks "https://${FQDN}/auth/realms/grommunio/.well-known/openid-configuration")"
issuer="$(printf '%s' "$discovery_json" | grep -oE '"issuer":"[^"]*"' | head -n1)"

if [[ -n "$issuer" ]]; then
    log "[ OK ] Discovery endpoint responded: $issuer"
else
    die "Discovery endpoint did not return an issuer. Response: ${discovery_json:0:300}"
fi

# ============================================================
# Report the actual client_id in use (varies by packaging — confirmed
# "grommunio-web" here, not the generic "grommunio" the upstream docs use)
# and note why the password-grant CLI test is intentionally skipped.
# ============================================================

local client_id=""
if [[ -f /etc/grommunio-auth/grommunio-client-web.json ]]; then
    client_id="$(grep -oE '"clientId" *: *"[^"]*"' /etc/grommunio-auth/grommunio-client-web.json | head -n1 | sed -E 's/.*"([^"]+)"$/\1/')"
fi

echo
echo "OIDC client in use: ${client_id:-<unknown>} (not the generic 'grommunio' the upstream docs assume)."
if [[ -f /etc/grommunio-auth/grommunio-client-web.json ]] && grep -q '"directAccessGrantsEnabled" *: *false' /etc/grommunio-auth/grommunio-client-web.json; then
    echo "directAccessGrantsEnabled=false — a deliberate, good security default, not a bug."
    echo "A CLI password-grant token test is intentionally NOT attempted here; the real"
    echo "end-to-end proof is the browser Authorization Code flow below."
fi

# ============================================================
# Verify/fix: audience mapper.
#
# Found live on testvps 2026-09-29: the postinst-driven setup creates the
# realm, client and user federation, but NOT a self-audience mapper on the
# client — so introspection fails with "invalid_token, reason=Client 'X' is
# not in the token audience" the moment anything (e.g. gromox-zcore
# verifying a bearer token) tries to introspect a token this client issued.
# This is a real gap in the package's own automated setup, not something
# the docs even call "expected" — their troubleshooting section frames it
# as something you'd only add if you happen to hit the symptom.
#
# This needs an authenticated kcadm.sh session, which needs the shared
# grommunio admin password. That password is NOT retrievable after the
# fact (debconf's own password-type templates get cleared once consumed;
# confirmed empty in /var/cache/debconf/passwords.dat) — matches how step
# 30 also never persists secrets to /root/cfg-server. So this prompts for
# it here, does not persist it anywhere, and is fully skippable: leave it
# blank to skip and fix it manually later (command printed either way).
# ============================================================

echo
echo "============================================================"
echo " Audience mapper check"
echo "============================================================"
echo

local KCADM=""
KCADM="$(dpkg -L grommunio-keycloak 2>/dev/null | grep -E 'bin/kcadm\.sh$' | head -n1)"

if [[ -z "$KCADM" || ! -x "$KCADM" || -z "$client_id" ]]; then
    die "Cannot check the audience mapper: kcadm.sh or the client_id is missing. Fix the grommunio-keycloak install, then re-run this step."
else
    echo "------------------------------------------------------------"
    echo " Why this step is needed for SSO"
    echo "------------------------------------------------------------"
    echo "grommunio-web logs users in through Keycloak (SSO). After a login,"
    echo "Keycloak gives grommunio-web a token for the '$client_id' client."
    echo "grommunio checks that token by asking Keycloak whether it is valid"
    echo "(introspection). Keycloak only accepts that check when the client has"
    echo "an 'audience' mapper, which this step creates. Without it, the check"
    echo "fails with 'Client ... is not in the token audience' and logins break."
    echo
    echo "Creating the mapper needs the shared admin password, the one"
    echo "grommunio-setup showed you at the end of its run."
    echo
    echo "Type SKIP only if you will add the mapper yourself later."
    echo "Until you do, SSO will not work."
    echo "------------------------------------------------------------"
    local ADMIN_PASSWORD="$SHARED_ADMIN_PASSWORD"
    while true; do
        if [[ -z "$ADMIN_PASSWORD" ]]; then
            read -r -s -p "Shared grommunio admin password (or SKIP): " ADMIN_PASSWORD
            echo
        fi
        if [[ "$ADMIN_PASSWORD" == "SKIP" ]]; then
            ADMIN_PASSWORD=""
            break
        fi
        [[ -n "$ADMIN_PASSWORD" ]] && break
        echo "A password is needed here, because SSO depends on this mapper."
        echo "Enter the admin password, or type SKIP (SSO will not work until fixed)."
    done

    [[ -n "$ADMIN_PASSWORD" ]] && SHARED_ADMIN_PASSWORD="$ADMIN_PASSWORD"
    if [[ -z "$ADMIN_PASSWORD" ]]; then
        err "[WARN] Audience mapper skipped. SSO login will NOT work until it is created."
        log "Fix it manually with:"
        echo "  $KCADM config credentials --server http://localhost:9080/auth --realm master --user admin"
        echo "  CLIENT_UUID=\$($KCADM get clients -r grommunio -q clientId=${client_id} --fields id | grep -oE '\"[a-f0-9-]{36}\"' | tr -d '\"')"
        echo "  $KCADM create \"clients/\${CLIENT_UUID}/protocol-mappers/models\" -r grommunio \\"
        echo "    -s name=grommunio-self-audience -s protocol=openid-connect -s protocolMapper=oidc-audience-mapper \\"
        echo "    -s 'config.\"included.client.audience\"=${client_id}' -s 'config.\"id.token.claim\"=false' \\"
        echo "    -s 'config.\"access.token.claim\"=true' -s 'config.\"introspection.token.claim\"=true'"
    else
        if "$KCADM" config credentials --server http://localhost:9080/auth --realm master --user admin --password "$ADMIN_PASSWORD" >/dev/null 2>&1; then
            local CLIENT_UUID
            CLIENT_UUID="$("$KCADM" get clients -r grommunio -q "clientId=${client_id}" --fields id 2>/dev/null | grep -oE '"[a-f0-9-]{36}"' | tr -d '"')"

            if [[ -z "$CLIENT_UUID" ]]; then
                die "Client '$client_id' not found in realm 'grommunio' via kcadm. Keycloak did not set up the client; re-run this step after fixing that."
            else
                local existing_mapper
                existing_mapper="$("$KCADM" get "clients/${CLIENT_UUID}/protocol-mappers/models" -r grommunio 2>/dev/null | grep -c 'oidc-audience-mapper' || true)"

                if [[ "${existing_mapper:-0}" -gt 0 ]]; then
                    log "[ OK ] An audience mapper already exists on '$client_id' — nothing to do."
                else
                    log "No audience mapper found — creating one..."
                    local create_out=""
                    if create_out="$("$KCADM" create "clients/${CLIENT_UUID}/protocol-mappers/models" -r grommunio \
                        -s name=grommunio-self-audience -s protocol=openid-connect -s protocolMapper=oidc-audience-mapper \
                        -s "config.\"included.client.audience\"=${client_id}" -s 'config."id.token.claim"=false' \
                        -s 'config."access.token.claim"=true' -s 'config."introspection.token.claim"=true' 2>&1)"; then
                        log "[ OK ] kcadm reported the audience mapper created on '$client_id'."
                    else
                        die "Creating the audience mapper failed. kcadm said: $create_out"
                    fi
                    # verify by reading it back, never trust the create's exit code alone
                    local recheck_mapper
                    recheck_mapper="$("$KCADM" get "clients/${CLIENT_UUID}/protocol-mappers/models" -r grommunio 2>/dev/null | grep -c 'oidc-audience-mapper' || true)"
                    if [[ "${recheck_mapper:-0}" -gt 0 ]]; then
                        log "[ OK ] Audience mapper verified on '$client_id'."
                        log "Only affects tokens issued from now on — any already-logged-in browser session needs a fresh login to pick it up."
                    else
                        die "Audience mapper was reported created but is not listed on '$client_id'. Check it with kcadm.sh."
                    fi
                fi

                # Files SSO: the Files "add account" with grommunio login sends a
                # token from this (webmail) login to WebDAV. That token must also
                # carry the grommunio-files audience, or Files answers "the audience
                # does not match the client ID". Only relevant if grommunio-files is
                # actually installed - this used to run unconditionally, creating an
                # orphaned mapper (referencing a client that does not exist) when
                # Files was never installed, found live 2026-11-14.
                if ! dpkg -s grommunio-files >/dev/null 2>&1; then
                    log "grommunio-files is not installed - skipping its audience mapper."
                    log "If you install grommunio-files later, re-run this step (40) to add it."
                else
                    local files_mapper_count
                    files_mapper_count="$("$KCADM" get "clients/${CLIENT_UUID}/protocol-mappers/models" -r grommunio 2>/dev/null | grep -c 'grommunio-files-audience' || true)"
                    if [[ "${files_mapper_count:-0}" -gt 0 ]]; then
                        log "[ OK ] Files audience mapper already exists on '$client_id'."
                    else
                        log "Adding the Files audience mapper on '$client_id'..."
                        local files_create_out=""
                        if ! files_create_out="$("$KCADM" create "clients/${CLIENT_UUID}/protocol-mappers/models" -r grommunio \
                            -s name=grommunio-files-audience -s protocol=openid-connect -s protocolMapper=oidc-audience-mapper \
                            -s 'config."included.client.audience"=grommunio-files' -s 'config."id.token.claim"=false' \
                            -s 'config."access.token.claim"=true' -s 'config."introspection.token.claim"=true' 2>&1)"; then
                            die "Creating the Files audience mapper failed. kcadm said: $files_create_out"
                        fi
                        files_mapper_count="$("$KCADM" get "clients/${CLIENT_UUID}/protocol-mappers/models" -r grommunio 2>/dev/null | grep -c 'grommunio-files-audience' || true)"
                        [[ "${files_mapper_count:-0}" -gt 0 ]] || die "Files audience mapper was reported created but is not listed on '$client_id'."
                        log "[ OK ] Files audience mapper verified on '$client_id'."
                    fi
                fi
            fi
        else
            die "kcadm.sh could not log in as admin: wrong password, or Keycloak is not reachable on localhost:9080. Re-run this step with the admin password from the grommunio-setup screen."
        fi
    fi
fi

echo
echo "============================================================"
echo " Done — CLI-level verification complete"
echo "============================================================"
echo

    # Chat (step 34) sets up its Keycloak SSO here if chat was installed before Keycloak.
    if dpkg -s grommunio-chat-v10 >/dev/null 2>&1 && [[ -n "$SHARED_ADMIN_PASSWORD" ]]; then
        chat_keycloak_sso "$SHARED_ADMIN_PASSWORD"
    fi
}
