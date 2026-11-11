#!/usr/bin/env bash
#
# 33-nginx-sites.sh
#
# Sets which nginx sites are enabled. Debian's nginx package enables its own
# "default" site, which listens on port 80 as default_server with server_name _.
# grommunio's catch-all uses the same name, so nginx reports
# 'conflicting server name "_" ... ignored' and grommunio's port 80 catch-all is
# dropped. Requests to unknown hosts then get Debian's welcome page. The
# community install docs say to remove this site, and our install did not.
#
# Debian has no enable/disable command for nginx sites (a2ensite and a2dissite
# are Apache tools). The Debian way is the symlink in sites-enabled/: enabling a
# site creates the link, disabling it removes the link. The site file in
# sites-available/ is kept, so it can be enabled again.
#
# Same for both package sources (see SOURCE-DIFFERENCES.md).

# nginx_site_enable <name>: link sites-available/<name> into sites-enabled/
nginx_site_enable()
{
    local name="$1"
    local avail="/etc/nginx/sites-available/${name}"
    local link="/etc/nginx/sites-enabled/${name}"
    [[ -f "$avail" ]] || die "nginx site $name does not exist in /etc/nginx/sites-available."
    if [[ ! -L "$link" ]]; then
        ln -s "$avail" "$link"
        log "Enabled nginx site $name."
    fi
}

# nginx_site_disable <name>: remove the link in sites-enabled/, keep the site file
nginx_site_disable()
{
    local name="$1"
    local link="/etc/nginx/sites-enabled/${name}"
    if [[ -L "$link" || -e "$link" ]]; then
        rm -f "$link"
        log "Disabled nginx site $name (removed ${link})."
    fi
}

step_nginx_sites()
{
require_cmd nginx
require_cmd systemctl

nginx_site_disable default

# The grommunio sites are not in sites-enabled/; they come from the grommunio
# configuration included by nginx.conf. Nothing else to enable here.

if ! nginx -t >/tmp/nginx-test.$$ 2>&1; then
    cat /tmp/nginx-test.$$ >&2
    rm -f /tmp/nginx-test.$$
    die "nginx configuration test failed after disabling the default site."
fi
if grep -q 'conflicting server name' /tmp/nginx-test.$$; then
    grep 'conflicting server name' /tmp/nginx-test.$$ >&2
    rm -f /tmp/nginx-test.$$
    die "nginx still reports conflicting server names. Check the sites listed above."
fi
rm -f /tmp/nginx-test.$$
log "[ OK ] nginx configuration test passes with no conflicting server names."

systemctl reload nginx
sleep 2   # reload is asynchronous; let the new workers take over before checking
log "nginx reloaded."

# Unknown hosts on port 80 must not get Debian's welcome page any more.
local body
body="$(curl -s --max-time 10 -H 'Host: unknown.example' http://127.0.0.1/ || true)"
if grep -qi 'Welcome to nginx' <<< "$body"; then
    die "Port 80 still answers with Debian's default welcome page."
fi
log "[ OK ] Port 80 no longer answers with Debian's default page."

# TLS settings: 256-bit AEAD suites only, explicit ECDH curves. The default list
# has CBC and 128-bit suites that SSL Labs rates lower. The server order is not
# set here: nginx.conf already sets ssl_prefer_server_ciphers, and a second one fails.
local TLS_CFG="/etc/nginx/conf.d/tls-ciphers.conf"
local TLS_NEW
TLS_NEW="$(mktemp)"
cat > "$TLS_NEW" <<'CONF'
# /etc/nginx/conf.d/tls-ciphers.conf (managed by 33-nginx-sites.sh)
# TLS 1.2: 256-bit AEAD suites only (GCM and ChaCha20). CBC and 128-bit suites are weak or lower-strength (SSL Labs).
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
# Key exchange: post-quantum hybrid first (X25519MLKEM768), then X25519 and the NIST curves.
# Setting ssl_ecdh_curve replaces OpenSSL's default group list, so the hybrid group must be listed here.
ssl_ecdh_curve X25519MLKEM768:X25519:secp384r1:secp256r1;
# TLS 1.3: 256-bit suites only.
ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
CONF
if ! cmp -s "$TLS_NEW" "$TLS_CFG"; then
    backup_file "$TLS_CFG"
    install -m 0644 "$TLS_NEW" "$TLS_CFG"
    finalize_backup "$TLS_CFG"
    nginx -t >/dev/null 2>&1 || die "nginx config test fails after writing $TLS_CFG."
    systemctl reload nginx
    log "[ OK ] Wrote $TLS_CFG (AEAD-only TLS 1.2 ciphers) and reloaded nginx."
else
    log "[ OK ] $TLS_CFG already correct."
fi
rm -f "$TLS_NEW"

# REAL GAP FOUND AND FIXED 2026-10-23: admin-web (port 8443) did not use the
# ssl_ciphers/ssl_protocols above at all - grommunio-admin-common ships its
# own, separate nginx-ssl-params.conf, included directly inside the
# admin-web server{} block, which sets its own (older, weaker) cipher list
# including two CBC-mode suites and TLSv1/1.1, and this SAME-block include
# takes precedence over the http-level $TLS_CFG above. Confirmed with
# testssl.sh: 8443 offered CBC and TLSv1/1.1 where 443 (main site, served
# from the same nginx) did not.
#
# Cannot simply add a second ssl_ciphers/ssl_protocols directive via another
# include in that same server{} block either - nginx rejects that outright
# ("directive is duplicate") the same way $TLS_CFG's own comment above
# already notes for ssl_prefer_server_ciphers. The package file itself is
# the only place these are actually set for this vhost, so it is managed
# directly here (idempotent, with a backup each time it needs rewriting) -
# the same pattern used elsewhere in this project for self-healing
# package-shipped defaults that could be reverted by an update.
local ADMIN_SSL_PARAMS="/usr/share/grommunio-admin-common/nginx-ssl-params.conf"
if [[ -f "$ADMIN_SSL_PARAMS" ]]; then
    local admin_ssl_changed=0
    if grep -q '^ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;' "$ADMIN_SSL_PARAMS"; then
        backup_file "$ADMIN_SSL_PARAMS"
        sed -i 's/^ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;/ssl_protocols TLSv1.2 TLSv1.3;/' "$ADMIN_SSL_PARAMS"
        admin_ssl_changed=1
        log "Set ssl_protocols = TLSv1.2 TLSv1.3 in $ADMIN_SSL_PARAMS (was TLSv1..1.3)."
    fi
    if ! grep -qF 'ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;' "$ADMIN_SSL_PARAMS"; then
        [[ "$admin_ssl_changed" -eq 1 ]] || backup_file "$ADMIN_SSL_PARAMS"
        sed -i 's/^ssl_ciphers .*/ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;/' "$ADMIN_SSL_PARAMS"
        admin_ssl_changed=1
        log "Removed CBC-mode cipher suites from $ADMIN_SSL_PARAMS (matches the AEAD-only list \$TLS_CFG uses for every other vhost)."
    fi
    finalize_backup "$ADMIN_SSL_PARAMS"
    if [[ "$admin_ssl_changed" -eq 1 ]]; then
        nginx -t >/dev/null 2>&1 || die "nginx config test fails after editing $ADMIN_SSL_PARAMS - restore from the .bak file just written."
        systemctl reload nginx
        log "[ OK ] $ADMIN_SSL_PARAMS fixed and nginx reloaded."
    else
        log "[ OK ] $ADMIN_SSL_PARAMS already correct."
    fi
else
    log "[WARN] $ADMIN_SSL_PARAMS not found - grommunio-admin-common not installed yet, or its layout changed."
fi

# grommunio-web requests /web/manifest.webmanifest, but the package does not ship
# the file (nginx returned 404 on every request). Add it when missing; the
# icons are the ones the web client ships.
local MANIFEST="/usr/share/grommunio-web/manifest.webmanifest"
if [[ ! -f "$MANIFEST" ]]; then
    cat > "$MANIFEST" <<'JSON'
{
  "name": "grommunio Web",
  "short_name": "grommunio",
  "description": "grommunio webmail, calendar and contacts",
  "start_url": "/web/",
  "scope": "/web/",
  "display": "standalone",
  "background_color": "#ffffff",
  "theme_color": "#ffffff",
  "icons": [
    { "src": "/web/client/resources/images/grommunio_icon_192.png", "sizes": "192x192", "type": "image/png" },
    { "src": "/web/client/resources/images/grommunio_icon_512.png", "sizes": "512x512", "type": "image/png" }
  ]
}
JSON
    chmod 644 "$MANIFEST"
    log "[ OK ] Wrote $MANIFEST (the grommunio-web package does not ship it)."
else
    log "[ OK ] $MANIFEST present."
fi
}
