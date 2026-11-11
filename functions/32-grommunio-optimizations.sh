#!/usr/bin/env bash
#
# 32-grommunio-optimizations.sh
#
# Small, independent default-tuning fixes for grommunio/gromox that are
# not big enough to be their own numbered step, and don't change any
# install order - each one is its own self-contained function, called in
# sequence from step_grommunio_optimizations(). Add future one-off
# defaults here rather than inventing a new step number per tweak.
#
# Convention for every tweak added here: it must be verified NOT to
# affect grommunio/gromox's own functioning - that is the bar for
# belonging in this file at all, not just "seems harmless".

step_grommunio_optimizations()
{
disable_unused_ldap
raise_webmail_upload_limit
}

# ============================================================
# disable_unused_ldap: this server never uses LDAP (users are created
# directly via grommunio-admin, confirmed live - `grommunio-admin ldap
# check` reports no imported users and no LDAP config exists at all).
# Found 2026-11-07: every admin-web dashboard page load lazily tries to
# instantiate the LDAP service anyway (ServiceHub's lazy-loading design),
# and /etc/gromox/ldap_adaptor.cfg not existing at all makes it fail
# config validation, logging a real [ERROR] every time:
#   (ldap@default) Failed to load service: Missing required config
#   value 'ldap_search_base'
#
# The package's own, documented way to turn this off is
# ldap_disabled = true in ldap_adaptor.cfg (services/ldap.py checks
# config.get("disabled") and raises ServiceDisabledError, which
# ServiceHub logs as a WARNING, not an ERROR - services/__init__.py
# distinguishes the two).
#
# REAL UPSTREAM QUIRK FOUND while verifying this live, not assumed: that
# disabled check runs AFTER _checkConfig() validates every required
# field (baseDn/objectID/users/connection) unconditionally - so setting
# only ldap_disabled=true does NOT actually avoid the error; the same
# KeyError fires first regardless, confirmed by setting it and watching
# the log (still "[ERROR] ... Missing required config value
# 'ldap_search_base'", unchanged). Fully silencing this would need fake
# placeholder values for every required field just to let validation
# pass before the disabled check is ever reached - that is worse than
# the log line itself (looks like LDAP is half-configured when it is
# simply unused). Left as a real, understood, purely cosmetic residual:
# the service never actually runs either way (confirmed via
# `grommunio-admin service status` - ldap stays at "0 instances"),
# nothing else is affected.
#
# Still sets ldap_disabled=true anyway: it is the correct, explicit way
# to say "LDAP is deliberately off" regardless of the log-level quirk,
# and is a real, documented config option future code (or a future
# package version fixing the validation order) can act on correctly.
# ============================================================

disable_unused_ldap()
{
local CFG="/etc/gromox/ldap_adaptor.cfg"

if [[ -f "$CFG" ]] && grep -qE '^\s*ldap_disabled\s*=\s*(true|yes|1)\s*$' "$CFG"; then
    log "[ OK ] $CFG already has ldap_disabled = true."
    return 0
fi

if [[ -f "$CFG" ]]; then
    log "$CFG exists without ldap_disabled - appending it, leaving the rest of the file alone."
    backup_file "$CFG"
    printf '\nldap_disabled = true\n' >> "$CFG"
    finalize_backup "$CFG"
else
    log "Creating $CFG with ldap_disabled = true (LDAP is not used on this server)."
    printf 'ldap_disabled = true\n' > "$CFG"
fi
chown grommunio:gromoxcf "$CFG"
chmod 640 "$CFG"

systemctl try-reload-or-restart grommunio-admin-api >/dev/null 2>&1 || true
log "[ OK ] LDAP service marked disabled in $CFG."
}

# ============================================================
# raise_webmail_upload_limit: grommunio-web's own PHP-FPM pool
# (pool-grommunio-web.conf) has no upload_max_filesize/post_max_size
# override at all, so it inherits php.ini's defaults (2M/8M) - found
# 2026-11-11 chasing a "150MB like Office 365" target across the whole
# stack (ModSecurity, Postfix, grommunio-files) for attachment/upload
# size: webmail's own "attach a file when composing mail" feature was
# the one place left capped far below that, since it is a classic
# multipart/form-data upload through PHP (unlike WebDAV PUT, which
# bypasses PHP's upload handling - see 39-nginx-modsecurity.sh's
# id:9000024/9000025 for that side).
#
# grommunio-files' own pool (pool-grommunio-files.conf) already
# overrides both to 10G - confirmed live, no change needed there, it
# already exceeds the 150MB target by a wide margin.
#
# post_max_size set slightly above upload_max_filesize (155M vs 150M),
# standard PHP guidance: POST data includes the uploaded file plus
# other form fields/multipart boundaries, so it must be able to hold
# slightly more than the file alone.
# ============================================================

raise_webmail_upload_limit()
{
local CFG="/etc/php/8.4/fpm/pool.d/pool-grommunio-web.conf"

[[ -f "$CFG" ]] || { log "[ OK ] $CFG does not exist - skipping (grommunio-web pool not installed this way)."; return 0; }

if grep -q 'php_admin_value\[upload_max_filesize\]' "$CFG"; then
    log "[ OK ] $CFG already has an upload_max_filesize override."
    return 0
fi

backup_file "$CFG"
cat >> "$CFG" <<'EOF'
; Added by 32-grommunio-optimizations.sh: no override existed here, so
; this pool inherited php.ini's defaults (2M/8M) - far below the 150MB
; (Office 365-matching) attachment size target used elsewhere in this
; project. post_max_size set slightly above upload_max_filesize per
; standard PHP guidance (POST data = the file plus other form fields).
php_admin_value[upload_max_filesize] = 150M
php_admin_value[post_max_size] = 155M
EOF
finalize_backup "$CFG"

systemctl reload php8.4-fpm || die "php8.4-fpm reload failed after raising the webmail upload limit."
log "[ OK ] Webmail upload limit raised to 150M/155M in $CFG."
}
