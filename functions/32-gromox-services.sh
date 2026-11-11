#!/usr/bin/env bash
#
# 32-gromox-services.sh
#
# Settles which gromox services should run on this server.
#
# gromox-istore is the Information Store as its own process. By default the
# store is loaded inside gromox-http, and gromox-istore only runs when
# gromox.cfg sets istore_standalone. The community gromox 3.12 package enables
# the gromox-istore unit anyway, and it then exits on every start with
# "istore↔http separation not enabled (gromox.cfg:istore_standalone)". The
# result is a failed unit on every boot. Nothing in the mail, web, IMAP, POP3
# or Keycloak path depends on it (verified 2026-10-03).
#
# So: if the unit exists, nothing configures istore_standalone, and it is
# enabled or running, disable it. If a configuration does set istore_standalone,
# leave the unit alone. See SOURCE-DIFFERENCES.md for the package differences.

step_gromox_services()
{
require_cmd systemctl

local GROMOX_CFG="/etc/gromox/gromox.cfg"

if ! systemctl list-unit-files gromox-istore.service --no-legend 2>/dev/null | grep -q '^gromox-istore.service'; then
    log "gromox-istore unit is not installed; nothing to do."
    return 0
fi

if grep -qE '^[[:space:]]*istore_standalone[[:space:]]*=' "$GROMOX_CFG" 2>/dev/null; then
    log "istore_standalone is set in $GROMOX_CFG, so gromox-istore is configured on purpose. Leaving it alone."
    return 0
fi

if systemctl is-enabled --quiet gromox-istore 2>/dev/null || systemctl is-active --quiet gromox-istore; then
    log "Disabling gromox-istore: istore_standalone is not set, so the unit can only fail on start."
    systemctl disable --now gromox-istore
fi
systemctl reset-failed gromox-istore 2>/dev/null || true

# ============================================================
# REAL VULNERABILITY FOUND AND FIXED 2026-10-23: plaintext IMAP/POP3 login
# was accepted with no TLS at all. grommunio-setup's own imap.cfg/pop3.cfg
# only set `imap_support_starttls`/`pop3_support_stls` - which *offer*
# STARTTLS/STLS, but never *require* it. Verified live before fixing: a
# real LOGIN/USER+PASS over a plain, unencrypted socket on 143/110 was
# accepted outright - credentials would go over the wire in cleartext for
# any client that simply doesn't bother with STARTTLS/STLS.
#
# The actual, currently-documented keys (confirmed via `man 8gx imap`/
# `man 8gx pop3` - note the man pages are named "imap"/"pop3", NOT
# "gromox-imap"/"gromox-pop3") are `imap_support_tls`/`imap_force_tls` and
# `pop3_support_tls`/`pop3_force_tls` - different names than what
# grommunio-setup writes, and both default to false/not-required. The
# gromox changelog documents that `force_tls=yes` combined with
# `support_tls=no` is rejected at startup, so `support_tls=yes` must be
# added explicitly alongside `force_tls=yes`, not just the force flag
# alone. Also confirmed (via `strings` on every gromox binary/library):
# gromox has no cipher-suite-list configuration of any kind, so this fix
# is scoped to mandating TLS itself, not cipher selection.
#
# Verified live after the fix: both services log "imap connections MUST
# be using TLS" / "pop3 MUST be running with TLS" on startup; a repeat of
# the same plaintext LOGIN/USER+PASS test now gets "BAD must issue a
# STARTTLS command first" / "-ERR must issue a STLS command first" (IMAP's
# CAPABILITY also now shows LOGINDISABLED); STARTTLS-upgraded IMAP, STLS-
# upgraded POP3, and the implicit-TLS ports (993/995) all still work with
# a real login.
# ============================================================

local IMAP_CFG="/etc/gromox/imap.cfg"
local POP3_CFG="/etc/gromox/pop3.cfg"
local gromox_tls_changed=0

if [[ -f "$IMAP_CFG" ]] && ! grep -qE '^imap_force_tls[[:space:]]*=[[:space:]]*yes' "$IMAP_CFG"; then
    backup_file "$IMAP_CFG"
    grep -qE '^imap_support_tls[[:space:]]*=' "$IMAP_CFG" || echo 'imap_support_tls=yes' >> "$IMAP_CFG"
    grep -qE '^imap_force_tls[[:space:]]*=' "$IMAP_CFG" || echo 'imap_force_tls=yes' >> "$IMAP_CFG"
    finalize_backup "$IMAP_CFG"
    gromox_tls_changed=1
    log "Set imap_support_tls=yes / imap_force_tls=yes in $IMAP_CFG (plaintext IMAP login was being accepted)."
else
    log "[ OK ] $IMAP_CFG already requires TLS."
fi

if [[ -f "$POP3_CFG" ]] && ! grep -qE '^pop3_force_tls[[:space:]]*=[[:space:]]*yes' "$POP3_CFG"; then
    backup_file "$POP3_CFG"
    grep -qE '^pop3_support_tls[[:space:]]*=' "$POP3_CFG" || echo 'pop3_support_tls=yes' >> "$POP3_CFG"
    grep -qE '^pop3_force_tls[[:space:]]*=' "$POP3_CFG" || echo 'pop3_force_tls=yes' >> "$POP3_CFG"
    finalize_backup "$POP3_CFG"
    gromox_tls_changed=1
    log "Set pop3_support_tls=yes / pop3_force_tls=yes in $POP3_CFG (plaintext POP3 login was being accepted)."
else
    log "[ OK ] $POP3_CFG already requires TLS."
fi

if [[ "$gromox_tls_changed" -eq 1 ]]; then
    systemctl restart gromox-imap gromox-pop3 || die "gromox-imap/gromox-pop3 failed to restart after enforcing TLS - check journalctl, and that support_tls=yes was actually written alongside force_tls=yes (gromox rejects the opposite combination at startup)."
    sleep 1
    systemctl is-active --quiet gromox-imap || die "gromox-imap is not active after the TLS-enforcement change."
    systemctl is-active --quiet gromox-pop3 || die "gromox-pop3 is not active after the TLS-enforcement change."
    log "[ OK ] gromox-imap and gromox-pop3 restarted and are active."
fi

# ============================================================
# CBC-mode cipher suites excluded on gromox-imap/gromox-pop3, 2026-10-24
# (user's follow-up to the TLS-enforcement fix above, after comparing
# against Kopano's old ssl_ciphers/ssl_prefer_server_ciphers settings).
# Extended 2026-11-08 to gromox-http and gromox-delivery-queue, the other
# two gromox daemons that terminate TLS themselves (same OPENSSL_CONF
# mechanism, same scoped config file - nothing new to build). Checked
# `ss -ltnp` first: gromox-http (process name "http") genuinely listens
# on its own TLS port (10443, listen_ssl_port in http.cfg) in addition to
# plain 10080 - not just a theoretical config option, real live traffic
# could hit it directly. gromox-delivery-queue has no TLS port actually
# listening right now (only plain port 24 - smtp.cfg has no
# listen_ssl_port set), but its own man page documents lda_listen_tls in
# gromox.cfg as a real, supported option, so it is included proactively:
# harmless while unused, already correct the moment it ever is enabled.
# gromox-zcore (AF_LOCAL socket only, confirmed via its own man page) and
# plain gromox-delivery (no listen/tls settings in its man page at all)
# are not TLS-relevant and are not included.
#
# Re-confirmed first, exhaustively, across every gromox man page (imap,
# pop3, http, gromox, gromox.cfg, midb, zcore, delivery): no equivalent
# of Kopano's ssl_ciphers/ssl_protocols/ssl_prefer_server_ciphers exists
# anywhere in gromox. It relies entirely on OpenSSL's own default cipher
# string, with no app-level override of any kind (confirmed earlier via
# `strings` finding zero cipher-related symbols in any gromox binary/
# library) - so "server cipher order" genuinely cannot be fixed without
# patching and rebuilding gromox itself, out of scope here.
#
# CBC removal specifically *is* achievable without touching gromox or the
# system-wide /etc/ssl/openssl.cnf (which would affect every OpenSSL-using
# program on the box): point only these two services at their own,
# separate OpenSSL config via the OPENSSL_CONF environment variable, with
# a CipherString that drops CBC from the default list they fall back to.
# Verified this mechanism actually works before wiring it into systemd:
# `OPENSSL_CONF=<scoped file> openssl ciphers -v` showed 0 CBC suites
# (24 remain) vs. 20 CBC suites under the normal system default.
#
# The scoped file must be a full copy of the system openssl.cnf, not just
# the new lines - OPENSSL_CONF replaces the whole config, it does not
# merge with the system one, so anything else in there (CA settings,
# provider loading) would otherwise be lost for these two services.
# Regenerated fresh from the current system file every run specifically
# because of this, so a system openssl.cnf update (e.g. a security
# update) is never silently out of sync with this copy.
#
# Verified live after restarting both services: forcing TLS 1.2 with a
# CBC cipher (openssl s_client -tls1_2 -cipher ECDHE-ECDSA-AES256-SHA384)
# now gets a handshake failure on both 993 and 995; forcing the AEAD
# equivalent (...-AES256-GCM-SHA384) still works; and a real IMAPS/POP3S
# login with a throwaway account succeeded on both ports afterward.
# ============================================================

local GROMOX_OPENSSL_CNF="/etc/gromox/openssl-noncbc.cnf"
local GROMOX_OPENSSL_CNF_NEW
GROMOX_OPENSSL_CNF_NEW="$(mktemp)"
cat /etc/ssl/openssl.cnf > "$GROMOX_OPENSSL_CNF_NEW"
# Only add the ssl_conf link if this copy doesn't already have one (a
# fresh copy of the system file never does, but re-running this against
# an already-modified copy must not add a second, conflicting link).
if ! grep -qE '^ssl_conf[[:space:]]*=' "$GROMOX_OPENSSL_CNF_NEW"; then
    sed -i '/^providers[[:space:]]*=[[:space:]]*provider_sect/a ssl_conf = ssl_module' "$GROMOX_OPENSSL_CNF_NEW"
fi
cat >> "$GROMOX_OPENSSL_CNF_NEW" <<'CONF'

[ssl_module]
system_default = system_default_sect

[system_default_sect]
CipherString = DEFAULT:!CBC
CONF

local gromox_openssl_changed=0
if ! cmp -s "$GROMOX_OPENSSL_CNF_NEW" "$GROMOX_OPENSSL_CNF"; then
    backup_file "$GROMOX_OPENSSL_CNF"
    install -m 0644 "$GROMOX_OPENSSL_CNF_NEW" "$GROMOX_OPENSSL_CNF"
    finalize_backup "$GROMOX_OPENSSL_CNF"
    gromox_openssl_changed=1
    log "[ OK ] Wrote $GROMOX_OPENSSL_CNF (CBC-mode ciphers excluded)."
else
    log "[ OK ] $GROMOX_OPENSSL_CNF already correct."
fi
rm -f "$GROMOX_OPENSSL_CNF_NEW"

local svc overrides_changed=0
for svc in gromox-imap gromox-pop3 gromox-http gromox-delivery-queue; do
    local override_dir="/etc/systemd/system/${svc}.service.d"
    local override_file="${override_dir}/override.conf"
    local override_wanted_file
    override_wanted_file="$(mktemp)"
    printf '[Service]\nEnvironment=OPENSSL_CONF=%s\n' "$GROMOX_OPENSSL_CNF" > "$override_wanted_file"
    # cmp, not a $(cat ...) string comparison: command substitution strips
    # trailing newlines, so a string comparison here always reports a
    # difference even when the file is already correct, forcing a needless
    # rewrite + restart every single run.
    if [[ ! -f "$override_file" ]] || ! cmp -s "$override_wanted_file" "$override_file"; then
        install -d -m 0755 "$override_dir"
        backup_file "$override_file"
        install -m 0644 "$override_wanted_file" "$override_file"
        finalize_backup "$override_file"
        overrides_changed=1
        log "[ OK ] Wrote $override_file (OPENSSL_CONF scoped to $svc)."
    else
        log "[ OK ] $override_file already correct."
    fi
    rm -f "$override_wanted_file"
done

if [[ "$gromox_openssl_changed" -eq 1 || "$overrides_changed" -eq 1 ]]; then
    systemctl daemon-reload
    systemctl restart gromox-imap gromox-pop3 gromox-http gromox-delivery-queue \
        || die "One of gromox-imap/gromox-pop3/gromox-http/gromox-delivery-queue failed to restart after the CBC-exclusion change."
    sleep 1
    for svc in gromox-imap gromox-pop3 gromox-http gromox-delivery-queue; do
        systemctl is-active --quiet "$svc" || die "$svc is not active after the CBC-exclusion change."
    done
    log "[ OK ] gromox-imap, gromox-pop3, gromox-http and gromox-delivery-queue restarted and are active (CBC excluded)."
fi

# ============================================================
# Deprecated per-daemon listen settings migrated to gromox.cfg,
# 2026-11-08 - found via a routine log sweep: every restart of
# gromox-http/-imap/-pop3/-delivery-queue logged a [WARN]-level
# "X is deprecated in favor of gromox.cfg:Y" for whichever of
# listen_port/listen_ssl_port (http.cfg, imap.cfg, pop3.cfg) or
# listen_port (smtp.cfg) was explicitly set.
#
# Confirmed via every relevant man page (http.8gx, imap.8gx, pop3.8gx,
# delivery-queue.8gx) which new key replaces which old one, and that
# the new keys take a "bind address specifier" (e.g. "[::]:993"), not
# a bare port number - the old key/value pairs below are exactly what
# was live on testvps before this migration (confirmed with `ss -ltnp`
# unchanged after, same PIDs listening on the same 7 ports).
#
# imap_listen/pop3_listen (the PLAIN, non-TLS ports) are deliberately
# NOT added here: neither imap.cfg nor pop3.cfg ever set listen_port
# explicitly, so they were already using the compiled-in default
# ([::]:143 / [::]:110 per the man pages) - nothing to migrate for
# those two. lda_listen IS added despite looking like it could also
# rely on a default: delivery-queue's own default is [::]:25, but this
# server deliberately runs its LDA on port 24 (Postfix's own transport
# routes final delivery there, port 25 stays Postfix's own), so the
# non-default value must be carried over explicitly or delivery would
# silently move to port 25 on the next restart.
# ============================================================

local -A GROMOX_LISTEN_MIGRATIONS=(
    [http.cfg]="listen_port=http_listen listen_ssl_port=http_listen_tls"
    [imap.cfg]="listen_ssl_port=imap_listen_tls"
    [pop3.cfg]="listen_ssl_port=pop3_listen_tls"
    [smtp.cfg]="listen_port=lda_listen"
)
local gromox_listen_changed=0 gromox_restart_needed=""
local daemon_cfg pair old_key new_key old_val

for daemon_cfg in "${!GROMOX_LISTEN_MIGRATIONS[@]}"; do
    for pair in ${GROMOX_LISTEN_MIGRATIONS[$daemon_cfg]}; do
        old_key="${pair%=*}"
        new_key="${pair#*=}"
        old_val="$(grep -E "^${old_key}=" "/etc/gromox/${daemon_cfg}" 2>/dev/null | tail -1 | cut -d= -f2-)"
        [[ -n "$old_val" ]] || continue
        if grep -qE "^${new_key}=" "$GROMOX_CFG" 2>/dev/null; then
            log "[ OK ] $GROMOX_CFG already has ${new_key}= - leaving ${daemon_cfg}:${old_key} removal to a human if it is somehow still set."
            continue
        fi
        backup_file "$GROMOX_CFG"
        echo "${new_key}=[::]:${old_val}" >> "$GROMOX_CFG"
        finalize_backup "$GROMOX_CFG"
        backup_file "/etc/gromox/${daemon_cfg}"
        sed -i "/^${old_key}=${old_val}\$/d" "/etc/gromox/${daemon_cfg}"
        finalize_backup "/etc/gromox/${daemon_cfg}"
        gromox_listen_changed=1
        case "$daemon_cfg" in
            http.cfg) gromox_restart_needed+=" gromox-http" ;;
            imap.cfg) gromox_restart_needed+=" gromox-imap" ;;
            pop3.cfg) gromox_restart_needed+=" gromox-pop3" ;;
            smtp.cfg) gromox_restart_needed+=" gromox-delivery-queue" ;;
        esac
        log "[ OK ] Migrated ${daemon_cfg}:${old_key}=${old_val} to ${GROMOX_CFG}:${new_key}=[::]:${old_val}."
    done
done

if [[ "$gromox_listen_changed" -eq 1 ]]; then
    # shellcheck disable=SC2086
    systemctl restart $gromox_restart_needed \
        || die "A gromox service failed to restart after migrating its deprecated listen setting to $GROMOX_CFG."
    sleep 1
    # shellcheck disable=SC2086
    for svc in $gromox_restart_needed; do
        systemctl is-active --quiet "$svc" || die "$svc is not active after the listen-setting migration."
    done
    log "[ OK ] Restarted:${gromox_restart_needed} (deprecated listen settings migrated)."
else
    log "[ OK ] No deprecated gromox listen settings found to migrate."
fi

if systemctl is-enabled --quiet gromox-istore 2>/dev/null; then
    die "gromox-istore is still enabled after disabling it."
fi
log "[ OK ] gromox-istore is disabled. The store is served by gromox-http."

# The services that serve the store must be up.
local svc
for svc in gromox-http gromox-zcore gromox-midb; do
    if systemctl is-active --quiet "$svc"; then
        log "[ OK ] $svc is active."
    else
        die "$svc is not active. Check: journalctl -u $svc"
    fi
done
}
