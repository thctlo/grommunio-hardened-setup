#!/usr/bin/env bash
#
# 60-boot-order.sh
#
# Sets the start order of the services, as systemd drop-ins in
# /etc/systemd/system/<unit>.d/10-boot-order.conf, and adds readiness units for
# the services that are slow to answer. Nothing in the packages is changed.
#
# This step must stay the LAST step (highest number), so every service it orders
# is already installed when it runs. A unit that is not installed (for example
# chat when it was not chosen) is skipped, not treated as an error.
#
# Why (found 2026-10-03/04):
#   - the admin API started before MariaDB at boot and fell back to offline mode.
#     Nothing else ordered the services, so the start order only worked by chance.
#   - Keycloak (Java) and chat take 14 s and 33 s to open their ports. systemd
#     counts a unit as started at once, so nginx sent them requests too early
#     and users got 502 at boot.
#   - gromox-http did not order after gromox-timer, so it logged
#     "gx_generic_connect timer_agent@[unix:/run/gromox/timer.sock]:6666: No
#     such file or directory" on every boot where gromox-timer's socket was
#     not yet there (found in a full post-reboot log sweep, 2026-10-24).
#
# How readiness is handled: a oneshot unit per slow service (grommunio-*-ready)
# runs curl with --retry, which keeps trying until the service answers. nginx
# orders after those units. The service units themselves are not changed.
#
# Soft ordering only (After= and Wants=). No Requires= and no BindsTo=, so a
# restart of a dependency does not stop the services that use it.
#
# Security (reviewed 2026-10-04):
#   - firewalld and fail2ban start before any service that accepts connections.
#   - saslauthd starts after MariaDB, because its PAM module reads the mailbox
#     passwords from the database. If the database is down, logins fail safely.
#   - Postfix starts after its MySQL socket bind, so its map lookups see the
#     database. If the bind is missing, mail is deferred, not accepted unchecked.
#   - nginx starts last among the web services, after its upstreams are ready.
#   - The unit and drop-in files hold ordering only, no secrets.

step_boot_order()
{
require_cmd systemctl
require_cmd systemd-analyze
require_cmd curl

local DB="mariadb.service"
local FW="firewalld.service fail2ban.service"

# Units that exist on this system (installed unit files)
# A unit counts as installed when systemd knows it: a unit file, or a generated
# unit such as the fstab mount. 'systemctl cat' fails for anything else.
is_installed()
{
    systemctl cat "$1" >/dev/null 2>&1
}

# ============================================================
# Readiness units: oneshot, retried with curl, stays active once ready
# ============================================================

# write_ready_unit <name> <parent service> <description> <url>
write_ready_unit()
{
    local name="$1" parent="$2" desc="$3" url="$4"
    local file="/etc/systemd/system/${name}.service"
    if ! is_installed "$parent"; then
        log "Skipping ${name}: ${parent} is not installed."
        # Remove a readiness unit this step wrote earlier, so nothing waits on a missing service
        if [[ -f "$file" ]]; then
            systemctl disable "${name}.service" >/dev/null 2>&1 || true
            rm -f "$file"
            log "Removed the stale readiness unit ${name}.service."
        fi
        return 0
    fi
    backup_file "$file"
    cat > "$file" <<EOF
# Readiness check for ${parent}, written by 60-boot-order.sh. Retries until the
# service answers, then stays active, so units that need it can order after it.
[Unit]
Description=${desc}
After=${parent}
Wants=${parent}

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/curl --silent --show-error --output /dev/null --max-time 5 --retry 60 --retry-delay 1 --retry-connrefused --retry-all-errors ${url}
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$file"
    finalize_backup "$file"
    # WantedBy only takes effect once the unit is enabled, or it never starts at boot
    systemctl enable "${name}.service" >/dev/null 2>&1 || die "Could not enable ${name}.service."
    log "Wrote and enabled readiness unit ${name}.service."
}

write_ready_unit "grommunio-keycloak-ready" "grommunio-keycloak.service" \
    "Wait until grommunio Keycloak answers" \
    "http://127.0.0.1:9080/auth/realms/grommunio/.well-known/openid-configuration"
write_ready_unit "grommunio-chat-ready" "grommunio-chat.service" \
    "Wait until grommunio Chat answers" \
    "http://127.0.0.1:8065/api/v4/system/ping"

# Recompute the installed list so the new readiness units count as installed
systemctl daemon-reload

# ============================================================
# Ordering drop-ins: unit | After | Wants (lists are filtered to installed units)
# ============================================================

local -a SPEC=(
    "grommunio-admin-api.service|$DB network.target|$DB"
    "grommunio-keycloak.service|$DB network-online.target|$DB"
    "php8.4-fpm.service|$DB|$DB"
    "saslauthd.service|$DB|$DB"
    "postfix.service|$DB saslauthd.service var-spool-postfix-run-mysqld.mount $FW|$DB saslauthd.service"
    "gromox-zcore.service|$DB $FW gromox-event.service|$DB gromox-event.service"
    "gromox-midb.service|$DB $FW gromox-event.service|$DB gromox-event.service"
    "gromox-http.service|$DB $FW gromox-event.service gromox-timer.service|$DB gromox-event.service gromox-timer.service"
    "gromox-imap.service|$DB $FW gromox-event.service|$DB gromox-event.service"
    "gromox-pop3.service|$DB $FW gromox-event.service|$DB gromox-event.service"
    "gromox-delivery.service|$DB $FW gromox-event.service|$DB gromox-event.service"
    "gromox-delivery-queue.service|$DB $FW gromox-event.service|$DB gromox-event.service"
    "gromox-event.service|$DB $FW|$DB"
    "gromox-timer.service|$DB $FW gromox-event.service|$DB gromox-event.service"
    "grommunio-chat.service|postgresql.service $FW|postgresql.service"
    "grommunio-chat-ready.service|grommunio-chat.service|grommunio-chat.service"
    "grommunio-keycloak-ready.service|grommunio-keycloak.service|grommunio-keycloak.service"
    "nginx.service|$FW php8.4-fpm.service grommunio-admin-api.service grommunio-keycloak-ready.service gromox-http.service grommunio-chat-ready.service|php8.4-fpm.service grommunio-admin-api.service grommunio-keycloak-ready.service gromox-http.service grommunio-chat-ready.service"
)

# keep only the installed units from a space-separated list
filter_installed()
{
    local out="" u
    for u in $1; do
        if is_installed "$u"; then
            out="${out:+$out }$u"
        fi
    done
    printf '%s' "$out"
}

local entry unit after wants dir file wrote=0 skipped=0
for entry in "${SPEC[@]}"; do
    IFS='|' read -r unit after wants <<< "$entry"
    if ! is_installed "$unit"; then
        log "Skipping $unit: not installed."
        # Remove an ordering drop-in written by an earlier run, so nothing orders after a missing unit
        if [[ -f "/etc/systemd/system/${unit}.d/10-boot-order.conf" ]]; then
            rm -f "/etc/systemd/system/${unit}.d/10-boot-order.conf"
            log "Removed the stale boot-order drop-in for ${unit}."
        fi
        skipped=$((skipped + 1))
        continue
    fi
    after="$(filter_installed "$after")"
    wants="$(filter_installed "$wants")"
    dir="/etc/systemd/system/${unit}.d"
    file="${dir}/10-boot-order.conf"
    mkdir -p "$dir"
    backup_file "$file"
    {
        echo "# Boot order, written by 60-boot-order.sh. Soft ordering only: no"
        echo "# Requires/BindsTo, so a restarting dependency does not stop this unit."
        echo "[Unit]"
        [[ -n "$after" ]] && echo "After=$after"
        [[ -n "$wants" ]] && echo "Wants=$wants"
    } > "$file"
    chmod 644 "$file"
    finalize_backup "$file"
    wrote=$((wrote + 1))
done
log "Wrote $wrote boot-order drop-in(s); skipped $skipped unit(s) that are not installed."

# Remove the old Keycloak start-wait drop-in content, if any: this file now holds
# ordering only (rewritten above), so nothing else to do here.

systemctl daemon-reload

# No ordering cycles: systemd-analyze reports them, and the step must stop
local verify_out
verify_out="$(for entry in "${SPEC[@]}"; do
    IFS='|' read -r unit _ _ <<< "$entry"
    is_installed "$unit" && systemd-analyze verify "$unit" 2>&1
done || true)"
if grep -qi 'cycle' <<< "$verify_out"; then
    echo "$verify_out" >&2
    die "systemd reports an ordering cycle in the boot-order drop-ins."
fi
log "[ OK ] No ordering cycles."

# The database-using services must order after MariaDB
local u
for u in grommunio-admin-api grommunio-keycloak php8.4-fpm saslauthd postfix gromox-http; do
    if is_installed "${u}.service"; then
        if systemctl show "${u}.service" -p After --value | tr ' ' '\n' | grep -qx "$DB"; then
            log "[ OK ] ${u} starts after ${DB}."
        else
            die "${u} does not start after ${DB} (boot order not applied)."
        fi
    fi
done

# nginx must order after its upstreams, including their readiness units
if is_installed "nginx.service"; then
    local nginx_after
    nginx_after="$(systemctl show nginx.service -p After --value)"
    for u in grommunio-admin-api.service grommunio-keycloak-ready.service gromox-http.service grommunio-chat-ready.service; do
        if is_installed "$u"; then
            tr ' ' '\n' <<< "$nginx_after" | grep -qx "$u" || die "nginx does not start after $u."
        fi
    done
    log "[ OK ] nginx starts after its upstreams and their readiness units."
fi

log "[ OK ] Boot order set. Test it with a reboot: the admin API must not report a database error at boot, and nginx must not return 502 at boot."
}
