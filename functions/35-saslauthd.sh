#!/usr/bin/env bash
#
# 35-saslauthd.sh
#
# Fixes a real gap in grommunio-setup: it correctly wires up everything SMTP
# AUTH needs — /etc/postfix/sasl/smtpd.conf (pwcheck_method: saslauthd),
# /etc/pam.d/smtp (pam_gromox.so, gromox's own PAM module that talks
# straight to mysql_adaptor/ldap_adaptor, no other gromox service needs to
# be running for it to work), /etc/default/saslauthd (START=yes, MECHANISMS
# =pam, -r flag so the full user@domain survives to pam_gromox) — but never
# actually enables/starts the saslauthd daemon itself. Confirmed as a real
# gap: docs.grommunio.com's own post-install checklist lists `saslauthd`
# as an expected running unit. Without it, Postfix logs "cannot connect to
# saslauthd server: No such file or directory" and NO client can
# authenticate to send mail via the submission port.
#
# This step only DETECTS the PAM file and the SASL appname config — it
# never writes/recreates those, since grommunio-setup's install already
# gets them right. If either is missing, that means this isn't a normal
# grommunio-setup install and this step stops rather than guessing at a
# replacement.
#
# /etc/default/saslauthd (START=yes, OPTIONS's "-r" flag) is a partial
# exception: grommunio-setup is what normally sets these (confirmed by
# reading its source), but nothing guarantees they STAY set - a sasl2-bin
# package upgrade can offer to restore the maintainer's stock conffile
# (START=no, no "-r"), silently undoing it. So every run of this step
# re-checks and, if needed, re-applies ONLY those two things, using
# Debian's own file layout and grommunio-setup's own values - never a
# different OPTIONS structure, and never the "-m" mux path, which stays
# Debian's own default (bridged into the chroot via the bind mount
# below, not by changing where saslauthd puts its socket).
#
# The 'submission' (587, STARTTLS) master.cf block is a partial exception:
# grommunio-setup DOES create this one itself (confirmed by reading its
# source), but it was found missing entirely on testvps 2026-10-22 (only a
# hand-added 'submissions' (465) block existed, added separately from the
# wizard at some unknown point) - docs.grommunio.com's own post-install
# guide lists Postfix's ports as "25, 587 (465 where implicit-TLS
# submission is enabled)", and the Admin UI's own DNS check looks for a
# `_submission` SRV record (587), not `_submissions`. So this step now
# creates 'submission' (587) if it's missing, using grommunio-setup's own
# exact recipe - and leaves any existing 'submissions' (465) block alone,
# since the docs frame 465 as an addition, not a replacement.

step_saslauthd()
{
require_cmd systemctl
require_cmd postconf

# ============================================================
# Preconditions: verify grommunio-setup's own SASL/PAM wiring is present.
# We only ever READ these — never write them.
# ============================================================

if [[ ! -f /etc/pam.d/smtp ]] || ! grep -q 'pam_gromox.so' /etc/pam.d/smtp; then
    err "/etc/pam.d/smtp missing or does not reference pam_gromox.so."
    err "This step only enables saslauthd on top of grommunio-setup's own PAM wiring — it does not create it. Run grommunio-setup first."
    return 1
fi

if [[ ! -f /etc/postfix/sasl/smtpd.conf ]] || ! grep -q '^pwcheck_method: *saslauthd' /etc/postfix/sasl/smtpd.conf; then
    err "/etc/postfix/sasl/smtpd.conf missing or not configured for pwcheck_method: saslauthd."
    err "This step only enables saslauthd on top of grommunio-setup's own Postfix SASL config — it does not create it. Run grommunio-setup first."
    return 1
fi

if ! command -v saslauthd >/dev/null 2>&1; then
    err "saslauthd binary not found (sasl2-bin not installed)."
    return 1
fi

log "Found grommunio-setup's existing PAM/SASL wiring (pam_gromox.so, pwcheck_method: saslauthd) — using it as-is."

# ============================================================
# Self-heal /etc/default/saslauthd's START= and OPTIONS's "-r" flag,
# every run - see the file header for why this can't just be trusted
# once and never re-checked. Backs up before any edit. Uses grommunio-
# setup's own exact values; never touches the "-m" mux path.
# ============================================================

SASLAUTHD_DEFAULT="/etc/default/saslauthd"
[[ -f "$SASLAUTHD_DEFAULT" ]] || die "$SASLAUTHD_DEFAULT not found — sasl2-bin not installed as expected."

SASLAUTHD_DEFAULT_CHANGED=0

if grep -q '^START=yes' "$SASLAUTHD_DEFAULT"; then
    log "[ OK ] START=yes already set in $SASLAUTHD_DEFAULT."
else
    backup_file "$SASLAUTHD_DEFAULT"
    if grep -q '^START=' "$SASLAUTHD_DEFAULT"; then
        sed -i 's/^START=.*/START=yes/' "$SASLAUTHD_DEFAULT"
    else
        sed -i '0,/^$/s//START=yes/' "$SASLAUTHD_DEFAULT"
    fi
    SASLAUTHD_DEFAULT_CHANGED=1
    log "Set START=yes in $SASLAUTHD_DEFAULT (was missing/no — a package upgrade's conffile prompt can silently revert this)."
fi

if grep -qE '^OPTIONS="-r ' "$SASLAUTHD_DEFAULT"; then
    log "[ OK ] OPTIONS already has the -r flag in $SASLAUTHD_DEFAULT."
elif grep -qE '^OPTIONS="' "$SASLAUTHD_DEFAULT"; then
    [[ "$SASLAUTHD_DEFAULT_CHANGED" -eq 1 ]] || backup_file "$SASLAUTHD_DEFAULT"
    sed -i -E 's/^OPTIONS="(.*)"$/OPTIONS="-r \1"/' "$SASLAUTHD_DEFAULT"
    SASLAUTHD_DEFAULT_CHANGED=1
    log "Added the -r flag to OPTIONS in $SASLAUTHD_DEFAULT (was missing — without it, PAM only sees the bare username, not user@domain, and pam_gromox can't tell domains apart)."
else
    die "$SASLAUTHD_DEFAULT has no OPTIONS= line in the expected quoted form — not a normal sasl2-bin install, refusing to guess one."
fi
finalize_backup "$SASLAUTHD_DEFAULT"

# ============================================================
# Ensure the 'submission' (587, STARTTLS) listener exists, matching
# grommunio's own documentation (docs.grommunio.com/guides/post-install/
# lists Postfix's ports as "25, 587 (465 where implicit-TLS submission is
# enabled)" - 587 is the documented baseline, 465 an optional addition)
# and grommunio's own Admin UI, which checks DNS for a `_submission` SRV
# record specifically (port 587) - not `_submissions`.
#
# REAL GAP FOUND 2026-10-22: testvps had only a hand-added 'submissions'
# (465, implicit TLS) block - confirmed by reading grommunio-setup's own
# source, which only ever configures 'submission' (587) and never touches
# 'submissions' at all. So the 465 block was added manually at some point,
# separate from the wizard, and 587 - the one grommunio's own docs/DNS
# checker actually expect - was simply never there. Built here using
# grommunio-setup's own exact recipe (`postconf -M` for the base line,
# `postconf -P` for each override) - safe to use postconf here, unlike
# the raw hand-written "-o" lines under 'submissions': nothing existing
# to destroy, and postconf manages its own entries consistently.
# Idempotent: skipped entirely if 'submission/inet' already exists.
# Leaves the existing 'submissions' (465) block completely untouched -
# docs frame 465 as an addition, not a replacement, and it already works.
# ============================================================

local SUBMISSION_JUST_CREATED=0
if postconf -M 2>/dev/null | awk '{print $1, $2}' | grep -qx 'submission inet'; then
    log "[ OK ] submission (587) listener already exists - not touching its base config."
else
    log "Creating the 'submission' (587, STARTTLS) listener - grommunio's own documented default, matching grommunio-setup's exact recipe..."
    postconf -M submission/inet="submission inet n - n - - smtpd" \
        || die "Could not create the submission/inet (587) service."
    postconf -P submission/inet/syslog_name="postfix/submission" \
        submission/inet/smtpd_tls_security_level=encrypt \
        submission/inet/smtpd_sasl_auth_enable=yes \
        submission/inet/smtpd_relay_restrictions=permit_sasl_authenticated,reject \
        submission/inet/milter_macro_daemon_name=ORIGINATING \
        || die "Could not set submission/inet's overrides."
    SUBMISSION_JUST_CREATED=1
    log "[ OK ] Created submission (587), matching grommunio-setup's own recipe exactly."
fi

# ============================================================
# Create the 'submissions' (465, implicit TLS / RFC 8314) listener.
#
# Previously left as a deliberate TODO: grommunio-setup never creates
# this one at all (confirmed by reading its source - it only ever
# configures 'submission', 587). Added now, mirroring
# 'submission' (587) exactly, with the one difference implicit TLS
# actually requires: smtpd_tls_wrappermode=yes instead of
# smtpd_tls_security_level=encrypt (the connection is TLS-wrapped from the
# first byte - there is no STARTTLS command on this port at all, so
# "security_level=encrypt" alone would not start TLS). Also carries the
# same hardening as the SUBMISSION_HARDENING block below (applied
# separately, that loop already targets both 'submission' and
# 'submissions' generically). Idempotent: skipped entirely if
# 'submissions/inet' already exists.
# ============================================================

local SUBMISSIONS_JUST_CREATED=0
if postconf -M 2>/dev/null | awk '{print $1, $2}' | grep -qx 'submissions inet'; then
    log "[ OK ] submissions (465) listener already exists - not touching its base config."
else
    log "Creating the 'submissions' (465, implicit TLS) listener..."
    postconf -M submissions/inet="submissions inet n - y - - smtpd" \
        || die "Could not create the submissions/inet (465) service."
    postconf -P submissions/inet/syslog_name="postfix/submissions" \
        submissions/inet/smtpd_tls_wrappermode=yes \
        submissions/inet/smtpd_sasl_auth_enable=yes \
        submissions/inet/smtpd_relay_restrictions=permit_sasl_authenticated,reject \
        submissions/inet/milter_macro_daemon_name=ORIGINATING \
        || die "Could not set submissions/inet's overrides."
    SUBMISSIONS_JUST_CREATED=1
    log "[ OK ] Created submissions (465, implicit TLS)."
fi

# ============================================================
# REAL GAP FOUND AND CLOSED 2026-10-22, same day as the above: Debian's
# own commented-out master.cf template for 'submission' lists several
# more overrides than grommunio-setup's recipe applies, and - critically -
# the already-live 'submissions' (465) block (the one added by hand,
# separate from grommunio-setup) already HAD all of these. The freshly
# built 'submission' (587) above did not. Checked empirically on testvps:
# without this, an UNAUTHENTICATED client could MAIL FROM/RCPT TO a local
# mailbox over port 587 and only get rejected by rspamd's milter, not by
# Postfix's own restrictions (permit_mynetworks in the global
# smtpd_recipient_restrictions chain would otherwise have let a loopback
# connection through) - meaning a confirmed `milter_default_action =
# accept` fail-open during an rspamd outage would have let unauthenticated
# relay through on 587. Fixed by giving submission/inet its own narrow
# `permit_sasl_authenticated,reject`, matching 'submissions' exactly, so
# this no longer depends on the milter being up. The other three
# (`smtpd_tls_auth_only`, `local_header_rewrite_clients`,
# `smtpd_hide_client_session`) are added for parity/defense-in-depth,
# matching Debian's own template and the existing 'submissions' block.
# Idempotent: only sets what's not already there, every run (not just on
# creation) - cheap to re-check and the authoritative fix for both a
# fresh listener and one that already existed before this was added here.
#
# Extended 2026-10-26 to also cover 'submissions' (465), created above -
# same hardening rationale applies identically to both listeners (both are
# authenticated-client-facing, both should reject the same way if SASL
# auth didn't happen). Skips a service name that doesn't exist (e.g. if a
# future run ever finds 'submissions' absent again).
# ============================================================

local SUBMISSION_HARDENING_CHANGED=0
local -A SUBMISSION_HARDENING=(
    [smtpd_tls_auth_only]=yes
    [local_header_rewrite_clients]=static:all
    [smtpd_hide_client_session]=yes
    [smtpd_reject_unlisted_recipient]=no
    [smtpd_recipient_restrictions]=permit_sasl_authenticated,reject
)
local svc param want have
for svc in submission submissions; do
    postconf -M 2>/dev/null | awk '{print $1, $2}' | grep -qx "${svc} inet" || continue
    for param in "${!SUBMISSION_HARDENING[@]}"; do
        want="${SUBMISSION_HARDENING[$param]}"
        have="$(postconf -P 2>/dev/null | awk -F' = ' -v p="${svc}/inet/${param}" '$1==p {print $2}')"
        if [[ "$have" == "$want" ]]; then
            log "[ OK ] ${svc}/inet/${param} is already ${want}."
        else
            postconf -P "${svc}/inet/${param}=${want}" || die "Could not set ${svc}/inet/${param}."
            SUBMISSION_HARDENING_CHANGED=1
            log "Set ${svc}/inet/${param} = ${want} (was: '${have:-<unset>}')."
        fi
    done
done

if [[ "$SUBMISSION_JUST_CREATED" -eq 1 || "$SUBMISSIONS_JUST_CREATED" -eq 1 || "$SUBMISSION_HARDENING_CHANGED" -eq 1 ]]; then
    postfix check || die "postfix check failed after configuring submission/inet."
    systemctl restart postfix || die "postfix restart failed after configuring submission/inet."
fi

# ============================================================
# Harden the submission listener to match Debian's own stock master.cf
# template (still present, commented out, right above grommunio-setup's
# own active block — confirmed live on testvps 2026-10-22): chroot=y.
# grommunio-setup's own postinst deliberately sets chroot=n instead
# (`postconf -M submission/inet="submission inet n - n - - smtpd"`),
# presumably to sidestep needing the saslauthd bind mount below - but
# nothing else in its override block (TLS cert paths, the milter) needs
# unchrooted filesystem access, so there is no real reason not to use
# Debian's own, more defensive default. All chrooted Postfix services
# share the SAME jail root (/var/spool/postfix/), so this does not need
# its own copy of the MySQL-socket bind mount below - smtp:25 (already
# chroot=y, unmodified Debian default) already provides it.
#
# REAL MISTAKE MADE AND FIXED 2026-10-22: the first version of this used
# `postconf -M service/inet=...` to flip just the chroot column. That
# command does NOT edit the matching line in place - it silently
# stripped every "-o ..." override line attached to the service (the TLS/
# SASL/relay-restriction hardening grommunio-setup had written) and
# relocated a bare, unprotected copy of the line to the end of the file.
# It also treated "submission" as already existing when only
# "submissions" ever was, and created a second, completely unprotected
# port 587 listener out of nothing. Caught within minutes on testvps via
# a live `postconf -P`/`ss -tlnp` check (not a dry run) and restored by
# hand from content read earlier in the same session; the actual
# functional exposure was limited - global `smtpd_recipient_restrictions`
# still includes `reject_unauth_destination`, so this was never an open
# relay - but SASL AUTH was unofferable and TLS not mandatory on this
# listener for the few minutes the bad config was live.
#
# Replaced with a precise, read-only-aware direct edit: for EACH active
# service line that genuinely exists (submission and/or submissions -
# both now, after the block above), flip only field 5 (chroot) on that
# single line via awk, and never touch anything else - every "-o" line
# below it is a separate physical line this edit never reads or
# rewrites. Backs up master.cf first, validates with `postfix check`
# before restarting, same convention as every other config file this
# framework edits.
# ============================================================

local MASTER_CF="/etc/postfix/master.cf"
local SERVICE_NAME_FOUND CHANGED_ANY=0

for SERVICE_NAME_FOUND in submission submissions; do
    # || true: grep legitimately finds nothing when this service name does
    # not exist (e.g. no "submissions" listener) - the very next line
    # already handles that empty-result case correctly. Without this, a
    # bare assignment from a failing piped command, under this project's
    # set -euo pipefail, kills the whole script with no error printed at
    # all (found live 2026-10-24 - see server-setup.sh's errtrace fix).
    SERVICE_LINE="$(grep -E "^${SERVICE_NAME_FOUND}[[:space:]]+inet" "$MASTER_CF" | head -n1 || true)"
    [[ -z "$SERVICE_LINE" ]] && continue

    if awk '{print $5}' <<< "$SERVICE_LINE" | grep -qx 'y'; then
        log "[ OK ] ${SERVICE_NAME_FOUND}/inet is already chroot=y."
    else
        log "Setting ${SERVICE_NAME_FOUND}/inet to chroot=y (was n) to match Debian's own stock default..."
        backup_file "$MASTER_CF"
        awk -v name="$SERVICE_NAME_FOUND" '
            $1 == name && $2 == "inet" && !done { $5 = "y"; done = 1 }
            { print }
        ' "$MASTER_CF" > "${MASTER_CF}.tmp" && mv "${MASTER_CF}.tmp" "$MASTER_CF"
        finalize_backup "$MASTER_CF"
        postfix check || die "postfix check failed after setting chroot=y on ${SERVICE_NAME_FOUND}/inet - restore ${MASTER_CF}.bak.* and investigate before retrying."
        CHANGED_ANY=1
        log "[ OK ] ${SERVICE_NAME_FOUND}/inet is now chroot=y."
    fi
done

if [[ -z "$(grep -E '^(submission|submissions)[[:space:]]+inet' "$MASTER_CF")" ]]; then
    err "No active 'submission'/'submissions' listener found in $MASTER_CF - nothing to harden."
    return 1
fi

if [[ "$CHANGED_ANY" -eq 1 ]]; then
    systemctl restart postfix || die "postfix restart failed after chroot-hardening the submission listener(s)."
    log "[ OK ] postfix restarted and passed 'postfix check' after the chroot change(s)."
fi

# ============================================================
# Detect Postfix's ACTUAL chroot setting for the submission service,
# live, rather than assuming it matches what we saw during development.
# ============================================================

local submission_line chroot_col
submission_line="$(grep -E '^submissions?[[:space:]]+inet' /etc/postfix/master.cf | head -n1 || true)"

if [[ -z "$submission_line" ]]; then
    err "No active 'submission'/'submissions' (587) listener found in /etc/postfix/master.cf."
    err "Expected grommunio-setup to have added one — nothing to fix SASL for."
    return 1
fi

# master.cf columns: service type private unpriv chroot wakeup maxproc command
chroot_col="$(awk '{print $5}' <<< "$submission_line")"
log "Detected submission (587) listener, chroot column: '$chroot_col'"

# ============================================================
# Determine saslauthd's actual socket directory from its own config,
# rather than hardcoding /var/run/saslauthd.
# ============================================================

local sasl_options sasl_mux_dir
sasl_options="$(grep -E '^OPTIONS=' /etc/default/saslauthd | sed -E 's/^OPTIONS="(.*)"$/\1/' || true)"
# || true: -m is optional in OPTIONS - the fallback default right below
# this already handles that case correctly.
sasl_mux_dir="$(grep -oE '\-m[[:space:]]+[^ ]+' <<< "$sasl_options" | awk '{print $2}' || true)"
sasl_mux_dir="${sasl_mux_dir:-/var/run/saslauthd}"
log "saslauthd socket directory (from /etc/default/saslauthd OPTIONS): $sasl_mux_dir"

# ============================================================
# If submission is chrooted, the socket must be bind-mounted into the
# jail — same pattern as the existing mysqld bind mount. If it is not
# chrooted (the case grommunio-setup actually built: chroot=n), nothing
# extra is needed; the socket at $sasl_mux_dir is directly reachable.
#
# ensure_saslauthd_chroot_mount compares the LIVE source directory's
# inode against the chroot target's: a bind mount binds to a specific
# directory INSTANCE, not a path, so if saslauthd ever recreates its own
# run-directory (confirmed to happen on a plain `systemctl restart
# saslauthd`, e.g. right after the self-heal above fixes a reverted
# OPTIONS/START=, and presumably on every reboot too, since /var/run is
# tmpfs), the existing mount silently starts showing the OLD, now-empty
# directory instead of the new socket - `mountpoint -q` alone can't see
# this, since the mount itself is still technically active. Called both
# here and again after the restart below, so a restart that happens
# AFTER this first call can't leave the mount stale for the rest of the
# run.
# ============================================================

ensure_saslauthd_chroot_mount()
{
    [[ "$chroot_col" == "y" ]] || { log "submission is not chrooted (chroot=$chroot_col) — no bind mount needed, saslauthd's default socket path is directly reachable."; return 0; }

    local chroot_target="/var/spool/postfix${sasl_mux_dir}"
    mkdir -p "$chroot_target"

    if mountpoint -q "$chroot_target"; then
        if [[ "$(stat -c %i "$sasl_mux_dir" 2>/dev/null)" == "$(stat -c %i "$chroot_target" 2>/dev/null)" ]]; then
            log "[ OK ] $chroot_target already mounted and matches the current $sasl_mux_dir."
            return 0
        fi
        log "$chroot_target is mounted but STALE (saslauthd recreated $sasl_mux_dir since the last mount) — remounting..."
        umount "$chroot_target"
    else
        log "submission is chrooted — bind-mounting saslauthd socket into the jail: $chroot_target"
    fi

    mount "$chroot_target"
    log "Mounted $chroot_target"
}

if [[ "$chroot_col" == "y" ]] && ! grep -qF "/var/spool/postfix${sasl_mux_dir}" /etc/fstab; then
    backup_file /etc/fstab
    echo "${sasl_mux_dir}	/var/spool/postfix${sasl_mux_dir}	bind	defaults,bind	0	0" >> /etc/fstab
    finalize_backup /etc/fstab
    log "Added fstab bind mount: $sasl_mux_dir -> /var/spool/postfix${sasl_mux_dir}"
elif [[ "$chroot_col" == "y" ]]; then
    log "fstab bind mount for /var/spool/postfix${sasl_mux_dir} already present."
fi

ensure_saslauthd_chroot_mount

# ============================================================
# Enable and start saslauthd (the actual missing piece).
# ============================================================

# Always enable: the sasl2-bin package start (postinst) can leave the service
# running but not enabled at boot, so "already active" must not skip enabling.
log "Enabling saslauthd at boot..."
systemctl enable saslauthd
if [[ "$SASLAUTHD_DEFAULT_CHANGED" -eq 1 ]] && systemctl is-active --quiet saslauthd; then
    log "Restarting saslauthd — it was already running, but with the OPTIONS/START= values just corrected above; a plain 'already active' would leave it running on the stale ones."
    systemctl restart saslauthd
elif systemctl is-active --quiet saslauthd; then
    log "saslauthd already active."
else
    log "Starting saslauthd..."
    systemctl start saslauthd
fi

# A restart (just above, or the plain 'systemctl start' on a fresh daemon)
# can recreate saslauthd's run-directory, which would silently invalidate
# the bind mount set up earlier in this same run — re-check and remount
# if needed, now that the daemon's final socket directory instance exists.
ensure_saslauthd_chroot_mount

# ============================================================
# Postfix SASL mechanisms. saslauthd verifies passwords through PAM, and PAM
# cannot do CRAM-MD5 or DIGEST-MD5. grommunio-setup writes a mech_list that
# includes them, so Postfix tries them first and logs a failure on every login.
# Both package sources write this file the same way (see SOURCE-DIFFERENCES.md).
# ============================================================

SMTPD_CONF="/etc/postfix/sasl/smtpd.conf"
if [[ -f "$SMTPD_CONF" ]] && grep -qE '^mech_list:.*(CRAM-MD5|DIGEST-MD5)' "$SMTPD_CONF"; then
    backup_file "$SMTPD_CONF"
    sed -i -E 's/^mech_list:.*/mech_list: LOGIN PLAIN/' "$SMTPD_CONF"
    finalize_backup "$SMTPD_CONF"
    log "Set SASL mechanisms to LOGIN PLAIN in $SMTPD_CONF (was CRAM-MD5/DIGEST-MD5 too)."
    systemctl reload postfix
fi
if [[ -f "$SMTPD_CONF" ]] && grep -qE '^mech_list: LOGIN PLAIN$' "$SMTPD_CONF"; then
    log "[ OK ] SASL mechanisms are LOGIN PLAIN."
else
    die "$SMTPD_CONF does not list LOGIN PLAIN only; CRAM-MD5 attempts would be logged on every login."
fi

# Aliases database: rebuild when /etc/aliases is newer, otherwise Postfix logs
# "database /etc/aliases.db is older than source file /etc/aliases" on each run.
if [[ -f /etc/aliases ]] && { [[ ! -f /etc/aliases.db ]] || [[ /etc/aliases -nt /etc/aliases.db ]]; }; then
    postalias /etc/aliases
    log "Rebuilt /etc/aliases.db from /etc/aliases."
fi

# Postfix's port 25 service runs in a chroot (/var/spool/postfix). Its MySQL
# lookups (virtual alias, BCC, domain maps) need the MariaDB socket inside that
# chroot, so /run/mysqld is bind-mounted there. Without it, every mail hitting
# those maps logs "Can't connect to local server through socket" and is
# deferred. Mount it through fstab so it comes back after a reboot.
MYSQL_SOCK_DIR="/run/mysqld"
CHROOT_MYSQL_DIR="/var/spool/postfix/run/mysqld"
if [[ -d /var/spool/postfix && -S "$MYSQL_SOCK_DIR/mysqld.sock" ]]; then
    if ! grep -qE "^${MYSQL_SOCK_DIR}[[:space:]]+${CHROOT_MYSQL_DIR}[[:space:]]" /etc/fstab; then
        backup_file /etc/fstab
        echo "${MYSQL_SOCK_DIR} ${CHROOT_MYSQL_DIR} bind defaults,bind 0 0" >> /etc/fstab
        finalize_backup /etc/fstab
        systemctl daemon-reload
        log "Added the Postfix chroot MySQL bind to /etc/fstab."
    fi
    mkdir -p "$CHROOT_MYSQL_DIR"
    mountpoint -q "$CHROOT_MYSQL_DIR" || mount "$CHROOT_MYSQL_DIR"
    if [[ -S "$CHROOT_MYSQL_DIR/mysqld.sock" ]]; then
        log "[ OK ] MySQL socket is visible inside the Postfix chroot."
    else
        die "The MySQL socket is not visible inside the Postfix chroot ($CHROOT_MYSQL_DIR). Postfix map lookups will fail."
    fi
else
    log "Postfix chroot or MariaDB socket not present yet; skipping the chroot bind."
fi

# ============================================================
# Verify
# ============================================================

sleep 1
local verify_failed=0

if systemctl is-active --quiet saslauthd; then
    log "[ OK ] saslauthd is active."
else
    err "[FAIL] saslauthd is not active."
    verify_failed=1
fi

if [[ -S "${sasl_mux_dir}/mux" ]]; then
    log "[ OK ] saslauthd socket present: ${sasl_mux_dir}/mux"
else
    err "[FAIL] saslauthd socket not found at ${sasl_mux_dir}/mux"
    verify_failed=1
fi

if [[ "$chroot_col" == "y" ]]; then
    if [[ -S "/var/spool/postfix${sasl_mux_dir}/mux" ]]; then
        log "[ OK ] saslauthd socket visible inside the postfix chroot."
    else
        err "[FAIL] saslauthd socket not visible inside the postfix chroot."
        verify_failed=1
    fi
fi

if [[ "$verify_failed" -ne 0 ]]; then
    die "saslauthd verification failed — see errors above."
fi

log "Reloading postfix so smtpd picks up a working saslauthd..."
systemctl reload postfix

echo
echo "============================================================"
echo " Done"
echo "============================================================"
echo
echo "saslauthd is active and reachable from Postfix's submission (587)"
echo "listener. SMTP AUTH should now work for real mail clients."
echo
echo "Verify with: journalctl -u postfix -f   (while a client attempts login)"
echo
}
