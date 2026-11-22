#!/usr/bin/env bash
#
# 42-grommunio-spam-ham-run.sh
#
# Deploys /usr/sbin/grommunio-spam-run and /usr/sbin/grommunio-ham-run
# (plus their systemd .service/.timer units) - the two scripts that
# automatically learn a user's Junk folder as spam (daily) and their
# TRAIN-HAM folder as ham (see 38-antispam.sh for the 4h interval
# override and the HAMRUN_FOLDER setting). This server runs plain
# upstream rspamd, not grommunio's own grommunio-antispam package -
# that package is what would normally ship these two scripts, so
# without this step they don't exist at all.
#
# Real bug found and fixed here, 2026-11-22: the upstream
# grommunio-antispam 4.1.5 source (our own rebuild tree,
# /srv/build/sources/rebuild/grommunio-antispam/) has an actual bug in
# both scripts. MYSQL_HOST is extracted from mysql_adaptor.cfg with a
# sed pattern that prepends "-h" (meant for command-line use), but the
# extracted value is then written straight into a generated MySQL
# [client] options file as "host=-hlocalhost" - not a valid hostname.
# Confirmed live: "ERROR 2005 (HY000): Unknown server host
# '-hlocalhost'". This silently broke spam/ham learning completely -
# confirmed zero successful learns ever, despite thousands of
# eligible messages already sitting in Junk folders across mailboxes.
# Fixed by removing the "-h" prefix from the sed pattern (the value is
# never used as a bare CLI flag anywhere in either script, only in
# this options-file context) - the two files here differ from the
# upstream source by exactly that one line each.
#
# Deliberately does NOT touch /etc/gromox/mysql_adaptor.cfg (shared by
# several gromox daemons - left alone, by the operator's own choice)
# and does NOT duplicate 38-antispam.sh's own handling of
# /etc/gromox/spamrun.cfg's HAMRUN_FOLDER key - this step only
# installs the two corrected scripts and their systemd units.
#
# Verify after a change: `/usr/sbin/grommunio-spam-run` (or
# `-ham-run`) by hand should no longer log "MySQL-Connection couldn't
# be established" - journalctl -t grommunio-spam-run/-ham-run.

step_grommunio_spam_ham_run()
{
require_root
require_cmd systemctl

local changed=0
local -A SPAM_HAM_FILES=(
    [grommunio-spam-run]="/usr/sbin/grommunio-spam-run:0755"
    [grommunio-ham-run]="/usr/sbin/grommunio-ham-run:0755"
    [grommunio-spam-run.service]="/usr/lib/systemd/system/grommunio-spam-run.service:0644"
    [grommunio-spam-run.timer]="/usr/lib/systemd/system/grommunio-spam-run.timer:0644"
    [grommunio-ham-run.service]="/usr/lib/systemd/system/grommunio-ham-run.service:0644"
    [grommunio-ham-run.timer]="/usr/lib/systemd/system/grommunio-ham-run.timer:0644"
)

local src dest mode
for src in "${!SPAM_HAM_FILES[@]}"; do
    dest="${SPAM_HAM_FILES[$src]%%:*}"
    mode="${SPAM_HAM_FILES[$src]##*:}"
    if ! cmp -s "${SCRIPT_DIR}/${src}" "$dest" 2>/dev/null; then
        [[ -f "$dest" ]] && backup_file "$dest"
        install -m "$mode" "${SCRIPT_DIR}/${src}" "$dest" \
            || die "Could not install $dest."
        finalize_backup "$dest"
        changed=1
        log "[ OK ] Wrote $dest."
    else
        log "[ OK ] $dest already correct."
    fi
done

if [[ "$changed" -eq 1 ]]; then
    systemctl daemon-reload
fi

systemctl enable --now grommunio-spam-run.timer grommunio-ham-run.timer \
    || die "Could not enable grommunio-spam-run.timer/grommunio-ham-run.timer."
log "[ OK ] grommunio-spam-run.timer and grommunio-ham-run.timer enabled."

# Verify the real bug is actually fixed - run grommunio-spam-run once
# by hand and confirm it no longer fails with a MySQL connection
# error (the exact symptom of the "-hlocalhost" bug).
local probe_out
probe_out="$(/usr/sbin/grommunio-spam-run 2>&1)"
if grep -q "MySQL-Connection couldn't be established" <<< "$probe_out"; then
    die "grommunio-spam-run still fails to connect to MySQL after the fix - check mysql_adaptor.cfg by hand. Output: $probe_out"
fi
log "[ OK ] grommunio-spam-run ran without a MySQL connection error."
}
