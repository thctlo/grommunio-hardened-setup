#!/usr/bin/env bash
#
# ensure-train-ham-folders.sh
#
# Ensures the TRAIN-HAM folder (see 38-antispam.sh - HAMRUN_FOLDER in
# /etc/gromox/spamrun.cfg, learned as ham every 30 min by
# grommunio-ham-run.timer) exists for every active mail user. Existing
# folders are never touched or recreated.
#
# Why this exists: grommunio-admin has no hook that creates this folder
# automatically when a new user is added - 38-antispam.sh's own
# folder-creation loop only ever ran once, for whichever users existed at
# that moment. Found 2026-10-28: NOT ONE of the 19 active users on this
# fresh testvps had the folder, because they were all created (or
# bulk-restored) after that step last ran. This script is the permanent
# fix: re-run by hand any time (e.g. right after creating a user), and via
# ensure-train-ham-folders.timer (runs daily - user creation is rare
# enough that this doesn't need to be more frequent).
#
# Scope: every active user in every active domain (not limited to
# RSPAMD_DKIM_DOMAINS, unlike 38-antispam.sh's own DKIM-signing loop -
# every mailbox benefits from ham training regardless of whether its
# domain is in the DKIM-signing list).

set -euo pipefail

HAM_FOLDER="TRAIN-HAM"
PROGNAME="$(basename "$0")"

usage() {
    cat <<USAGE
Usage: $PROGNAME [--all | -user <email>]

  --all            Check/create the $HAM_FOLDER folder for every active user.
  -user <email>    Check/create it for just one user.

No arguments: show this help.
USAGE
}

ensure_folder() {
    local u="$1"
    if grommunio-admin exmdb "$u" folder list 2>/dev/null | grep -q "$HAM_FOLDER ("; then
        echo "[ OK ] $u: $HAM_FOLDER already present."
    else
        grommunio-admin exmdb "$u" folder create "$HAM_FOLDER" 0x9 \
            --comment "Move mail here that is not spam; learned as ham every 30 minutes" >/dev/null \
            || { echo "[FAIL] $u: could not create $HAM_FOLDER." >&2; return 1; }
        echo "[ OK ] $u: created $HAM_FOLDER."
    fi
}

case "${1:-}" in
    --all)
        mapfile -t users < <(grommunio-admin user query 2>/dev/null | awk '$2 ~ /@/ && $3 ~ /^0\/active/ {print $2}')
        if [[ ${#users[@]} -eq 0 ]]; then
            echo "No active users found." >&2
            exit 1
        fi
        failed=0
        for u in "${users[@]}"; do
            ensure_folder "$u" || failed=1
        done
        exit "$failed"
        ;;
    -user)
        [[ -n "${2:-}" ]] || { usage; exit 1; }
        ensure_folder "$2"
        ;;
    *)
        usage
        ;;
esac
