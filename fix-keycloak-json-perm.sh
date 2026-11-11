#!/usr/bin/env bash
#
# fix-keycloak-json-perm.sh
#
# Installed as an apt DPkg::Post-Invoke hook (see
# /etc/apt/apt.conf.d/99-grommunio-keycloak-json-fix) - runs after EVERY
# dpkg invocation within every apt transaction, on this server, forever.
# Not scoped to any one package on purpose: the real bug this works
# around lives in grommunio-auth's own setup-gk-app-g-web, whose `cp -va`
# preserves the source file's own mode (600, from the umask the writer
# script used) instead of the `umask 0027` wrapped around that same `cp`
# line - so the copy silently ends up 600 instead of 640. The dpkg
# trigger that re-runs that script fires from grommunio-auth,
# grommunio-pkg-bits, grommunio-chat-v10, grommunio-files,
# grommunio-archive, or grommunio-admin-api/-web being
# installed or upgraded - any one of those, now or in the future, can
# silently reset /etc/gromox/keycloak.json to mode 600 and break SSO
# with zero error anywhere (found live repeatedly on one server before
# this hook was added).
#
# A fix scoped to a single package's own postinst/trigger handling
# cannot GUARANTEE it runs after grommunio-auth's own trigger within the
# same apt transaction - dpkg does not guarantee trigger-processing
# order between independently-interested packages. Post-Invoke is the
# one hook apt guarantees runs after a transaction's dpkg run has fully
# finished, including all trigger processing - so this is deliberately
# NOT "a fix in one package", it is a server-level safety net.
#
# Must be fast and silent when there is nothing to fix: this runs on
# EVERY apt operation on the whole server, not just grommunio-related
# ones. Never exits non-zero - a failure here must never fail or block
# an unrelated apt transaction (the hook registration also wraps this in
# "|| true" as a second layer of the same guarantee).

set -uo pipefail

FILE="/etc/gromox/keycloak.json"
WANT_OWNER="root:groweb"
WANT_MODE="640"

[[ -f "$FILE" ]] || exit 0

actual_owner="$(stat -c '%U:%G' "$FILE" 2>/dev/null)" || exit 0
actual_mode="$(stat -c '%a' "$FILE" 2>/dev/null)" || exit 0

[[ "$actual_owner" == "$WANT_OWNER" && "$actual_mode" == "$WANT_MODE" ]] && exit 0

chown "$WANT_OWNER" "$FILE" 2>/dev/null
chmod "$WANT_MODE" "$FILE" 2>/dev/null
logger -t fix-keycloak-json-perm "Corrected $FILE from $actual_owner $actual_mode to $WANT_OWNER $WANT_MODE (grommunio-auth's setup-gk-app-g-web regressed it again - see docs/bugreports/grommunio-auth-keycloak-json-cp-a-ignores-umask.md)"

exit 0
