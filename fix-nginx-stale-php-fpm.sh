#!/usr/bin/env bash
#
# fix-nginx-stale-php-fpm.sh
#
# Installed as an apt DPkg::Post-Invoke hook (see
# /etc/apt/apt.conf.d/99-grommunio-nginx-phpfpm-fix) - runs after EVERY
# dpkg invocation within every apt transaction, on this server, forever.
#
# Found live 2026-11-21: a routine `apt upgrade` restarted php8.4-fpm
# (its own package was upgraded) and upgraded grommunio-web. Both
# happened within the same transaction, a few seconds apart.
# grommunio-web's own postinst only does `systemctl reload nginx` -
# its own comment says plainly that reloading is not enough for
# php-fpm, but it reloads nginx anyway, and nothing in the transaction
# then ALSO restarts nginx again after php-fpm comes back up. nginx
# never crashed or even logged an error - its workers just kept
# reusing stale keepalive connections to php-fpm's now-replaced unix
# socket. The result: webmail was broken (502-type failures through
# the live site) until the operator noticed and ran a manual full
# `systemctl restart nginx` - a reload never clears this, only a full
# restart does.
#
# Rather than hardcoding "restart nginx whenever package X or Y was
# touched" (fragile - dpkg does not guarantee trigger-processing order
# between independently-interested packages, and a future package
# could cause the exact same symptom through some other path), this
# checks the ACTUAL, REAL symptom directly: can nginx still serve a
# page through php-fpm at all? If yes, there is nothing to fix and
# this exits immediately, cheap enough to run after every single apt
# operation on the whole server. If no, do the one thing a reload
# cannot do: a full restart.
#
# Must be fast and silent when there is nothing to fix, and must never
# exit non-zero - a failure here must never fail or block an unrelated
# apt transaction (the hook registration also wraps this in "|| true"
# as a second layer of the same guarantee).

set -uo pipefail

systemctl is-active --quiet nginx || exit 0
systemctl is-active --quiet php8.4-fpm || exit 0

FQDN="$(hostname -f 2>/dev/null)"
[[ -n "$FQDN" ]] || exit 0

code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
    -H "Host: ${FQDN}" "https://127.0.0.1/web/" -k 2>/dev/null)"

# 200/30x are all fine (a redirect still means nginx+php-fpm answered);
# anything else (502/504/000/empty) means the upstream is not actually
# reachable despite both services showing "active".
[[ "$code" =~ ^(200|301|302|303)$ ]] && exit 0

systemctl restart nginx 2>/dev/null
logger -t fix-nginx-stale-php-fpm "nginx's php-fpm upstream was not responding (http '${code}') after an apt run - did a full restart (a reload alone does not clear a stale php-fpm socket connection, see docs/bugreports/ for the full story)"

exit 0
