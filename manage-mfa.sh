#!/usr/bin/env bash
#
# manage-mfa.sh
#
# Per-user opt-in MFA (TOTP) via Keycloak, for grommunio Web and every
# other Keycloak-SSO client (chat, files, archive). Realm-wide mandatory
# MFA is deliberately NOT what this script does: opt-in came first
# (verified live 2026-11-05 against two real mailboxes); a future
# mandatory flow would be bound separately on top of this.
#
# Does NOT touch IMAP/POP3/SMTP-AUTH/EAS logins - those are basic-auth at
# the protocol level and cannot receive an MFA challenge no matter what
# this script or Keycloak does. This only affects interactive logins that
# go through Keycloak.
#
# Shared mailboxes (e.g. the admin@<domain> hub created by step 31) have
# no password of their own and are only ever reached via a real person's
# own login (send-as/store-owner delegation) - requiring OTP on one would
# have no effect (nobody logs into it directly) and is refused by this
# script. Enroll the REAL person who manages the server instead, once
# they have their own mailbox.
#
# Three real gotchas this script handles automatically (found enrolling
# test users):
#   - Keycloak's person-name validator rejects the ENTIRE user record on
#     any update if the federated displayname/surname contains a
#     character it does not allow (parentheses, in the case found) - this
#     has nothing to do with MFA, but blocks --enable/--reset/--remove
#     all the same. This script does not guess the validator's exact
#     rules; it just attempts the change, and on this specific error
#     prints the current name fields plus the exact grommunio-admin
#     command to fix them, then exits - it does not rewrite anyone's name
#     on its own.
#   - Keycloak caches federated user attributes; a grommunio-side name
#     fix is invisible to Keycloak until the realm's user cache is
#     cleared. This script always clears it before reading or writing a
#     user, so a stale cache is never the reason a retry is needed.
#   - A user with no givenname/surname set in grommunio hits Keycloak's
#     own realm-required "Update Account Information" screen on login,
#     BEFORE the OTP step - and can never get past it: the grommunio
#     user-storage federation provider's own database grant is read-only
#     by design (confirmed in grommunio's setup-guide PDF, "SELECT access
#     to grommunio.users and grommunio.user_properties"), so nothing
#     typed into that screen can ever be saved. --enable/--reset refuse
#     up front if the name is missing, with the exact grommunio-admin
#     command to set it first - enrolling a nameless account would lock
#     it out of login entirely, not just skip MFA.
#
# Usage:
#   manage-mfa.sh                      Show this help.
#   manage-mfa.sh --status <user>      Report current MFA state for
#                                        <user> (email address). Never
#                                        changes anything.
#   manage-mfa.sh --status users       One line per realm user: OTP on/off,
#                                        enrolment pending or not.
#   manage-mfa.sh --status domains     Per grommunio domain: whether
#                                        domain-default MFA is
#                                        configured for it, and separately
#                                        whether that mechanism is bound
#                                        anywhere at all (configured but
#                                        unbound has NO live effect).
#   manage-mfa.sh --enable <user>      Opt <user> into MFA: next login
#                                        shows a TOTP QR code; every login
#                                        after that asks for the code.
#   manage-mfa.sh --reset <user>       Remove <user>'s existing TOTP
#                                        credential(s) and require fresh
#                                        enrolment on next login - for a
#                                        lost phone/authenticator, keeps
#                                        MFA itself turned on.
#   manage-mfa.sh --remove <user>      Remove <user>'s existing TOTP
#                                        credential(s) and turn MFA off
#                                        entirely - back to password-only.
#
# Requires grommunio-keycloak installed and configured (step 31 having
# run at least once is not required by this script itself, but there is
# nothing useful to enroll before then).

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/functions/00-common.sh"

KCADM="/opt/grommunio-keycloak/bin/kcadm.sh"
KC_CONFIG="/root/.keycloak/kcadm.config"
KC_SERVER="http://localhost:9080/auth"
KC_ADMIN_PW_FILE="/root/cfg-server/keycloak-admin-password.txt"
REALM="grommunio"

show_help()
{
    sed -n '3,78p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

require_cmd grommunio-admin
require_cmd python3
[[ -x "$KCADM" ]] || die "kcadm.sh not found at $KCADM - is grommunio-keycloak installed?"

# kc <kcadm args...>
#
# Runs kcadm.sh with the shared config, transparently re-logging in once
# if the saved admin session has expired (found to happen periodically -
# not specific to this script) and retrying exactly once. Any other
# failure is passed through as-is.
# Always writes combined stdout+stderr to stdout and returns the real
# exit code - so a caller capturing `out="$(kc ...)"` sees the error text
# (e.g. error-person-name-invalid-character) regardless of success or
# failure, instead of it disappearing onto a stream nobody captured.
kc()
{
    local out rc=0
    out="$("$KCADM" "$@" --config "$KC_CONFIG" 2>&1)" || rc=$?
    if [[ "$rc" -ne 0 ]] && grep -qE 'Session has expired|not logged in' <<< "$out"; then
        [[ -f "$KC_ADMIN_PW_FILE" ]] || die "Keycloak session expired and $KC_ADMIN_PW_FILE does not exist - cannot re-login automatically."
        "$KCADM" config credentials --server "$KC_SERVER" --realm master --user admin \
            --password "$(cat "$KC_ADMIN_PW_FILE")" --config "$KC_CONFIG" >/dev/null \
            || die "Could not re-login to Keycloak with the saved admin password."
        rc=0
        out="$("$KCADM" "$@" --config "$KC_CONFIG" 2>&1)" || rc=$?
    fi
    [[ -n "$out" ]] && printf '%s\n' "$out"
    return "$rc"
}

# kc_user_id <email>
#
# kcadm's own -q email=... filter was found unreliable (returned every
# user, not just the match) while enrolling the first test user - so this
# filters client-side instead, on the realm's full user list.
kc_user_id()
{
    local email="$1" id
    id="$(kc get users -r "$REALM" --fields id,email | python3 -c '
import json, sys
email = sys.argv[1].lower()
for u in json.load(sys.stdin):
    if u.get("email", "").lower() == email:
        print(u["id"])
        break
' "$email")"
    [[ -n "$id" ]] || die "No Keycloak user found for email ${email} in realm ${REALM}."
    echo "$id"
}

# refuse_if_shared <user>
#
# Shared mailboxes (addressStatus: shared) have no password of their own
# - requiring OTP on one has no effect, since nobody ever logs into it
# directly.
refuse_if_shared()
{
    local user="$1"
    # Format is "addressStatus: <n> (<domainStatus>|<status>)" - the user's
    # OWN status (where "shared" lives) is the SECOND value, after the
    # pipe, not the first - confirmed from the admin-api's own cli/user.py
    # (_mkStatus(cli, user.domainStatus) then _mkStatus(cli, user.status)).
    # A grep matching right after the opening paren was found live to miss
    # every real shared mailbox and silently allow --enable on one.
    if grommunio-admin user show "$user" 2>/dev/null | grep -qE '^\s*addressStatus:\s*[0-9]+\s*\([^|]*\|shared\)'; then
        die "${user} is a shared mailbox (no password of its own) - MFA has no effect on it. Enroll the real person who manages the server instead, once they have their own mailbox."
    fi
}

# refuse_if_nameless <user>
#
# Keycloak's realm requires firstName/lastName/email on every user
# (realm User Profile config) and shows its own "Update Account
# Information" screen on login whenever any are missing - BEFORE the OTP
# step, so a nameless account enrolled into MFA would hit this screen on
# every login. That screen cannot be filled in and saved: the grommunio
# user-storage federation provider connects to the grommunio database
# with a READ-ONLY grant (confirmed in grommunio's own setup-guide PDF,
# "SELECT access to grommunio.users and grommunio.user_properties" - by
# design, not a bug here or in Keycloak). A nameless account is
# therefore stuck at that screen permanently once required to log in via
# Keycloak - give(n)name/surname must be set in grommunio BEFORE
# enrolling, never afterward through the login page itself.
refuse_if_nameless()
{
    local user="$1" show
    show="$(grommunio-admin user show "$user" 2>/dev/null)"
    if ! grep -qE '^\s*givenname:' <<< "$show" || ! grep -qE '^\s*surname:' <<< "$show"; then
        die "${user} has no givenname/surname set in grommunio - Keycloak would show its \"Update Account Information\" screen on next login, which cannot be saved (the federation provider's DB grant is read-only by design). Set a name FIRST: grommunio-admin user modify ${user} --property givenname='<First>' --property surname='<Last>' --property displayname='<First Last>' - then run this command again."
    fi
}

print_name_fix_hint()
{
    local user="$1"
    echo
    echo "Keycloak rejected the update: error-person-name-invalid-character."
    echo "This happens on ANY update to this user while its federated name"
    echo "contains a character Keycloak's own validator disallows (parentheses,"
    echo "the one case found so far) - unrelated to MFA itself. Current values:"
    echo
    grommunio-admin user show "$user" 2>/dev/null | grep -E 'displayname|givenname|surname' | sed 's/^/  /'
    echo
    echo "Fix with, for example:"
    echo "  grommunio-admin user modify ${user} --property surname='<value without the character>'"
    echo "  grommunio-admin user modify ${user} --property displayname='<value without the character>'"
    echo
    echo "Then run: $(basename "${BASH_SOURCE[0]}") --enable ${user}  (clears the cache and retries)."
}

# otp_credential_ids <keycloak user id>
otp_credential_ids()
{
    local uid="$1"
    kc get "users/${uid}/credentials" -r "$REALM" \
        | python3 -c '
import json, sys
for c in json.load(sys.stdin):
    if c.get("type") == "otp":
        print(c["id"])
'
}

clear_cache()
{
    kc create "realms/${REALM}/clear-user-cache" -r "$REALM" >/dev/null
}

# cmd_status_users: every realm user, one line each, sorted by domain
# then local part (grommunio's own federated username IS the email
# address, so a plain sort already groups by domain).
cmd_status_users()
{
    echo
    echo "=== MFA status for every user ==="
    echo
    kc get users -r "$REALM" -q max=1000 --fields username,totp,requiredActions \
        | python3 -c '
import json, sys
users = json.load(sys.stdin)
for u in sorted(users, key=lambda u: u.get("username", "")):
    totp = "on " if u.get("totp") else "off"
    pending = "pending" if "CONFIGURE_TOTP" in u.get("requiredActions", []) else ""
    print("  %-40s otp=%s %s" % (u.get("username", "?"), totp, pending))
'
}

# cmd_status_domains: for every grommunio domain, whether domain-default
# MFA (the regex-conditioned sub-flow) is configured for it, and
# separately whether that mechanism is actually bound anywhere at all.
# Configured but unbound is a real, distinct state this setup has sat in
# since 2026-11-05 - never silently reported as "on" just because a regex
# happens to mention the domain.
cmd_status_domains()
{
    echo
    echo "=== Domain-default MFA status ==="
    echo

    local flow_bound="no" realm_flow gw_override
    realm_flow="$(kc get "realms/${REALM}" -r "$REALM" --fields browserFlow | python3 -c 'import json,sys; print(json.load(sys.stdin).get("browserFlow",""))' 2>/dev/null || true)"
    if [[ "$realm_flow" == "browser-domain-mfa" ]]; then
        flow_bound="yes (realm-wide)"
    else
        local gw_id
        gw_id="$(kc get clients -r "$REALM" -q clientId=grommunio-web --fields id | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(d[0]["id"] if d else "")
' 2>/dev/null || true)"
        if [[ -n "$gw_id" ]]; then
            gw_override="$(kc get "clients/${gw_id}" -r "$REALM" --fields authenticationFlowBindingOverrides | python3 -c '
import json, sys
print(json.load(sys.stdin).get("authenticationFlowBindingOverrides", {}).get("browser", ""))
' 2>/dev/null || true)"
            [[ -n "$gw_override" ]] && flow_bound="yes (grommunio-web client only)"
        fi
    fi
    echo "Domain-default flow bound: ${flow_bound}"
    [[ "$flow_bound" == "no" ]] && echo "(configured below has NO live effect until bound - normal login uses the unmodified realm default)"
    echo

    local domains cond_execs configured_domains=""
    domains="$(grommunio-admin domain list 2>/dev/null | grep -oE '^[0-9]+: [^ ]+' | awk '{print $2}')"

    if cond_execs="$(kc get 'authentication/flows/browser-domain-mfa%20Domain%20MFA%20Default/executions' -r "$REALM" 2>/dev/null)"; then
        local config_id
        config_id="$(python3 -c '
import json, sys
for e in json.load(sys.stdin):
    if e.get("providerId") == "conditional-user-attribute":
        print(e.get("authenticationConfig", ""))
        break
' <<< "$cond_execs")"
        if [[ -n "$config_id" ]]; then
            local regex_value
            regex_value="$(kc get "authentication/config/${config_id}" -r "$REALM" | python3 -c '
import json, sys
print(json.load(sys.stdin).get("config", {}).get("attribute_expected_value", ""))
')"
            echo "Configured pattern: ${regex_value:-<none>}"
            echo
            # Compare against the regex with backslashes stripped (the
            # pattern escapes dots as "\." - a literal substring match
            # against the plain domain name, which has no backslashes,
            # would otherwise never match and silently report every
            # domain as "off". Found live testing this very command.
            local regex_plain="${regex_value//\\/}"
            for d in $domains; do
                if [[ -n "$regex_plain" ]] && grep -qF "$d" <<< "$regex_plain"; then
                    printf "  %-30s default: on (in pattern)\n" "$d"
                else
                    printf "  %-30s default: off\n" "$d"
                fi
            done
            return
        fi
    fi

    echo "No domain-default condition configured yet."
    for d in $domains; do
        printf "  %-30s default: off (not configured)\n" "$d"
    done
}

cmd_status()
{
    local user="$1" uid
    uid="$(kc_user_id "$user")"
    echo
    echo "=== MFA status for ${user} ==="
    echo
    kc get "users/${uid}" -r "$REALM" --fields username,totp,requiredActions
    local creds
    creds="$(kc get "users/${uid}/credentials" -r "$REALM" | python3 -c '
import json, sys
for c in json.load(sys.stdin):
    if c.get("type") == "otp":
        print("  %s  label=%s  created=%s" % (c["id"], c.get("userLabel", "-"), c.get("createdDate", "-")))
')"
    if [[ -n "$creds" ]]; then
        echo "OTP credentials:"
        echo "$creds"
    else
        echo "OTP credentials: (none)"
    fi
}

cmd_enable()
{
    local user="$1" uid out
    refuse_if_shared "$user"
    refuse_if_nameless "$user"
    uid="$(kc_user_id "$user")"
    clear_cache
    if ! out="$(kc update "users/${uid}" -r "$REALM" -s 'requiredActions=["CONFIGURE_TOTP"]')"; then
        if grep -q '^error-person-name-invalid-character$' <<< "$out"; then
            print_name_fix_hint "$user"
        else
            printf '%s\n' "$out" >&2
        fi
        exit 1
    fi
    log "[ OK ] ${user} must configure OTP on next login. Log out completely and open the web login again - after the password, Keycloak shows a QR code."
}

cmd_reset()
{
    local user="$1" uid ids id out
    refuse_if_shared "$user"
    refuse_if_nameless "$user"
    uid="$(kc_user_id "$user")"
    clear_cache
    ids="$(otp_credential_ids "$uid")"
    if [[ -z "$ids" ]]; then
        log "[INFO] ${user} has no OTP credential to reset."
    else
        while read -r id; do
            [[ -n "$id" ]] || continue
            kc delete "users/${uid}/credentials/${id}" -r "$REALM" >/dev/null
            log "[ OK ] Removed OTP credential ${id}."
        done <<< "$ids"
    fi
    if ! out="$(kc update "users/${uid}" -r "$REALM" -s 'requiredActions=["CONFIGURE_TOTP"]')"; then
        if grep -q '^error-person-name-invalid-character$' <<< "$out"; then
            print_name_fix_hint "$user"
        else
            printf '%s\n' "$out" >&2
        fi
        exit 1
    fi
    log "[ OK ] ${user} must configure OTP again on next login (old credential removed, MFA stays required)."
}

cmd_remove()
{
    local user="$1" uid ids id out
    uid="$(kc_user_id "$user")"
    clear_cache
    ids="$(otp_credential_ids "$uid")"
    if [[ -z "$ids" ]]; then
        log "[INFO] ${user} has no OTP credential to remove."
    else
        while read -r id; do
            [[ -n "$id" ]] || continue
            kc delete "users/${uid}/credentials/${id}" -r "$REALM" >/dev/null
            log "[ OK ] Removed OTP credential ${id}."
        done <<< "$ids"
    fi
    if ! out="$(kc update "users/${uid}" -r "$REALM" -s 'requiredActions=[]')"; then
        if grep -q '^error-person-name-invalid-character$' <<< "$out"; then
            print_name_fix_hint "$user"
        else
            printf '%s\n' "$out" >&2
        fi
        exit 1
    fi
    log "[ OK ] MFA turned off for ${user} - back to password-only login."
}

case "${1:-}" in
    --status)
        [[ -n "${2:-}" ]] || die "Usage: $(basename "${BASH_SOURCE[0]}") --status <user>|users|domains"
        case "$2" in
            users)   cmd_status_users ;;
            domains) cmd_status_domains ;;
            *)       cmd_status "$2" ;;
        esac
        ;;
    --enable)
        [[ -n "${2:-}" ]] || die "Usage: $(basename "${BASH_SOURCE[0]}") --enable <user>"
        cmd_enable "$2"
        ;;
    --reset)
        [[ -n "${2:-}" ]] || die "Usage: $(basename "${BASH_SOURCE[0]}") --reset <user>"
        cmd_reset "$2"
        ;;
    --remove)
        [[ -n "${2:-}" ]] || die "Usage: $(basename "${BASH_SOURCE[0]}") --remove <user>"
        cmd_remove "$2"
        ;;
    *)
        show_help
        ;;
esac
