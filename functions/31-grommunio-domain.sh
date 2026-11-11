#!/usr/bin/env bash
#
# 31-grommunio-domain.sh
#
# Creates the mail domain in grommunio. Without a domain, step 45 cannot create
# its test mailbox and fails with "Invalid domain". Domain creation is done by
# the grommunio-admin CLI, not by the wizard, so it is a step of its own.
#
# The domain comes from step 10 (NEW_DOMAIN). It is asked for only when step 10
# has not saved one. The domain is created with 50 users and chat off, the same
# as the test install. Create more domains by hand with grommunio-admin.
#
# Same for both package sources (grommunio-admin is part of grommunio-admin-api
# in both). See SOURCE-DIFFERENCES.md.

step_grommunio_domain()
{
require_cmd grommunio-admin

# The shared admin password is asked for here, first thing after the wizard, and
# kept in memory for the rest of the run. Later steps then do not ask again.
if [[ -z "$SHARED_ADMIN_PASSWORD" ]]; then
    shared_admin_password_confirm
fi

# System-wide (not per-domain), so this applies to every domain this
# server ever gets - set unconditionally on every run, not gated to the
# first domain. Idempotent: dbconf set is a plain overwrite.
ensure_mailbox_quota_defaults

local NET_CFG="$(cfg_file 10-network-hostname)"
local DOMAIN=""
if [[ -f "$NET_CFG" ]]; then
    # shellcheck disable=SC1090
    source "$NET_CFG"
    DOMAIN="${NEW_DOMAIN:-}"
fi
if [[ -z "$DOMAIN" ]]; then
    read -r -p "Mail domain to create (e.g. example.com): " DOMAIN
fi
[[ -n "$DOMAIN" ]] || die "No mail domain given."

# Computed BEFORE creating/recovering $DOMAIN below, so this is only true
# when there were truly zero domains beforehand - on any later re-run
# (domain already exists) this is naturally 0, no separate persisted flag
# needed to avoid repeating the admin-hub scaffolding below.
local IS_FIRST_DOMAIN=0
[[ -z "$(grommunio-admin domain list 2>/dev/null)" ]] && IS_FIRST_DOMAIN=1

# The list shows "ID: name (status)". A deleted domain is still listed, so the
# status must be checked, not only the name.
domain_status()
{
    grommunio-admin domain list 2>/dev/null | sed -nE "s/^[0-9]+: ${DOMAIN//./\\.} \(([a-z]+)\).*/\1/p" | head -1
}

case "$(domain_status)" in
    active)
        log "[ OK ] Domain $DOMAIN exists and is active."
        ;;
    deleted)
        log "Domain $DOMAIN exists but is deleted. Recovering it..."
        grommunio-admin domain recover "$DOMAIN" >/dev/null 2>&1 \
            || die "grommunio-admin could not recover the domain $DOMAIN."
        [[ "$(domain_status)" == "active" ]] || die "Domain $DOMAIN is still not active after recover."
        log "[ OK ] Domain $DOMAIN recovered and active."
        ;;
    *)
        log "Creating domain $DOMAIN (50 users, chat off)..."
        grommunio-admin domain create "$DOMAIN" -u 50 --chat false >/dev/null 2>&1 \
            || die "grommunio-admin could not create the domain $DOMAIN."
        [[ "$(domain_status)" == "active" ]] || die "Domain $DOMAIN was reported created but is not active."
        log "[ OK ] Domain $DOMAIN created."
        ;;
esac

if [[ "$IS_FIRST_DOMAIN" -eq 1 ]]; then
    ensure_admin_hub_mailbox "$DOMAIN"
fi

hint_dedicated_mx_if_needed "$DOMAIN"
}

# ensure_mailbox_quota_defaults
#
# grommunio-admin's own stock defaults-system (prohibitsendquota/
# prohibitreceivequota both 150 MiB, storagequotalimit ~9.8 GiB) are
# internally inconsistent: send/receive get blocked at 150 MiB while the
# nominal "hard" limit sits at ~9.8 GiB and is never actually reached -
# found live 2026-11-05 reviewing every current default on testvps. Fixed
# to a single, consistent staircase instead: 9 GiB (send) / 9.5 GiB
# (receive) / 10 GiB (hard limit), in KB as grommunio-admin's cli/user.py
# stores them (_kByteKeys, factor 1024).
#
# Only affects users created AFTER this runs - grommunio-admin reads
# defaults-system fresh at creation time (cli/user.py's cliUserCreate),
# it is never applied retroactively to existing mailboxes.
ensure_mailbox_quota_defaults()
{
local send=9437184 receive=9961472 limit=10485760

grommunio-admin dbconf set grommunio-admin defaults-system user.properties.prohibitsendquota "$send" >/dev/null 2>&1 \
    || die "Could not set prohibitsendquota default."
grommunio-admin dbconf set grommunio-admin defaults-system user.properties.prohibitreceivequota "$receive" >/dev/null 2>&1 \
    || die "Could not set prohibitreceivequota default."
grommunio-admin dbconf set grommunio-admin defaults-system user.properties.storagequotalimit "$limit" >/dev/null 2>&1 \
    || die "Could not set storagequotalimit default."
log "[ OK ] Mailbox quota defaults: 9 GiB send / 9.5 GiB receive / 10 GiB hard limit."
}

# ensure_admin_hub_mailbox <domain>
#
# Scaffolds a single RFC 2142 role-address hub for the first domain this
# server ever gets: admin@<domain>, carrying postmaster/hostmaster/root/
# webmaster/abuse/security as aliases, and wires /etc/aliases so root's own
# system mail (cron, logwatch, etc.) actually reaches it instead of
# bouncing.
#
# Deliberately a SHARED mailbox with no password of its own, not a normal
# account - it is meant to be accessed only via a real person's own login
# (send-as + store-owner delegation), never a separately-known shared
# password. Matches the pattern already in live use on testvps before this
# was written (found 2026-10-21: an existing shared "hostmaster@" mailbox
# there, delegated the same way to a real user's own account).
#
# No real personal mailbox exists yet at this point in a fresh run (this
# step only creates the DOMAIN; mailboxes are still created by hand
# afterwards), so the delegation step itself can't be automated here -
# printed as an instruction instead.
#
# Idempotent: safe to call again (e.g. a second domain later never
# re-enters this function at all, since IS_FIRST_DOMAIN gates the call;
# but the checks inside are harmless even if it ever were called twice).
ensure_admin_hub_mailbox()
{
local domain="$1"
local hub="admin@${domain}"

if grommunio-admin user show "$hub" >/dev/null 2>&1; then
    log "[ OK ] $hub already exists - leaving it as-is."
else
    log "Creating $hub as the RFC 2142 role-address hub for $domain (shared mailbox, no password by design)..."
    grommunio-admin user create "$hub" \
        --status shared \
        --privWeb true --privDav true --privEas true \
        --alias "postmaster@${domain}" \
        --alias "hostmaster@${domain}" \
        --alias "root@${domain}" \
        --alias "webmaster@${domain}" \
        --alias "abuse@${domain}" \
        --alias "security@${domain}" \
        --no-defaults >/dev/null \
        || die "Could not create $hub."
    log "[ OK ] Created $hub with aliases: postmaster, hostmaster, root, webmaster, abuse, security."
fi

local aliases_file="/etc/aliases"
local hub_escaped="${hub//./\\.}"
if [[ -f "$aliases_file" ]] && grep -qE "^root:[[:space:]]*${hub_escaped}[[:space:]]*\$" "$aliases_file"; then
    log "[ OK ] /etc/aliases already routes root -> $hub."
else
    if [[ -f "$aliases_file" ]]; then
        backup_file "$aliases_file"
    fi
    if [[ -f "$aliases_file" ]] && grep -qE '^root:' "$aliases_file"; then
        sed -i -E "s/^root:.*/root:\t${hub}/" "$aliases_file"
    else
        printf 'root:\t%s\n' "$hub" >> "$aliases_file"
    fi
    finalize_backup "$aliases_file"
    require_cmd newaliases
    newaliases
    log "[ OK ] /etc/aliases: root -> $hub"
fi

echo
echo "============================================================"
echo " Admin hub mailbox: $hub"
echo "============================================================"
echo
echo "This is a SHARED mailbox - deliberately no password of its own."
echo "Link it to your own real mailbox once you have created one:"
echo
echo "  grommunio-admin user sendas $hub add <you>@${domain}"
echo "  grommunio-admin user storeowner $hub add <you>@${domain}"
echo
echo "Until then, mail to root/postmaster/hostmaster/webmaster/abuse/security@${domain}"
echo "(including this server's own system mail) queues in $hub, unread by"
echo "anyone."
echo
echo "------------------------------------------------------------"
echo " MFA (TOTP) goes on YOUR mailbox, never on $hub"
echo "------------------------------------------------------------"
echo
echo "$hub is shared and has no password of its own - MFA has no effect on"
echo "it (nobody ever logs into it directly). Once you have created and"
echo "linked your own real mailbox above, opt it into MFA with:"
echo
echo "  manage-mfa.sh --enable <you>@${domain}"
echo
echo "(manage-mfa.sh also has --status/--reset/--remove - see its own"
echo "--help. This is per-user opt-in, not a server-wide requirement -"
echo "see manage-mfa.sh's own header comment for why.)"
echo
}

# hint_dedicated_mx_if_needed <domain>
#
# Whether this domain's natural MX target (mail.<domain>) is ALSO this
# server's own canonical hostname - the one found via PTR by step 10,
# the one Postfix uses as myhostname/HELO, the one hostnamectl set. If
# so, that one shared name is already "spoken for" as the server's own
# identity, not this domain's alone - giving it an independent MX
# hostname (conventionally "mx1", but any name not already in use would
# do) is what actually lets this domain run its own DANE/TLSA policy
# later. If the server's own hostname is something else entirely (a
# provider-assigned rDNS string unrelated to any hosted domain, for
# example), there IS no collision: mail.<domain> is already this
# domain's own, nothing else shares it, and nothing extra is needed.
#
# Deliberately NOT gated to "the first domain": the actual trigger is
# whether THIS domain's mail.<domain> happens to equal the server's own
# hostname, which usually (but not necessarily) is the first domain -
# it depends entirely on what the PTR/A record say, not on creation
# order. Called for every domain, every time step_grommunio_domain
# creates or recovers one.
hint_dedicated_mx_if_needed()
{
local domain="$1"
local needs_dedicated_mx=0
if [[ -n "${NEW_FQDN:-}" && "$NEW_FQDN" == "mail.${domain}" ]]; then
    needs_dedicated_mx=1
fi

if [[ "$needs_dedicated_mx" -eq 1 ]]; then
    echo
    echo "------------------------------------------------------------"
    echo " mail.${domain} is this server's own hostname - give this domain its own MX"
    echo "------------------------------------------------------------"
    echo
    echo "This server's own hostname (found via PTR/reverse DNS by step 10,"
    echo "used by Postfix as myhostname/HELO, set via hostnamectl) is"
    echo "mail.${domain} - the exact name this domain would otherwise use as"
    echo "its own MX target. Since that name is the server's shared identity,"
    echo "not something exclusive to ${domain}, DANE (TLSA) can never be"
    echo "enabled for just this domain while it shares that MX name: DANE is"
    echo "keyed on the MX hostname, not the recipient domain, so it would"
    echo "silently apply to anything else that ever uses that same hostname"
    echo "too (see dns-records-reference.md, section 'First domain only: a"
    echo "dedicated mx1 MX target', for the full reasoning)."
    echo
    echo "Give ${domain} its own, otherwise-unused MX hostname instead - by"
    echo "convention mx1.${domain}, though any free name works the same way:"
    echo
    echo "  mx1.${domain}  A     <same IPv4 as mail.${domain}>"
    echo "  mx1.${domain}  AAAA  <same IPv6 as mail.${domain}>"
    echo "  @              MX    10 mx1.${domain}.   (instead of mail.${domain}.)"
    echo
    echo "Then run: manage-certs.sh --all (adds mx1.${domain} to the"
    echo "certificate) and, if DANE is wanted now, manage-dane.sh --setup."
    echo
else
    log "[ OK ] ${domain}: mail.${domain} is not this server's own hostname - no dedicated MX hostname needed, independent DANE is already possible for it if wanted."
fi
}
