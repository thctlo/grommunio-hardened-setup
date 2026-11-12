#!/usr/bin/env bash
#
# 34-postfix-tls.sh
#
# grommunio-setup sets postfix's STARTTLS certificate to the Let's Encrypt
# bundle and key (postconf -e in its setup step, SSL_BUNDLE_T/SSL_KEY_T). On
# testvps that did not happen: postfix offered /etc/ssl/certs/ssl-cert-snakeoil.pem,
# a self-signed certificate, so SMTP clients saw an untrusted certificate
# (found 2026-10-05). This step checks the two settings, sets them when they
# differ, checks the configuration, reloads postfix and verifies that the
# certificate postfix really offers is the Let's Encrypt one.
#
# The bundle is a symlink to /etc/letsencrypt/live/<FQDN>/fullchain.pem, so
# renewals are picked up without copying. postfix reads these files outside
# its chroot, the same way it reads the snakeoil files.
#
# Needs: the grommunio-setup step (30) and the nginx step (33) have run, so the
# Let's Encrypt certificate and /etc/grommunio-common/ssl/ exist.
#
# Also installs/configures outbound MTA-STS enforcement (postfix as an SMTP
# CLIENT, via postfix-mta-sts-resolver) - see the dedicated comment block
# further down for why that is a separate concern from everything above it
# (which is postfix as an SMTP SERVER).

POSTFIX_TLS_CERT="/etc/grommunio-common/ssl/server-bundle.pem"
POSTFIX_TLS_KEY="/etc/grommunio-common/ssl/server.key"

step_postfix_tls()
{
require_cmd postconf
require_cmd openssl

# ============================================================
# Keep server.key in sync with Let's Encrypt, and make sure it stays that
# way on every future renewal
#
# REAL BUG FOUND 2026-10-25: grommunio-setup's own ssl_setup symlinks the
# cert bundle (server-bundle.pem -> .../fullchain.pem, always current) but
# COPIES the private key (cp -f .../privkey.pem server.key) instead of
# symlinking it - and nothing refreshes that copy again afterward: not
# grommunio's own deploy-hook (it only restarts services, confirmed by
# reading its source), not the plain certbot.timer/.service this box uses
# (stock package units, no extra logic). Every future key rotation - any
# `certbot renew`, or an --expand reissue like this project's own
# manage-certs.sh - leaves the copy stale, breaking nginx/postfix/
# gromox-http/imap/pop3 (a straight key/cert mismatch) all at once, since
# they all read this same file.
#
# A symlink (matching the bundle's own pattern) was tried live first and
# itself broke gromox-http/imap/pop3: they run as a non-root user (gromox,
# uid 983) and cannot read Let's Encrypt's own privkey.pem (root:root,
# 0600) directly - the copy exists specifically to give them their own,
# separately-owned readable copy. So this has to stay a copy, kept fresh
# by comparing content on every run of this step, not a symlink.
# ============================================================

if [[ -L "$POSTFIX_TLS_CERT" ]]; then
    local LE_LIVE_DIR LE_PRIVKEY
    # One level only (plain readlink, not -f): server-bundle.pem points
    # directly at .../live/<cert-name>/fullchain.pem, which itself is a
    # second symlink into .../archive/<cert-name>/fullchainN.pem - fully
    # resolving with -f lands in the archive dir instead, where the key is
    # named privkeyN.pem (versioned), not privkey.pem - found live
    # 2026-10-25: this silently skipped the whole sync check.
    LE_LIVE_DIR="$(dirname "$(readlink "$POSTFIX_TLS_CERT")")"
    LE_PRIVKEY="${LE_LIVE_DIR}/privkey.pem"
    if [[ -f "$LE_PRIVKEY" && -e "$POSTFIX_TLS_KEY" ]]; then
        if ! cmp -s "$LE_PRIVKEY" "$POSTFIX_TLS_KEY"; then
            cp -f "$LE_PRIVKEY" "$POSTFIX_TLS_KEY"
            chown gromox:gromox "$POSTFIX_TLS_KEY"
            chmod 600 "$POSTFIX_TLS_KEY"
            log "[ OK ] Refreshed $POSTFIX_TLS_KEY from $LE_PRIVKEY (was stale)."
            systemctl restart gromox-http gromox-imap gromox-pop3 \
                || die "gromox-http/imap/pop3 failed to restart after refreshing $POSTFIX_TLS_KEY."
            log "[ OK ] gromox-http/imap/pop3 restarted with the refreshed key."
            # nginx caches its loaded cert/key in memory at reload time, same
            # as postfix/gromox - without this it keeps serving the stale
            # pair indefinitely. grommunio-setup's own certbot-deploy-hook
            # config (/etc/grommunio-common/grommunio-certbot-deploy-hook.conf,
            # its own hardcoded template - confirmed by reading
            # common/ssl_setup in the package) never lists nginx in
            # systemd_restart/systemd_reload at all - a real, separate gap
            # from the stale-key-copy issue, found live 2026-10-26. Reloaded
            # here (not added to grommunio's own config file, which
            # grommunio-setup can overwrite on a future run) and in the
            # deploy-hook below, so this is never missed either way.
            systemctl reload nginx || die "nginx did not reload after refreshing $POSTFIX_TLS_KEY."
            log "[ OK ] nginx reloaded with the refreshed key."
        else
            log "[ OK ] $POSTFIX_TLS_KEY already matches the current Let's Encrypt key."
        fi
    fi
fi

# Make sure every FUTURE renewal keeps this in sync too, not just this run.
local HOOK_FILE="/etc/letsencrypt/renewal-hooks/deploy/70-sync-ssl-key"
if [[ -d "$(dirname "$HOOK_FILE")" ]]; then
    local HOOK_NEW
    HOOK_NEW="$(mktemp)"
    cat > "$HOOK_NEW" <<'HOOK'
#!/usr/bin/env bash
#
# 70-sync-ssl-key (managed by 34-postfix-tls.sh)
#
# Certbot deploy-hook: keeps /etc/grommunio-common/ssl/server.key in sync
# with the renewed Let's Encrypt private key, and reloads nginx. See
# 34-postfix-tls.sh for why both are needed:
#   - grommunio-setup's own ssl_setup copies this key once and never
#     refreshes it.
#   - grommunio-setup's own certbot-deploy-hook config
#     (grommunio-certbot-deploy-hook.conf, its own hardcoded template) never
#     lists nginx in systemd_restart/systemd_reload at all - confirmed by
#     reading common/ssl_setup in the package - so without this, nginx would
#     keep serving the pre-renewal certificate indefinitely. Reloading it
#     here rather than editing that package-owned config file, which
#     grommunio-setup can overwrite on a future run.
# Runs before 80-grommunio-certbot-deploy-hook (which restarts postfix and
# the gromox services) so everything restarts/reloads with an
# already-correct key. $RENEWED_LINEAGE is set by certbot to the
# live/<cert-name> directory of whichever certificate was just
# renewed/issued.

set -euo pipefail

TARGET="/etc/grommunio-common/ssl/server.key"
SOURCE="${RENEWED_LINEAGE:-}/privkey.pem"

[[ -n "${RENEWED_LINEAGE:-}" && -f "$SOURCE" ]] || exit 0
[[ -e "$TARGET" ]] || exit 0

if ! cmp -s "$SOURCE" "$TARGET"; then
    cp -f "$SOURCE" "$TARGET"
    chown gromox:gromox "$TARGET"
    chmod 600 "$TARGET"
fi
systemctl reload nginx || true
HOOK
    if ! cmp -s "$HOOK_NEW" "$HOOK_FILE" 2>/dev/null; then
        backup_file "$HOOK_FILE"
        install -m 0755 "$HOOK_NEW" "$HOOK_FILE"
        finalize_backup "$HOOK_FILE"
        log "[ OK ] Wrote $HOOK_FILE (keeps server.key in sync on every future renewal)."
    else
        log "[ OK ] $HOOK_FILE already up to date."
    fi
    rm -f "$HOOK_NEW"
fi

local CUR_CERT CUR_KEY
CUR_CERT="$(postconf -h smtpd_tls_cert_file)"
CUR_KEY="$(postconf -h smtpd_tls_key_file)"

if [[ ! -e "$POSTFIX_TLS_CERT" || ! -e "$POSTFIX_TLS_KEY" ]]; then
    err "$POSTFIX_TLS_CERT or $POSTFIX_TLS_KEY is missing; run the Let's Encrypt step first."
    return 1
fi

if [[ "$CUR_CERT" == "$POSTFIX_TLS_CERT" && "$CUR_KEY" == "$POSTFIX_TLS_KEY" ]]; then
    log "postfix already uses the grommunio TLS bundle and key."
else
    log "postfix used '$CUR_CERT' / '$CUR_KEY'; setting the grommunio bundle and key."
    backup_file /etc/postfix/main.cf
    postconf -e "smtpd_tls_cert_file=${POSTFIX_TLS_CERT}" "smtpd_tls_key_file=${POSTFIX_TLS_KEY}"
    finalize_backup /etc/postfix/main.cf
fi

if ! postfix check >/dev/null 2>&1; then
    err "postfix check failed after the TLS change; see 'postfix check'."
    return 1
fi
systemctl reload postfix || { err "postfix reload failed."; return 1; }

# Verify what postfix actually offers, not just what main.cf says.
local OFFERED
OFFERED="$(echo | timeout 8 openssl s_client -starttls smtp -connect 127.0.0.1:25 2>/dev/null \
    | openssl x509 -noout -subject -issuer 2>/dev/null)"
if [[ -z "$OFFERED" ]]; then
    err "postfix did not answer STARTTLS on 127.0.0.1:25."
    return 1
fi
if echo "$OFFERED" | grep -q "Let's Encrypt"; then
    log "postfix offers the Let's Encrypt certificate: $(echo "$OFFERED" | tr '\n' ' ')"
else
    err "postfix still offers a certificate that is not from Let's Encrypt: $(echo "$OFFERED" | tr '\n' ' ')"
    return 1
fi

# ============================================================
# Harden postfix's own TLS protocol/cipher policy, to match nginx and
# gromox-imap/pop3 (both already TLS1.2+-only, no CBC - confirmed A+ via a
# live testssl.sh scan 2026-10-26). Postfix's own defaults
# (smtpd_tls_protocols = >=TLSv1, smtpd_tls_ciphers = medium, no
# exclusions - grommunio-setup never restricts any of this) still offer
# deprecated TLS 1.0/1.1 and CBC-mode ciphers; the same scan flagged
# LUCKY13 as "potentially VULNERABLE" on both port 25 and 587 for exactly
# that reason.
#
# "CBC" is confirmed live as a valid OpenSSL cipher-string exclusion
# keyword (`openssl ciphers -v 'HIGH:!aNULL:!CBC'` drops all 22 CBC suites
# from this box's OpenSSL build, keeping only AEAD/GCM/ChaCha20-Poly1305) -
# this is a different mechanism from gromox's own openssl-noncbc.cnf fix
# (a system-wide OpenSSL CipherString override): postfix's TLS parameters
# are independent of that file, so the exclusion is set directly via its
# own smtpd_tls_exclude_ciphers parameter instead.
#
# Applied in main.cf (not per-listener), so it covers smtp:25,
# submission:587 and submissions:465 uniformly - 35-saslauthd.sh is what
# creates/hardens the listeners themselves. Idempotent: only postconf -e's
# what's not already set, every run.
# ============================================================

local -A TLS_HARDENING=(
    [smtpd_tls_protocols]=">=TLSv1.2"
    [smtpd_tls_mandatory_protocols]=">=TLSv1.2"
    [smtpd_tls_ciphers]="high"
    [smtpd_tls_mandatory_ciphers]="high"
    [smtpd_tls_exclude_ciphers]="aNULL, CBC"
    # smtpd_tls_mandatory_exclude_ciphers and both smtp_tls_* (outbound/
    # client) equivalents were missing entirely until 2026-10-30 - found
    # while reviewing the full settings list during the SHA-1 investigation:
    # only the plain smtpd_tls_exclude_ciphers above had ever been set,
    # leaving postfix's OWN outgoing connections (sending mail out) with
    # no CBC exclusion at all, and the server side's "mandatory" tier
    # unprotected too.
    [smtpd_tls_mandatory_exclude_ciphers]="aNULL, CBC"
    [smtp_tls_exclude_ciphers]="aNULL, CBC"
    [smtp_tls_mandatory_exclude_ciphers]="aNULL, CBC"
    # 1, not Postfix's own default 0: logs one summary line per
    # connection (protocol, cipher, key-exchange, signature) - enough to
    # spot a real compatibility problem (found live 2026-11-12/13 during
    # a scanner/Gmail compatibility round) without the much noisier
    # per-record hex/ASCII dumps level 2+ adds.
    [smtpd_tls_loglevel]="1"
)
local TLS_HARDENING_CHANGED=0
local tls_param tls_want tls_have
for tls_param in "${!TLS_HARDENING[@]}"; do
    tls_want="${TLS_HARDENING[$tls_param]}"
    tls_have="$(postconf -h "$tls_param")"
    if [[ "$tls_have" == "$tls_want" ]]; then
        log "[ OK ] ${tls_param} is already ${tls_want}."
    else
        [[ "$TLS_HARDENING_CHANGED" -eq 1 ]] || backup_file /etc/postfix/main.cf
        postconf -e "${tls_param}=${tls_want}" || die "Could not set ${tls_param}."
        TLS_HARDENING_CHANGED=1
        log "Set ${tls_param} = ${tls_want} (was: '${tls_have:-<unset>}')."
    fi
done
finalize_backup /etc/postfix/main.cf

if [[ "$TLS_HARDENING_CHANGED" -eq 1 ]]; then
    postfix check || die "postfix check failed after the TLS protocol/cipher hardening."
    systemctl reload postfix || die "postfix reload failed after the TLS protocol/cipher hardening."
    log "[ OK ] postfix reloaded with the hardened TLS protocol/cipher policy."
fi

# ============================================================
# Block SHA-1 as a TLS1.2 signature algorithm (2026-10-30) - prompted by
# an external mail-security scan report flagging "Server accepts SHA-1 as
# hash function for the digital signature during key exchange" (RFC 9155
# discourages this). Live testing found this server's OpenSSL 3.5.7 build
# ALREADY refuses a SHA-1-only signature_algorithms offer by default (its
# own SECLEVEL policy) and always picks SHA-256+ over SHA-1 even in a
# mixed offer - so this is NOT a fix for an active weakness, just
# explicit, defense-in-depth hardening against a future OpenSSL/config
# change silently relaxing that default.
#
# Postfix has no native parameter for this (confirmed:
# `postconf -d | grep -i sigalg` returns nothing) - the mechanism is the
# same one gromox-imap/-pop3 already use for their own CBC-cipher
# exclusion (`openssl-noncbc.cnf` + a systemd Environment=OPENSSL_CONF=
# override, confirmed by reading their actual .service.d/override.conf
# files, not assumed): a dedicated, service-scoped OpenSSL config file.
# `SignatureAlgorithms` (not `CipherString`) is the config-file key for
# this - confirmed both from OpenSSL's own SSL_CONF_cmd docs and by a live
# discriminating test (a temporary openssl s_server restricted to
# ECDSA+SHA384 only correctly refused a SHA256 offer, which default
# OpenSSL always accepts - proving the directive is actually parsed and
# enforced, not a silently-ignored no-op).
POSTFIX_OPENSSL_CONF="/etc/postfix/openssl-nosha1.cnf"
POSTFIX_SYSTEMD_OVERRIDE_DIR="/etc/systemd/system/postfix.service.d"
POSTFIX_SYSTEMD_OVERRIDE="${POSTFIX_SYSTEMD_OVERRIDE_DIR}/override.conf"

SHA1_CONF_WANT='openssl_conf = openssl_init

[openssl_init]
ssl_conf = ssl_module

[ssl_module]
system_default = system_default_sect

[system_default_sect]
SignatureAlgorithms = ECDSA+SHA512:ECDSA+SHA384:ECDSA+SHA256:RSA+SHA512:RSA+SHA384:RSA+SHA256
'
SHA1_OVERRIDE_WANT="[Service]
Environment=OPENSSL_CONF=${POSTFIX_OPENSSL_CONF}
"

sha1_changed=0

if [[ -f "$POSTFIX_OPENSSL_CONF" ]] && cmp -s <(printf '%s' "$SHA1_CONF_WANT") "$POSTFIX_OPENSSL_CONF"; then
    log "[ OK ] ${POSTFIX_OPENSSL_CONF} already up to date."
else
    backup_file "$POSTFIX_OPENSSL_CONF"
    printf '%s' "$SHA1_CONF_WANT" > "$POSTFIX_OPENSSL_CONF"
    finalize_backup "$POSTFIX_OPENSSL_CONF"
    sha1_changed=1
    log "[ OK ] Wrote ${POSTFIX_OPENSSL_CONF}."
fi

mkdir -p "$POSTFIX_SYSTEMD_OVERRIDE_DIR"
if [[ -f "$POSTFIX_SYSTEMD_OVERRIDE" ]] && cmp -s <(printf '%s' "$SHA1_OVERRIDE_WANT") "$POSTFIX_SYSTEMD_OVERRIDE"; then
    log "[ OK ] ${POSTFIX_SYSTEMD_OVERRIDE} already up to date."
else
    backup_file "$POSTFIX_SYSTEMD_OVERRIDE"
    printf '%s' "$SHA1_OVERRIDE_WANT" > "$POSTFIX_SYSTEMD_OVERRIDE"
    finalize_backup "$POSTFIX_SYSTEMD_OVERRIDE"
    sha1_changed=1
    log "[ OK ] Wrote ${POSTFIX_SYSTEMD_OVERRIDE} (OPENSSL_CONF scoped to postfix only)."
fi

# Found 2026-11-04 (a `systemctl show postfix -p Environment` looked
# right, but /proc/<master-pid>/environ genuinely lacked OPENSSL_CONF):
# postfix's own master process sanitizes its environment down to
# import_environment's whitelist on every start, discarding anything
# else systemd handed it - the systemd Environment= override above is
# necessary but not sufficient, postfix must also be told to keep this
# one. Without this, the SignatureAlgorithms exclusion silently never
# reached tlsproxy at all, on any restart, since this was first set up -
# confirmed by directly reading tlsproxy's own /proc/<pid>/environ.
CURRENT_IMPORT_ENV="$(postconf -h import_environment)"
if ! grep -qw 'OPENSSL_CONF' <<< "$CURRENT_IMPORT_ENV"; then
    backup_file /etc/postfix/main.cf
    postconf -e "import_environment = ${CURRENT_IMPORT_ENV} OPENSSL_CONF" \
        || die "Could not add OPENSSL_CONF to postfix's import_environment."
    finalize_backup /etc/postfix/main.cf
    sha1_changed=1
    log "[ OK ] Added OPENSSL_CONF to postfix's import_environment."
else
    log "[ OK ] OPENSSL_CONF already in postfix's import_environment."
fi

if [[ "$sha1_changed" -eq 1 ]]; then
    systemctl daemon-reload || die "systemctl daemon-reload failed after the SignatureAlgorithms override."
    systemctl restart postfix || die "postfix did not restart after the SignatureAlgorithms override."
    log "[ OK ] postfix restarted with the SHA-1 signature-algorithm exclusion."
fi

# Verify live: a SHA-1-only offer must fail, a SHA-256 offer must still work.
#
# Found 2026-11-04: the original version of this check (plain
# `-sigalgs 'ECDSA+SHA1'`, no @SECLEVEL) was a false negative all
# along - this host's own openssl CLIENT refuses, at its own default
# security level, to even construct a ClientHello offering only a
# SHA-1 signature algorithm ("no ciphers available", confirmed by
# re-running it with OPENSSL_CONF=/dev/null: same client-side refusal,
# with or without our server-side config). The "0" result always meant
# "the client gave up before sending anything", never "the server
# rejected it" - this was never a real test of the server's behaviour.
# `@SECLEVEL=0` on the CLIENT's own cipher string lowers its security
# floor so it actually sends the SHA-1 offer, making a "0" here mean
# what it always should have.
SHA1_CHECK_OK="$(echo | timeout 8 openssl s_client -connect 127.0.0.1:25 -starttls smtp \
    -tls1_2 -cipher 'ECDHE-ECDSA-AES256-GCM-SHA384:@SECLEVEL=0' -sigalgs 'ECDSA+SHA256' 2>/dev/null \
    | grep -c 'Cipher is ECDHE')"
SHA1_CHECK_BLOCKED="$(echo | timeout 8 openssl s_client -connect 127.0.0.1:25 -starttls smtp \
    -tls1_2 -cipher 'ECDHE-ECDSA-AES256-GCM-SHA384:@SECLEVEL=0' -sigalgs 'ECDSA+SHA1' 2>/dev/null \
    | grep -c 'Cipher is ECDHE')"
if [[ "$SHA1_CHECK_OK" -eq 1 && "$SHA1_CHECK_BLOCKED" -eq 0 ]]; then
    log "[ OK ] Verified live: SHA-256 signature offer works, SHA-1-only offer is refused."
else
    die "SHA-1 signature-algorithm verification failed (SHA-256 ok=${SHA1_CHECK_OK}, SHA-1 blocked=${SHA1_CHECK_BLOCKED})."
fi

# ============================================================
# Outbound MTA-STS enforcement (2026-10-30): everything above is about
# postfix as an SMTP SERVER (inbound TLS). This part is postfix as an SMTP
# CLIENT (outbound) - when WE send mail OUT to another domain that
# publishes its own MTA-STS policy, do we actually validate against it?
# Stock postfix has no native MTA-STS support at all; this package adds a
# small local daemon (mta-sts-daemon, listening on 127.0.0.1:8461) that
# postfix queries per destination via smtp_tls_policy_maps' socketmap
# interface - confirmed working live via the package's own documented
# check: `postmap -q gmail.com socketmap:inet:127.0.0.1:8461:postfix`
# returns "secure match=...".
#
# Prerequisite (confirmed already satisfied on testvps, not changed here):
# smtp_tls_CAfile must point at a real CA bundle, or every MTA-STS
# destination would fail as "Unverified TLS connection" even with a valid
# certificate.
#
# tls_policy is a separate, STATIC, hand-maintained table listed BEFORE
# the socketmap on purpose: this daemon always answers "secure" for any
# domain with an MTA-STS policy, which overrides postfix's own native DANE
# validation for that domain even if it also publishes DANE (RFC 8461
# itself says MTA-STS must not override a failing DANE validation; this
# tool's own README documents this exact override and this exact fix).
# Starts empty - add a line here only for a specific domain confirmed to
# deploy both, e.g. "example.nl dane-only", then re-run `postmap
# /etc/postfix/tls_policy`.
# ============================================================

require_cmd postmap

if ! dpkg -s postfix-mta-sts-resolver >/dev/null 2>&1; then
    log "Installing postfix-mta-sts-resolver..."
    apt-get install -y postfix-mta-sts-resolver
else
    log "[ OK ] postfix-mta-sts-resolver already installed."
fi

local TLS_POLICY_TABLE="/etc/postfix/tls_policy"
if [[ -f "$TLS_POLICY_TABLE" ]]; then
    log "[ OK ] $TLS_POLICY_TABLE already exists - left as-is (hand-maintained)."
else
    cat > "$TLS_POLICY_TABLE" <<'EOF'
# Static DANE override table (ahead of the MTA-STS socketmap) - domains
# known to deploy BOTH MTA-STS and DANE go here as "dane-only", so DANE
# wins for them instead of the MTA-STS resolver. Managed by
# 34-postfix-tls.sh. Empty by design until a specific domain needs it.
EOF
    postmap "$TLS_POLICY_TABLE"
    log "[ OK ] Created $TLS_POLICY_TABLE (empty) and $TLS_POLICY_TABLE.db."
fi

local WANT_POLICY_MAPS="hash:${TLS_POLICY_TABLE}, socketmap:inet:127.0.0.1:8461:postfix"
local HAVE_POLICY_MAPS
HAVE_POLICY_MAPS="$(postconf -h smtp_tls_policy_maps)"
if [[ "$HAVE_POLICY_MAPS" == "$WANT_POLICY_MAPS" ]]; then
    log "[ OK ] smtp_tls_policy_maps already set correctly."
else
    backup_file /etc/postfix/main.cf
    postconf -e "smtp_tls_policy_maps=${WANT_POLICY_MAPS}" || die "Could not set smtp_tls_policy_maps."
    finalize_backup /etc/postfix/main.cf
    postfix check || die "postfix check failed after setting smtp_tls_policy_maps."
    systemctl reload postfix || die "postfix reload failed after setting smtp_tls_policy_maps."
    log "Set smtp_tls_policy_maps = ${WANT_POLICY_MAPS} (was: '${HAVE_POLICY_MAPS:-<unset>}')."
fi

systemctl enable --now postfix-mta-sts-resolver >/dev/null 2>&1
if systemctl is-active --quiet postfix-mta-sts-resolver; then
    log "[ OK ] postfix-mta-sts-resolver is active."
else
    err "postfix-mta-sts-resolver is not active after enabling it."
    return 1
fi

# smtp_tls_loglevel defaults to 0 (postfix logs nothing about outbound TLS
# verification level at all) - raised to 1 so "Verified/Trusted/Untrusted
# TLS connection established..." lines actually appear, confirmed useful
# live 2026-10-30 to verify this step's own MTA-STS enforcement on a real
# message (not just the synthetic postmap -q check below).
if [[ "$(postconf -h smtp_tls_loglevel)" != "1" ]]; then
    backup_file /etc/postfix/main.cf
    postconf -e 'smtp_tls_loglevel=1'
    finalize_backup /etc/postfix/main.cf
    systemctl reload postfix || die "postfix reload failed after setting smtp_tls_loglevel."
    log "[ OK ] Set smtp_tls_loglevel = 1 (outbound TLS verification now visible in the log)."
else
    log "[ OK ] smtp_tls_loglevel is already 1."
fi

local MTA_STS_CHECK
MTA_STS_CHECK="$(postmap -q gmail.com socketmap:inet:127.0.0.1:8461:postfix 2>/dev/null || true)"
if [[ "$MTA_STS_CHECK" == secure\ match=* ]]; then
    log "[ OK ] MTA-STS resolver verified live: gmail.com -> $MTA_STS_CHECK"
else
    err "MTA-STS resolver did not return a 'secure match=' result for gmail.com (got: '${MTA_STS_CHECK:-<empty>}')."
    return 1
fi

# ============================================================
# postscreen (2026-10-30): a cheap protocol-violation triage layer in
# front of smtpd on port 25 ONLY - never 587/465, those are
# authenticated-client ports postscreen must never see (its tests target
# anonymous MTA connections). Catches junk like a raw TLS ClientHello sent
# where plain SMTP is expected, or a client that talks before the server
# has even greeted it - found live 2026-10-30 (92.118.39.58/.65, already
# known from the postfix-abuse findtime-widening work). Deliberately only
# the four cheap, protocol-level tests (PREGREET/pipelining/non-SMTP-
# command/bare-newline), all set to drop - DNSBL-based scoring left off on
# purpose, since rspamd already does its own RBL checks post-acceptance
# and combining both needs a deliberate decision, not a default.
#
# mynetworks (loopback) is exempt from postscreen by its own default
# postscreen_access_list=permit_mynetworks - do not test this from
# 127.0.0.1, it will always pass through untested. Verified live
# 2026-10-30 against the real public IP instead; also confirmed fail2ban's
# own ignoreself rule exempts bans sourced from the server's own public
# IP, which is why a self-test never produces an actual ban even when the
# filter correctly matches.
# ============================================================

local -A POSTSCREEN_SETTINGS=(
    [postscreen_greet_action]="drop"
    [postscreen_non_smtp_command_enable]="yes"
    [postscreen_non_smtp_command_action]="drop"
    [postscreen_pipelining_enable]="yes"
    [postscreen_pipelining_action]="drop"
    [postscreen_bare_newline_enable]="yes"
    [postscreen_bare_newline_action]="drop"
)
local PS_CHANGED=0
local ps_param ps_want ps_have
for ps_param in "${!POSTSCREEN_SETTINGS[@]}"; do
    ps_want="${POSTSCREEN_SETTINGS[$ps_param]}"
    ps_have="$(postconf -h "$ps_param")"
    if [[ "$ps_have" == "$ps_want" ]]; then
        log "[ OK ] ${ps_param} is already ${ps_want}."
    else
        [[ "$PS_CHANGED" -eq 1 ]] || backup_file /etc/postfix/main.cf
        postconf -e "${ps_param}=${ps_want}" || die "Could not set ${ps_param}."
        PS_CHANGED=1
        log "Set ${ps_param} = ${ps_want} (was: '${ps_have:-<unset>}')."
    fi
done
finalize_backup /etc/postfix/main.cf

local MASTER_CF="/etc/postfix/master.cf"
if grep -qE '^smtp[[:space:]]+inet[[:space:]].*[[:space:]]postscreen[[:space:]]*$' "$MASTER_CF"; then
    log "[ OK ] master.cf already wires port 25 through postscreen."
else
    backup_file "$MASTER_CF"
    sed -i \
        -e '/^smtp[[:space:]]\+inet[[:space:]]\+n[[:space:]]\+-[[:space:]]\+y[[:space:]]\+-[[:space:]]\+-[[:space:]]\+smtpd$/s/^/#/' \
        -e '/^#smtp[[:space:]]\+inet[[:space:]]\+n[[:space:]]\+-[[:space:]]\+y[[:space:]]\+-[[:space:]]\+1[[:space:]]\+postscreen$/s/^#//' \
        -e '/^#smtpd[[:space:]]\+pass[[:space:]]\+-[[:space:]]\+-[[:space:]]\+y[[:space:]]\+-[[:space:]]\+-[[:space:]]\+smtpd$/s/^#//' \
        -e '/^#dnsblog[[:space:]]\+unix[[:space:]]\+-[[:space:]]\+-[[:space:]]\+y[[:space:]]\+-[[:space:]]\+0[[:space:]]\+dnsblog$/s/^#//' \
        -e '/^#tlsproxy[[:space:]]\+unix[[:space:]]\+-[[:space:]]\+-[[:space:]]\+y[[:space:]]\+-[[:space:]]\+0[[:space:]]\+tlsproxy$/s/^#//' \
        "$MASTER_CF"
    grep -qE '^smtp[[:space:]]+inet[[:space:]].*[[:space:]]postscreen[[:space:]]*$' "$MASTER_CF" \
        || die "master.cf edit did not produce the expected postscreen line - check the file by hand, it may be a non-stock master.cf."
    finalize_backup "$MASTER_CF"
    PS_CHANGED=1
    log "[ OK ] master.cf now wires port 25 through postscreen (smtp/smtpd/dnsblog/tlsproxy)."
fi

if [[ "$PS_CHANGED" -eq 1 ]]; then
    postfix check || die "postfix check failed after the postscreen change."
    systemctl reload postfix || die "postfix reload failed after the postscreen change."
    log "[ OK ] postfix reloaded with postscreen in front of port 25."
fi

# Verify live, against the real public IP (not 127.0.0.1 - mynetworks is
# exempt from postscreen's own tests by default).
local PS_PUBLIC_IP
PS_PUBLIC_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
if [[ -n "$PS_PUBLIC_IP" ]]; then
    local PS_TEST
    PS_TEST="$( { printf 'EHLO postscreen-verify\r\n'; sleep 3; } | timeout 5 nc "$PS_PUBLIC_IP" 25 2>/dev/null)"
    if echo "$PS_TEST" | grep -q '521'; then
        log "[ OK ] Verified live: an EHLO sent before the greeting completes is correctly dropped (521)."
    else
        err "postscreen PREGREET test did not produce the expected 521 response (got: '${PS_TEST}')."
        return 1
    fi
else
    log "[WARN] Could not determine this host's public IP - skipped the live postscreen verification."
fi
}
