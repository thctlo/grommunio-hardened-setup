#!/usr/bin/env bash
#
# 38-antispam.sh
#
# grommunio-antispam (rspamd) is installed by grommunio-setup, but on the test
# server (2026-10-04) it did not filter any mail. Four things were wrong
# (a fifth, non-bug addition - making actions.conf's thresholds explicit -
# is also in this step, see 1e below):
#
#   1. Postfix did not hand mail to rspamd. main.cf had no smtpd_milters, so
#      rspamd scanned 0 messages. grommunio-setup writes these settings in one
#      postconf block; on this server they were missing.
#   2. local.d/antivirus.conf (written by grommunio-setup) nests the clamav
#      block inside a second antivirus {} section, so rspamd's config test
#      fails with "nested section". It also points clamav at TCP 127.0.0.1:3310,
#      but clamd only listens on its Unix socket here.
#   3. DKIM signing was not configured and no key existed, so mail was not
#      signed. SPF and DMARC are DNS-only and need nothing from this step.
#   4. (found 2026-10-17) rspamd's add_header verdict (score 6-14) was
#      entirely invisible to users: nothing routed that mail into Junk. See
#      step 1d below for the fix (gromox's lda_junk_rules) and the
#      feedback-loop risk that comes with it.
#
# DKIM is signed twice per domain:
#   - Ed25519 (RFC 8463), selector "dkim-ed"  -> record dkim-ed._domainkey
#   - RSA 2048,           selector "dkim-rsa" -> record dkim-rsa._domainkey
# Gmail and some other large providers do not verify Ed25519-only signatures,
# so the RSA signature is there for them. Both records are published in DNS
# by hand; this step cannot do that.
#
# This step is safe to re-run:
#   - writes local.d/antivirus.conf (backup of the old file kept)
#   - sets the Postfix milter settings (only if they differ)
#   - adds lda_junk_rules to gromox.cfg only if that directive is not
#     already present at all (never overwrites a value you set by hand)
#   - creates both DKIM keys per active domain (existing keys are kept)
#   - writes local.d/dkim_signing.conf (per domain, both selectors), restarts rspamd
#   - checks the rspamd config and that a test message gets both signatures
#   - writes the DNS records to /root/cfg-server/dkim-dns-records.txt
#
# Port 11332 is the rspamd milter (grommunio-setup's value). Mail that rspamd
# cannot scan is accepted (milter_default_action=accept), so a broken rspamd
# does not stop mail flow.

RSPAMD_MILTER="inet:localhost:11332"
RSPAMD_DKIM_DIR="/var/lib/rspamd/dkim"
RSPAMD_DKIM_ED_SELECTOR="dkim-ed"
RSPAMD_DKIM_ED_TYPE="ed25519"
RSPAMD_DKIM_RSA_SELECTOR="dkim-rsa"
RSPAMD_DKIM_RSA_BITS=2048
# Only these domains get DKIM keys and signing. Other active domains are left
# alone. Determined at run time, inside step_antispam() below (not here at
# source time, before steps 10/30 have actually run) - see there for how.

# make_dkim_key <domain> <selector> <type> [bits]: creates one key and keeps an existing one
make_dkim_key()
{
    local dom="$1" sel="$2" type="$3" bits="${4:-}"
    local key="$RSPAMD_DKIM_DIR/$dom.$sel.key"
    if [[ -f "$key" ]]; then
        log "[ OK ] $type DKIM key for $dom (selector $sel) exists (kept)."
        return 0
    fi
    local -a args=(-t "$type" -d "$dom" -s "$sel" -k "$key")
    if [[ -n "$bits" ]]; then args+=(-b "$bits"); fi
    rspamadm dkim_keygen "${args[@]}" > "$RSPAMD_DKIM_DIR/$dom.$sel.txt" \
        || die "rspamadm could not create the $type DKIM key for $dom."
    chown _rspamd:_rspamd "$key"; chmod 0640 "$key"
    log "[ OK ] Created $type DKIM key for $dom (selector $sel)."
}

step_antispam()
{
require_cmd rspamd
require_cmd rspamc
require_cmd rspamadm
require_cmd postconf

# Which domain(s) to sign DKIM for: prefer the domain confirmed during
# grommunio-setup (step 30's saved cheat-sheet), fall back to what step 10
# detected, same default chain step 30 itself uses for its own prompt. Set
# RSPAMD_DKIM_DOMAINS yourself before calling this step to override (e.g.
# more than one domain, space-separated).
if [[ -z "${RSPAMD_DKIM_DOMAINS:-}" ]]; then
    local SETUP_CFG="$(cfg_file 30-grommunio-setup)"
    local NETHOST_CFG="$(cfg_file 10-network-hostname)"
    local SETUP_FQDN="" SETUP_DOMAIN="" SETUP_TLS="" SETUP_RELAY=""
    local NEW_HOSTNAME="" NEW_DOMAIN="" NEW_FQDN="" PRIMARY_IPV4="" PRIMARY_IPV6=""
    if [[ -f "$SETUP_CFG" ]]; then
        # shellcheck disable=SC1090
        source "$SETUP_CFG"
    fi
    if [[ -z "$SETUP_DOMAIN" && -f "$NETHOST_CFG" ]]; then
        # shellcheck disable=SC1090
        source "$NETHOST_CFG"
    fi
    RSPAMD_DKIM_DOMAINS="${SETUP_DOMAIN:-$NEW_DOMAIN}"
    [[ -n "$RSPAMD_DKIM_DOMAINS" ]] \
        || die "Could not determine the mail domain (no saved answer from step 10 or step 30, and RSPAMD_DKIM_DOMAINS not set by hand)."
fi

# 1. antivirus module: merged block, ClamAV on its Unix socket
local AV_CFG="/etc/rspamd/local.d/antivirus.conf"
local AV_NEW
AV_NEW="$(mktemp)"
cat > "$AV_NEW" <<'CONF'
# local.d/antivirus.conf (managed by 38-antispam.sh)
# Merged into the stock antivirus module, so no outer antivirus {} block here.
#
# REAL GAP FOUND AND FIXED 2026-10-22: without `action = "reject";`, a
# detected virus only added the CLAM_VIRUS symbol (weight 4, from
# local.d/antivirus_group.conf) to the additive spam score - nowhere near
# the reject threshold (15) or even add_header (6) on its own, so a
# confirmed virus (verified live with a real, correctly-encoded EICAR
# attachment through the actual SMTP pipeline, not just a config read)
# sailed through completely unflagged. ClamAV/clamd and the milter
# pipeline were never the problem - confirmed separately that clamd
# itself detects EICAR, and that rspamd's own per-MIME-part attachment
# filter (`is_attachment()`) correctly identified the test attachment as
# checkable. `action = "reject"` makes a virus hit force an immediate
# reject regardless of the overall additive score, matching how
# antivirus detection should behave - a hit is a hit, not a scoring
# input. The message template is also fixed to use antivirus.lua's own
# ${SCANNER}/${VIRUS} placeholders (the old config had them replaced with
# literal empty strings, producing a blank, useless rejection message).
#
# Verified live: EICAR now gets `554 5.7.1 clamav: virus found:
# "Eicar-Test-Signature"`; a normal clean message still passes.
clamav {
  action = "reject";
  scan_mime_parts = true;
  scan_text_mime = false;
  scan_image_mime = false;
  symbol = "CLAM_VIRUS";
  type = "clamav";
  servers = "/var/run/clamav/clamd.ctl";
  message = '${SCANNER}: virus found: "${VIRUS}"';
}
CONF
if ! cmp -s "$AV_NEW" "$AV_CFG"; then
    if [[ -f "$AV_CFG" ]]; then
        backup_file "$AV_CFG"
    fi
    install -m 0644 "$AV_NEW" "$AV_CFG"
    finalize_backup "$AV_CFG"
    log "[ OK ] Wrote $AV_CFG (ClamAV on its Unix socket, no nested block)."
else
    log "[ OK ] $AV_CFG already correct."
fi
rm -f "$AV_NEW"

# 1g. Local sender whitelist/blacklist, user's request 2026-10-22: a ready-to-
#     edit setup, not yet populated with real entries (the map files ship
#     with one commented-out example each, so a real entry is a straight
#     uncomment-and-edit, not a syntax lesson). Blacklist hits force an
#     immediate reject (same reasoning as antivirus's action=reject earlier
#     the same day - a blacklist match is a decision, not a scoring input);
#     whitelist hits get a strong but not absolute -5.0 score reduction, so
#     a whitelisted domain sending something that also trips several other
#     real red flags can still be caught, rather than get a blanket bypass.
#     Verified live: a test domain added to the blacklist gets a hard
#     reject with `Message - smtp_message: Matched map: ...`; the same
#     domain added to the whitelist instead drops a message's score from
#     well above add_header down to 2.50 (no action).
#
#     REAL RISK FOUND AND REVERTED 2026-10-22, same day: this domain
#     whitelist matches the raw `From:` header text only - it does NOT
#     require SPF/DKIM to actually pass. Briefly populated
#     whitelist_domains.map with this server's own 12 hosted domains
#     (seemed reasonable at first). Tested what that actually does: an
#     external, unauthenticated message forging `From: x@example.com`
#     (no valid SPF/DKIM) got DMARC_POLICY_QUARANTINE(+1.5) correctly,
#     but WHITELISTED_SENDER_DOMAIN(-5.0) outweighed it - net score low
#     enough for "no action", meaning the whitelist made spoofing this
#     server's own domains EASIER to get through, not harder. Reverted:
#     this map is for externally-added trusted PARTNER domains only
#     (added by hand later, by someone who's judged it's safe to trust
#     that domain's name alone) - never this server's own hosted
#     domains, which are exactly the ones worth spoofing and are already
#     protected by SPF/DKIM/DMARC on their own.
local MAPS_DIR="/etc/rspamd/local.d/maps.d"
install -d -m 0755 "$MAPS_DIR"
local -A WB_MAPS=(
    [whitelist_domains.map]="# Sender domains that are always trusted (reduces the spam score sharply).
# One domain per line, # for comments. Example (commented out):
# partner-company.example
#
# Deliberately NOT this server's own hosted domains (this server's hosted domains) -
# tested 2026-10-22: an external, unauthenticated message forging a
# From: header on one of our own domains got -5.0 from this, which
# outweighed the DMARC warning (+1.5) and let the message through
# unflagged - exactly backwards, since this is a plain domain-name match
# with no SPF/DKIM requirement. Only meant for external partner domains
# you add yourself. (As of 2026-10-22, the real whitelist score only
# applies via the TRUSTED_WHITELISTED_SENDER composite (local.d/composites.conf),
# which also requires a passing SPF or DKIM check - so this is safe to populate with
# any domain, including one of this server's own, going forward. Kept
# out of the default example anyway, since the safest default is still
# an empty list.)"
    [whitelist_emails.map]="# Specific sender addresses that are always trusted.
# One address per line, # for comments. Example (commented out):
# invoices@supplier.example"
    [blacklist_domains.map]="# Sender domains that are always rejected.
# One domain per line, # for comments. Example (commented out):
# known-spammer.example"
    [blacklist_emails.map]="# Specific sender addresses that are always rejected.
# One address per line, # for comments. Example (commented out):
# annoying-sender@example.com"
)
local map_name
for map_name in "${!WB_MAPS[@]}"; do
    if [[ ! -f "$MAPS_DIR/$map_name" ]]; then
        printf '%s\n' "${WB_MAPS[$map_name]}" > "$MAPS_DIR/$map_name"
        log "[ OK ] Created $MAPS_DIR/$map_name (empty, one commented example)."
    else
        log "[ OK ] $MAPS_DIR/$map_name already exists - left as-is (may hold real entries by now)."
    fi
done

local MM_CFG="/etc/rspamd/local.d/multimap.conf"
local MM_NEW
MM_NEW="$(mktemp)"
cat > "$MM_NEW" <<CONF
# local.d/multimap.conf (managed by 38-antispam.sh)
#
# WHITELIST_SENDER_DOMAIN/EMAIL score is deliberately 0.0 here - the real
# discount only applies through the TRUSTED_WHITELISTED_SENDER composite
# in local.d/composites.conf, which additionally requires a passing SPF
# or DKIM check. See that file's comment for why: a plain -5.0 here would
# match only the raw From: header text, trivially forged by anyone.
WHITELIST_SENDER_DOMAIN {
  type = "from";
  filter = "email:domain";
  map = "$MAPS_DIR/whitelist_domains.map";
  symbol = "WHITELISTED_SENDER_DOMAIN";
  score = 0.0;
  description = "Sender domain on the local whitelist (see TRUSTED_WHITELISTED_SENDER for the real score)";
}
WHITELIST_SENDER_EMAIL {
  type = "from";
  filter = "email:addr";
  map = "$MAPS_DIR/whitelist_emails.map";
  symbol = "WHITELISTED_SENDER_EMAIL";
  score = 0.0;
  description = "Sender address on the local whitelist (see TRUSTED_WHITELISTED_SENDER for the real score)";
}
BLACKLIST_SENDER_DOMAIN {
  type = "from";
  filter = "email:domain";
  map = "$MAPS_DIR/blacklist_domains.map";
  symbol = "BLACKLISTED_SENDER_DOMAIN";
  action = "reject";
  description = "Sender domain on the local blacklist";
}
BLACKLIST_SENDER_EMAIL {
  type = "from";
  filter = "email:addr";
  map = "$MAPS_DIR/blacklist_emails.map";
  symbol = "BLACKLISTED_SENDER_EMAIL";
  action = "reject";
  description = "Sender address on the local blacklist";
}
CONF
if ! cmp -s "$MM_NEW" "$MM_CFG"; then
    if [[ -f "$MM_CFG" ]]; then
        backup_file "$MM_CFG"
    fi
    install -m 0644 "$MM_NEW" "$MM_CFG"
    finalize_backup "$MM_CFG"
    log "[ OK ] Wrote $MM_CFG (whitelist/blacklist by sender domain and address)."
else
    log "[ OK ] $MM_CFG already correct."
fi
rm -f "$MM_NEW"

# 1k. TRUSTED_WHITELISTED_SENDER composite - the real whitelist score, only
#     granted together with a passing SPF or DKIM check.
#
#     REAL VULNERABILITY FOUND AND FIXED 2026-10-22: the user asked to
#     populate whitelist_domains.map with this server's own hosted
#     domains. Tested before trusting it (same pattern as the antivirus
#     fix earlier the same day - verify, don't assume): an external,
#     unauthenticated message forging `From: x@example.com` (no valid
#     SPF/DKIM) got DMARC_POLICY_QUARANTINE(+1.5) correctly, but a plain
#     multimap `score = -5.0` on WHITELISTED_SENDER_DOMAIN outweighed it -
#     net score low enough for "no action". The whitelist made spoofing
#     this server's own domain identity EASIER, not harder - the map only
#     ever matches raw From: header text, never checks it's genuine.
#
#     First fix (same day, simpler): just don't put this server's own
#     domains in the map, document why in the file. Still left a real gap
#     open: ANY future whitelist entry - including someone eventually
#     re-adding an own domain without reading the warning - inherits the
#     exact same bypass. User asked directly "are we actually protected
#     against that" - answer was no, so this composite makes the
#     *mechanism* itself safe regardless of what gets added later: the
#     real -5.0 only fires when the whitelist match is paired with
#     R_DKIM_ALLOW or R_SPF_ALLOW actually passing.
#
#     Verified live, both directions: the same spoofed/unauthenticated
#     test message got WHITELISTED_SENDER_DOMAIN(0.00) and no
#     TRUSTED_WHITELISTED_SENDER - still scored into "add header", no
#     bypass. A genuinely DKIM-signed message (sent for real through this
#     server's own authenticated submission + DKIM signing, one of this
#     server's own domains temporarily added to the map for this one test, removed
#     afterwards) got R_DKIM_ALLOW and TRUSTED_WHITELISTED_SENDER(-5.00)
#     together, confirming the legitimate path still works.
local COMP_CFG="/etc/rspamd/local.d/composites.conf"
local COMP_NEW
COMP_NEW="$(mktemp)"
cat > "$COMP_NEW" <<'CONF'
# local.d/composites.conf (managed by 38-antispam.sh)
TRUSTED_WHITELISTED_SENDER {
  expression = "(WHITELISTED_SENDER_DOMAIN | WHITELISTED_SENDER_EMAIL) & (R_DKIM_ALLOW | R_SPF_ALLOW)";
  score = -5.0;
  description = "Whitelisted sender domain/address with a passing SPF or DKIM check";
}
CONF
if ! cmp -s "$COMP_NEW" "$COMP_CFG"; then
    if [[ -f "$COMP_CFG" ]]; then
        backup_file "$COMP_CFG"
    fi
    install -m 0644 "$COMP_NEW" "$COMP_CFG"
    finalize_backup "$COMP_CFG"
    log "[ OK ] Wrote $COMP_CFG (whitelist discount now requires passing SPF or DKIM too)."
else
    log "[ OK ] $COMP_CFG already correct."
fi
rm -f "$COMP_NEW"

# 1b. milter headers: rspamd adds nothing to mail unless "use" lists the headers
local MH_CFG="/etc/rspamd/local.d/milter_headers.conf"
local MH_NEW
MH_NEW="$(mktemp)"
cat > "$MH_NEW" <<CONF
# local.d/milter_headers.conf (managed by 38-antispam.sh)
# Headers rspamd adds to each message: SPF, DKIM and DMARC results, the spam
# score, and (spam-header, overridden below to emit X-Spam-Flag: YES) a
# plain yes/no flag - gromox's lda_junk_rules matches on that one to file
# mail into Junk, see 1d. NOTE (found 2026-10-17, corrected): "x-spam-flag"
# is not a real milter_headers routine name - rspamd logged "routine
# "x-spam-flag" does not exist" and silently never added the header, which
# would have made 1d's lda_junk_rules rule never fire. The real routine is
# called "spam-header"; its own default emits "Deliver-To: Junk" instead,
# so the header/value are overridden below to match gromox's example
# (X-Spam-Flag=YES) instead of changing the gromox.cfg side.
# Confirmed by reading /usr/share/rspamd/plugins/milter_headers.lua directly
# (rspamd 3.12.1): settings.routines['spam-header'] is the registered name,
# and opts.routines["spam-header"] is where local.d overrides header/value.
use = ["authentication-results", "x-spamd-result", "x-rspamd-queue-id", "x-rspamd-server", "x-spam-level", "spam-header"];
routines {
    "spam-header" {
        header = "X-Spam-Flag";
        value = "YES";
        remove = 0;
    }
}
CONF
if ! cmp -s "$MH_NEW" "$MH_CFG"; then
    install -m 0644 "$MH_NEW" "$MH_CFG"
    log "[ OK ] Wrote $MH_CFG (Authentication-Results and spam headers)."
else
    log "[ OK ] $MH_CFG already correct."
fi
rm -f "$MH_NEW"

# 1d. Without this, rspamd's add_header verdict (score 6-14, below reject but
#     above greylist) does nothing visible: the headers above are added, but
#     nothing files the message into Junk - found live on testvps
#     2026-10-17, confirmed against grommunio's own antispam guide
#     (docs.grommunio.com/guides/antispam/): Postfix/rspamd tag the message,
#     gromox-delivery turns it into a MAPI object, and gromox's own
#     lda_junk_rules (gromox.cfg, added in Gromox 3.4) is what actually
#     moves it to Junk E-mail instead of Inbox - and it was empty.
#
#     Risk, straight from that same guide: grommunio-spam-run learns every
#     message sitting in Junk as confirmed spam, every night. A legitimate
#     message that gets wrongly add_header-flagged now lands in Junk AND
#     gets reinforced as spam the next night, instead of just being
#     misfiled. Not mitigated here - only documented. Check Junk folders
#     for false positives occasionally.
local GROMOX_CFG="/etc/gromox/gromox.cfg"
local JUNK_RULE="lda_junk_rules=X-Spam-Flag=YES"
if [[ -f "$GROMOX_CFG" ]] && grep -q "^lda_junk_rules=" "$GROMOX_CFG"; then
    log "[ OK ] $GROMOX_CFG already has lda_junk_rules set (left as-is, not overwritten)."
elif [[ -f "$GROMOX_CFG" ]]; then
    echo "$JUNK_RULE" >> "$GROMOX_CFG"
    log "[ OK ] $GROMOX_CFG: added $JUNK_RULE."
    systemctl restart gromox-delivery gromox-delivery-queue \
        || die "gromox-delivery/-queue did not restart after the lda_junk_rules change."
else
    die "$GROMOX_CFG not found - is gromox installed?"
fi

# 1e. actions.conf: write rspamd's own stock thresholds explicitly, rather
#     than silently relying on the compiled-in default (same principle as
#     the domain lookup earlier in this file - make the choice visible, even
#     when the chosen value equals the default).
#
#     Checked against real data before deciding not to change the numbers:
#     scored a real mailbox (2026-10-17, synced in via imapsync, 2487
#     messages sampled across every folder) through rspamc. The labelled
#     spam folder ("Ongewenste e-mail", 37 messages) landed entirely in
#     add_header or reject - 0 messages scored low enough to be missed as
#     no_action/greylist. The add_header hits among legitimate mail
#     concentrated in bulk/transactional folders (crypto exchange notices,
#     invoices, IT support lists), not scattered across personal
#     correspondence. No evidence these defaults are miscalibrated for this
#     mailbox, so they are kept as-is, just made explicit.
local ACT_CFG="/etc/rspamd/local.d/actions.conf"
local ACT_NEW
ACT_NEW="$(mktemp)"
cat > "$ACT_NEW" <<CONF
# local.d/actions.conf (managed by 38-antispam.sh)
# rspamd's own stock values, written explicitly rather than left to the
# compiled-in default. Checked against a real mailbox on 2026-10-17 (see
# comment in 38-antispam.sh) before deciding to keep them unchanged.
reject = 15;
add_header = 6;
# greylist: set far above reject, not removed or set to null - see the
# 1f comment below for why this line exists at all (greylisting is
# disabled, a 2026-10-22 decision). Found live 2026-10-28: the
# base /etc/rspamd/actions.conf already defines "greylist = 4;" directly
# inside its own actions{} block (confirmed by reading it) - re-stating
# the same "4" here, as this file did before, changed NOTHING, so every
# message scoring 4-6 was still silently soft-rejected. The settings.conf
# override below (1f) only ever disabled the greylist MODULE's own
# symbols/forced action - the plain score-threshold "greylist" action
# that assigns this label purely by score, independent of the module, was
# never addressed and is the one that was actually firing (confirmed with
# a real newsletter in rspamd's own history: score 7.63, action "soft
# reject"/greylist). Setting the threshold to a value no real score can
# reach removes that band outright; a literal "null"/omitting the key was
# deliberately NOT used - UCL merge semantics for duplicate=merge made
# the actual behavior of either uncertain enough not to risk it, verified
# live instead with this far-above-reject value, re-tested with a known
# repro that previously greylisted at score 5.70 - now "no action", and
# add_header/reject both reconfirmed unaffected.
greylist = 1000;
CONF
if ! cmp -s "$ACT_NEW" "$ACT_CFG"; then
    install -m 0644 "$ACT_NEW" "$ACT_CFG"
    log "[ OK ] Wrote $ACT_CFG (reject=15, add_header=6, greylist=1000/effectively disabled)."
else
    log "[ OK ] $ACT_CFG already correct."
fi
rm -f "$ACT_NEW"

# 1f. Greylisting disabled entirely, user's call 2026-10-22: it delays
#     first-time senders by design (soft-reject + require a retry within
#     1 day), judged more annoying than useful given everything else
#     already active (Bayes, neural, fuzzy_check, DMARC/SPF/DKIM,
#     antivirus). The greylist module (greylist.lua) has no `enabled`
#     option of its own (checked the source directly - grepped for
#     "enabled", zero matches) and forces its own "soft reject" action
#     directly, independent of the normal score-threshold path, so
#     neither an `enabled = false` in local.d/greylist.conf nor zeroing
#     a score would do anything. The officially documented way (the
#     greylist module's own doc page) is the settings module: disable
#     the GREYLIST_CHECK/GREYLIST_SAVE symbols and null out the
#     "greylist" action for every connection.
#     Verified live: `rspamc --ip <external-test-ip> ...` (simulating an
#     untrusted sender, who would previously have been greylisted) no
#     longer shows any GREYLIST_* symbol and gets a normal "add header"
#     verdict instead of "soft reject".
local SET_CFG="/etc/rspamd/local.d/settings.conf"
local SET_NEW
SET_NEW="$(mktemp)"
cat > "$SET_NEW" <<'CONF'
# local.d/settings.conf (managed by 38-antispam.sh)
disable_greylisting {
  id = "disable_greylisting";
  priority = high;
  ip = ["0.0.0.0/0", "::/0"];
  apply {
    symbols_disabled = ["GREYLIST_CHECK", "GREYLIST_SAVE"];
    actions {
      greylist = null;
    }
  }
}
CONF
if ! cmp -s "$SET_NEW" "$SET_CFG"; then
    if [[ -f "$SET_CFG" ]]; then
        backup_file "$SET_CFG"
    fi
    install -m 0644 "$SET_NEW" "$SET_CFG"
    finalize_backup "$SET_CFG"
    log "[ OK ] Wrote $SET_CFG (greylisting disabled)."
else
    log "[ OK ] $SET_CFG already correct."
fi
rm -f "$SET_NEW"

# 1h. Reputation module, user's request 2026-10-22: tracks sender IP, SPF-
#     and DKIM-verified domain history in Redis (its own "RR:" prefix, not
#     shared with Bayes), building a per-sender trust/distrust score over
#     time (10+ observations needed before it starts scoring at all -
#     rspamd's own `lower_bound` default - so this does nothing visible
#     for the first while). Config syntax and group weights are straight
#     from docs.rspamd.com/modules/reputation/ - the module needs its own
#     `backend "redis" {}` per rule, it does NOT inherit the global
#     redis.conf automatically.
#     Verified end to end for real: synthetic test traffic from this host
#     (127.0.0.1, via both rspamc and real local SMTP deliveries) never
#     produced any "RR:*" key in Redis - but a genuine external message
#     (a real Gmail test send, 2026-10-22) did: `DKIM_REPUTATION(0.00){0;}`
#     appeared in its scan log, and `redis-cli keys 'RR:*'` immediately
#     showed `RR:gmail.com.a`, `RR:i:2a00:1450:4864:20::`, `RR:c:US`,
#     `RR:a:15169`. So the module only writes history for genuinely
#     external senders, not for anything originating from mynetworks -
#     which is sensible (nothing useful to learn from your own test
#     traffic), not a bug, but it does mean this can only ever be tested
#     with real inbound mail, never from this host alone.
local REP_CFG="/etc/rspamd/local.d/reputation.conf"
local REP_NEW
REP_NEW="$(mktemp)"
cat > "$REP_NEW" <<'CONF'
# local.d/reputation.conf (managed by 38-antispam.sh)
rules {
  ip_reputation = {
    selector "ip" {
    }
    backend "redis" {
      servers = "127.0.0.1:6379";
    }
    symbol = "SENDER_REP";
  }
  spf_reputation = {
    selector "spf" {
    }
    backend "redis" {
      servers = "127.0.0.1:6379";
    }
    symbol = "SPF_REPUTATION";
  }
  dkim_reputation = {
    selector "dkim" {
    }
    backend "redis" {
      servers = "127.0.0.1:6379";
    }
    symbol = "DKIM_REPUTATION";
  }
}
CONF
if ! cmp -s "$REP_NEW" "$REP_CFG"; then
    if [[ -f "$REP_CFG" ]]; then
        backup_file "$REP_CFG"
    fi
    install -m 0644 "$REP_NEW" "$REP_CFG"
    finalize_backup "$REP_CFG"
    log "[ OK ] Wrote $REP_CFG (IP/SPF/DKIM reputation via Redis)."
else
    log "[ OK ] $REP_CFG already correct."
fi
rm -f "$REP_NEW"

# 1i. mx_check and known_senders, enabled 2026-10-29: both are
#     package-default-disabled (confirmed by reading modules.d/*.conf
#     directly - both say "enabled = false;"), and both just need
#     "enabled = true;" to turn on - no redis servers block of their own
#     needed, unlike reputation.conf above (that module's own architecture
#     requires an explicit backend "redis" {} per rule; mx_check/
#     known_senders use rspamd's common lua_redis library, which reads the
#     global local.d/redis.conf automatically).
#     mx_check: connects to each sender domain's own MX to confirm it's
#     real/reachable (MX_GOOD/MX_INVALID/MX_MISSING symbols).
#     known_senders: tracks (in Redis) which addresses have mailed before;
#     a first-ever sender gets a different symbol than a known one -
#     complements reputation.conf (IP/SPF/DKIM-level) at the email-address
#     level.
local MXCHK_CFG="/etc/rspamd/local.d/mx_check.conf"
local MXCHK_NEW
MXCHK_NEW="$(mktemp)"
cat > "$MXCHK_NEW" <<'CONF'
# local.d/mx_check.conf (managed by 38-antispam.sh)
enabled = true;
CONF
if ! cmp -s "$MXCHK_NEW" "$MXCHK_CFG" 2>/dev/null; then
    install -m 0644 "$MXCHK_NEW" "$MXCHK_CFG"
    log "[ OK ] Wrote $MXCHK_CFG (enabled)."
else
    log "[ OK ] $MXCHK_CFG already correct."
fi
rm -f "$MXCHK_NEW"

local KSEND_CFG="/etc/rspamd/local.d/known_senders.conf"
local KSEND_NEW
KSEND_NEW="$(mktemp)"
cat > "$KSEND_NEW" <<'CONF'
# local.d/known_senders.conf (managed by 38-antispam.sh)
enabled = true;
CONF
if ! cmp -s "$KSEND_NEW" "$KSEND_CFG" 2>/dev/null; then
    install -m 0644 "$KSEND_NEW" "$KSEND_CFG"
    log "[ OK ] Wrote $KSEND_CFG (enabled)."
else
    log "[ OK ] $KSEND_CFG already correct."
fi
rm -f "$KSEND_NEW"

local GRP_CFG="/etc/rspamd/local.d/groups.conf"
local GRP_NEW
GRP_NEW="$(mktemp)"
cat > "$GRP_NEW" <<'CONF'
# local.d/groups.conf (managed by 38-antispam.sh)
group "reputation" {
  symbols = {
    "SENDER_REP_HAM" {
      weight = -1.0;
    }
    "SENDER_REP_SPAM" {
      weight = 4.0;
    }
    "DKIM_REPUTATION" {
      weight = 1.0;
    }
    "SPF_REPUTATION_HAM" {
      weight = -1.0;
    }
    "SPF_REPUTATION_SPAM" {
      weight = 2.0;
    }
  }
}
CONF
if ! cmp -s "$GRP_NEW" "$GRP_CFG"; then
    if [[ -f "$GRP_CFG" ]]; then
        backup_file "$GRP_CFG"
    fi
    install -m 0644 "$GRP_NEW" "$GRP_CFG"
    finalize_backup "$GRP_CFG"
    log "[ OK ] Wrote $GRP_CFG (reputation symbol weights)."
else
    log "[ OK ] $GRP_CFG already correct."
fi
rm -f "$GRP_NEW"

# 1i. senderscore_reputation RBL disabled, found and fixed 2026-10-22: every
#     query to score.senderscore.com (any IP at all, including Google's and
#     this server's own public IP - tested directly with several) returned
#     the identical fixed 127.255.255.255 ("RBL_SENDERSCORE_REPUT_BLOCKED",
#     already weight 0.0, so this was never a scoring problem - just a
#     recurring, meaningless "likely DNS spoofing or BL internal issues"
#     warning every ~10-15 minutes from rspamd's own health-check). Root
#     cause: modules.d/rbl.conf's own comments explain the free-tier query
#     quota is shared between `bl.score.senderscore.com` and
#     `score.senderscore.com` - rspamd's stock config already disables the
#     former by default for exactly this reason ("Disabled by default to
#     prioritize the use of score.senderscore.com"), and even with only
#     the latter active, the shared quota is already exhausted. The exact
#     numeric quota isn't published anywhere readable (Validity's own
#     knowledge-base article is a JS-rendered page with no static text) -
#     getting real data back would need registering a MyValidity account,
#     not something worth doing for a single RBL signal among many others
#     already working. `enabled = false` is natively supported per-rule in
#     this module (the stock "senderscore" sibling rule already uses it) -
#     confirmed via rspamd's own startup log: `disable rbl
#     "senderscore_reputation"`, and other RBLs (tested: RBL_SPAMHAUS_PBL)
#     keep firing normally.
local RBL_CFG="/etc/rspamd/local.d/rbl.conf"
local RBL_NEW
RBL_NEW="$(mktemp)"
cat > "$RBL_NEW" <<'CONF'
# local.d/rbl.conf (managed by 38-antispam.sh)
rules {
  senderscore_reputation {
    enabled = false;
  }
}
CONF
if ! cmp -s "$RBL_NEW" "$RBL_CFG"; then
    if [[ -f "$RBL_CFG" ]]; then
        backup_file "$RBL_CFG"
    fi
    install -m 0644 "$RBL_NEW" "$RBL_CFG"
    finalize_backup "$RBL_CFG"
    log "[ OK ] Wrote $RBL_CFG (senderscore_reputation disabled - quota already exhausted, was a zero-weight no-op anyway)."
else
    log "[ OK ] $RBL_CFG already correct."
fi
rm -f "$RBL_NEW"

# 1j. history_redis, found disabled 2026-10-22 while verifying the earlier
#     module inventory: the stock config ships with `servers` commented
#     out, so rspamd's web-UI scan history was never actually persisted to
#     Redis (it has its own separate, non-Redis basic history regardless,
#     so this wasn't "no history at all", just not the Redis-backed kind).
#     Pointed at the same local Redis as everything else here. Verified
#     live: after restarting rspamd and sending one test message, Redis
#     key `rs_history<hostname>_zst` (a list, capped at `nrows`
#     =200) existed and was populated - confirmed with `redis-cli type`/
#     `llen`.
local HR_CFG="/etc/rspamd/local.d/history_redis.conf"
local HR_NEW
HR_NEW="$(mktemp)"
cat > "$HR_NEW" <<'CONF'
# local.d/history_redis.conf (managed by 38-antispam.sh)
servers = "127.0.0.1:6379";
CONF
if ! cmp -s "$HR_NEW" "$HR_CFG"; then
    if [[ -f "$HR_CFG" ]]; then
        backup_file "$HR_CFG"
    fi
    install -m 0644 "$HR_NEW" "$HR_CFG"
    finalize_backup "$HR_CFG"
    log "[ OK ] Wrote $HR_CFG (scan history now persisted to Redis)."
else
    log "[ OK ] $HR_CFG already correct."
fi
rm -f "$HR_NEW"

# 1c. Redis for rspamd: the Bayes classifier (ham/spam training) and its learn
#     cache need a Redis server. Without this setting rspamd refuses all learning.
local RD_CFG="/etc/rspamd/local.d/redis.conf"
local RD_NEW
RD_NEW="$(mktemp)"
cat > "$RD_NEW" <<CONF
# local.d/redis.conf (managed by 38-antispam.sh)
# rspamd uses the local Redis for the Bayes classifier and its learn cache.
servers = "127.0.0.1:6379";
write_servers = "127.0.0.1:6379";
CONF
if ! cmp -s "$RD_NEW" "$RD_CFG"; then
    install -m 0644 "$RD_NEW" "$RD_CFG"
    log "[ OK ] Wrote $RD_CFG (rspamd uses Redis on 127.0.0.1:6379)."
else
    log "[ OK ] $RD_CFG already correct."
fi
rm -f "$RD_NEW"

# 2. Postfix milter settings
local pair key want cur
for pair in "smtpd_milters=$RSPAMD_MILTER" "non_smtpd_milters=$RSPAMD_MILTER" "milter_default_action=accept" "milter_protocol=6"; do
    key="${pair%%=*}"; want="${pair#*=}"
    cur="$(postconf -h "$key" 2>/dev/null)"
    if [[ "$cur" != "$want" ]]; then
        backup_file /etc/postfix/main.cf
        postconf -e "$pair" || die "postconf could not set $key."
        log "Set Postfix $key = $want (was: ${cur:-empty})."
    fi
done
finalize_backup /etc/postfix/main.cf
if ! postconf -P submission/inet/milter_macro_daemon_name=ORIGINATING 2>/dev/null; then
    log "[WARN] submission service not in master.cf; skipped its milter macro."
fi
log "[ OK ] Postfix milter: $(postconf -h smtpd_milters)"

# 3. DKIM keys for every active domain: Ed25519 and RSA
install -d -o _rspamd -g _rspamd -m 0750 "$RSPAMD_DKIM_DIR" || die "Cannot create $RSPAMD_DKIM_DIR."
local -a domains=()
local d
while read -r d; do
    if [[ -n "$d" ]]; then domains+=("$d"); fi
done < <(grommunio-admin domain list 2>/dev/null | sed -nE 's/^[0-9]+: ([^ ]+) \(active\).*/\1/p')
if [[ ${#domains[@]} -eq 0 ]]; then
    die "No active mail domain found for DKIM (grommunio-admin domain list)."
fi
# keep only the configured DKIM domains ($RSPAMD_DKIM_DOMAINS); other active domains are not signed
local -a dkim_domains=()
for d in "${domains[@]}"; do
    if [[ " $RSPAMD_DKIM_DOMAINS " == *" $d "* ]]; then dkim_domains+=("$d"); fi
done
if [[ ${#dkim_domains[@]} -eq 0 ]]; then
    die "None of the DKIM domains ($RSPAMD_DKIM_DOMAINS) is an active mail domain."
fi
for d in "${dkim_domains[@]}"; do
    make_dkim_key "$d" "$RSPAMD_DKIM_ED_SELECTOR" "$RSPAMD_DKIM_ED_TYPE"
    make_dkim_key "$d" "$RSPAMD_DKIM_RSA_SELECTOR" rsa "$RSPAMD_DKIM_RSA_BITS"
done

local -a imported=()

# 4. DKIM signing config: each domain signs with both selectors
local SIGN_CFG="/etc/rspamd/local.d/dkim_signing.conf"
local SIGN_NEW
SIGN_NEW="$(mktemp)"
{
    echo "# local.d/dkim_signing.conf (managed by 38-antispam.sh)"
    echo "# Each domain signs with an Ed25519 and an RSA selector (two DKIM-Signature headers)."
    echo "sign_authenticated = true;"
    echo "sign_local = true;"
    echo "use_domain = \"header\";"
    echo "use_redis = false;"
    echo "allow_pubkey_mismatch = false;"
    echo "domain {"
    for d in "${dkim_domains[@]}"; do
        echo "  \"$d\" {"
        echo "    selectors ["
        echo "      { path = \"$RSPAMD_DKIM_DIR/$d.$RSPAMD_DKIM_ED_SELECTOR.key\"; selector = \"$RSPAMD_DKIM_ED_SELECTOR\"; },"
        echo "      { path = \"$RSPAMD_DKIM_DIR/$d.$RSPAMD_DKIM_RSA_SELECTOR.key\"; selector = \"$RSPAMD_DKIM_RSA_SELECTOR\"; }"
        echo "    ]"
        echo "  }"
    done
    echo "}"
} > "$SIGN_NEW"
if ! cmp -s "$SIGN_NEW" "$SIGN_CFG"; then
    backup_file "$SIGN_CFG"
    install -m 0644 "$SIGN_NEW" "$SIGN_CFG"
    finalize_backup "$SIGN_CFG"
    log "[ OK ] Wrote $SIGN_CFG."
fi
rm -f "$SIGN_NEW"

# 4b. Local recursive resolver for rspamd. URIBL refuses the hosting provider's
#     resolvers (it answers 127.0.0.1 = "refused"), so URIBL checks silently fail
#     without this. unbound asks the root servers directly, listens on 127.0.0.1 only.
if ! dpkg -s unbound >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y unbound >/dev/null || die "Could not install unbound."
    log "Installed unbound (local resolver for rspamd)."
fi
local UB_CFG="/etc/unbound/unbound.conf.d/rspamd-local.conf"
local UB_NEW
UB_NEW="$(mktemp)"
cat > "$UB_NEW" <<CONF
# Local recursive resolver for rspamd (managed by 38-antispam.sh).
# URIBL refuses forwarding resolvers, so this asks the root and authoritative servers directly.
server:
    interface: 127.0.0.1
    port: 53
    access-control: 127.0.0.0/8 allow
    access-control: 0.0.0.0/0 refuse
    do-ip4: yes
    do-ip6: no
    hide-identity: yes
    hide-version: yes
    prefetch: yes
    qname-minimisation: yes
CONF
ub_changed=0
if ! cmp -s "$UB_NEW" "$UB_CFG"; then
    install -m 0644 "$UB_NEW" "$UB_CFG"; ub_changed=1
    log "[ OK ] Wrote $UB_CFG."
fi
rm -f "$UB_NEW"
unbound-checkconf >/dev/null || die "unbound config test fails (unbound-checkconf)."
systemctl enable unbound >/dev/null 2>&1
if [[ "$ub_changed" -eq 1 ]] || ! systemctl is-active --quiet unbound; then
    systemctl restart unbound || die "unbound did not start."
fi
sleep 2
if [[ -z "$(dig +short @127.0.0.1 "${dkim_domains[0]}" MX 2>/dev/null)" ]]; then
    die "Local resolver does not answer on 127.0.0.1 (unbound)."
fi
log "[ OK ] Local resolver (unbound) answers on 127.0.0.1."

# rspamd uses the local resolver (options.inc is merged into the stock dns block)
local OPT_CFG="/etc/rspamd/local.d/options.inc"
local OPT_NEW
OPT_NEW="$(mktemp)"
cat > "$OPT_NEW" <<CONF
# local.d/options.inc (managed by 38-antispam.sh)
# rspamd asks the local unbound resolver: URIBL and Spamhaus refuse forwarding resolvers.
dns {
    nameserver = ["127.0.0.1:53"];
}
CONF
if ! cmp -s "$OPT_NEW" "$OPT_CFG"; then
    install -m 0644 "$OPT_NEW" "$OPT_CFG"
    log "[ OK ] Wrote $OPT_CFG (rspamd uses 127.0.0.1 for DNS)."
fi
rm -f "$OPT_NEW"

# 5. Check the config and restart
if ! rspamadm configtest >/dev/null 2>&1; then
    die "rspamd config test fails (rspamadm configtest). Not restarting."
fi
systemctl restart rspamd || die "rspamd did not restart."
sleep 3
systemctl is-active --quiet rspamd || die "rspamd is not active after restart."
log "[ OK ] rspamd config test passes and rspamd is running."

# 6. Check: a message from the first domain gets both signatures
local probe scan
probe="$(mktemp)"
printf 'From: postmaster@%s\nTo: test@example.com\nSubject: antispam check\nDate: %s\nMessage-ID: <antispam-check@%s>\n\nCheck.\n' \
    "${dkim_domains[0]}" "$(date -R)" "${dkim_domains[0]}" > "$probe"
scan="$(rspamc --ip 127.0.0.1 --helo "$(hostname -f)" --from "postmaster@${dkim_domains[0]}" --hostname "$(hostname -f)" --headers "$probe" 2>/dev/null)"
rm -f "$probe"
if grep -q "a=ed25519-sha256" <<< "$scan"; then
    log "[ OK ] Test message from ${dkim_domains[0]} is signed with Ed25519 (selector $RSPAMD_DKIM_ED_SELECTOR)."
else
    die "Test message from ${dkim_domains[0]} has no Ed25519 signature. Check: rspamc stat, journalctl -u rspamd."
fi
if grep -q "a=rsa-sha256" <<< "$scan"; then
    log "[ OK ] Test message from ${dkim_domains[0]} is also signed with RSA (selector $RSPAMD_DKIM_RSA_SELECTOR)."
else
    log "[WARN] No RSA signature on the test message from ${dkim_domains[0]}; check the selectors in $SIGN_CFG."
fi

# 6b. Ham training: users move mail that is not spam into a TRAIN-HAM folder.
#     grommunio-ham-run learns that folder as ham every 30 minutes.
#
#     Folder creation itself (for every active user, not just the DKIM
#     domains above - every mailbox benefits from ham training regardless
#     of which domains sign DKIM) is delegated to the standalone
#     ensure-train-ham-folders.sh/.timer, not done inline here - see that
#     script's own header for why: grommunio-admin has no hook that creates
#     this when a new user is added, so a one-time loop here only ever
#     covered whichever users existed at the moment this step last ran.
#     Found live 2026-10-28: NOT ONE of 19 active users on a freshly
#     reprovisioned testvps had the folder, because every one of them was
#     created/restored after this step's single run. The standalone
#     script/timer (daily, deployed separately) is the permanent fix; this
#     step still runs it once immediately too, for instant effect on a
#     normal provisioning run.
# grommunio-ham-run.timer ships at every 30 minutes
# (/usr/lib/systemd/system/, package-owned - not edited directly).
# Changed 2026-10-29: every 30 minutes is overkill, since mail is moved
# into TRAIN-HAM rarely, not every half hour - changed to every 4 hours via a drop-in
# override (OnCalendar= cleared then re-set, which is how systemd drop-ins
# replace rather than add to a repeated directive).
local HAMRUN_TIMER_DROPIN_DIR="/etc/systemd/system/grommunio-ham-run.timer.d"
local HAMRUN_TIMER_DROPIN="$HAMRUN_TIMER_DROPIN_DIR/override.conf"
local HAMRUN_TIMER_NEW
HAMRUN_TIMER_NEW="$(mktemp)"
cat > "$HAMRUN_TIMER_NEW" <<'DROPIN'
# Managed by 38-antispam.sh - changed 2026-10-29: every 30 minutes
# was overkill (users move mail into TRAIN-HAM rarely, not every half
# hour), changed to every 4 hours. OnCalendar= in a drop-in REPLACES the
# package's own value entirely (systemd's own documented behavior for
# repeated directives via a drop-in), so no need to clear it first.
[Timer]
OnCalendar=
OnCalendar=00/4:05:00
DROPIN
install -d "$HAMRUN_TIMER_DROPIN_DIR"
if ! cmp -s "$HAMRUN_TIMER_NEW" "$HAMRUN_TIMER_DROPIN" 2>/dev/null; then
    install -m 0644 "$HAMRUN_TIMER_NEW" "$HAMRUN_TIMER_DROPIN"
    systemctl daemon-reload
    systemctl restart grommunio-ham-run.timer || die "Could not restart grommunio-ham-run.timer after changing its interval."
    log "[ OK ] grommunio-ham-run.timer: interval changed to every 4 hours."
else
    log "[ OK ] grommunio-ham-run.timer: 4-hour interval already set."
fi
rm -f "$HAMRUN_TIMER_NEW"

local HAM_FOLDER="TRAIN-HAM"
local SPAMRUN_CFG="/etc/gromox/spamrun.cfg"
if [[ -f "$SPAMRUN_CFG" ]]; then
    backup_file "$SPAMRUN_CFG"
    if grep -q "^HAMRUN_FOLDER=" "$SPAMRUN_CFG"; then
        sed -i "s/^HAMRUN_FOLDER=.*/HAMRUN_FOLDER=$HAM_FOLDER/" "$SPAMRUN_CFG"
    else
        echo "HAMRUN_FOLDER=$HAM_FOLDER" >> "$SPAMRUN_CFG"
    fi
    finalize_backup "$SPAMRUN_CFG"
    log "[ OK ] $SPAMRUN_CFG: HAMRUN_FOLDER=$HAM_FOLDER."
fi
if [[ -x /root/bin/ensure-train-ham-folders.sh ]]; then
    /root/bin/ensure-train-ham-folders.sh --all || die "ensure-train-ham-folders.sh --all failed."

    # Install the daily timer too - the one-time --all run above only
    # catches users that already exist right now. Without this timer,
    # a user created later never gets the folder until someone re-runs
    # this step by hand (found live 2026-10-28: 0 of 19 users had it,
    # all created/restored after this step had last run).
    local TRAIN_HAM_SVC="/root/bin/ensure-train-ham-folders.service"
    local TRAIN_HAM_TIMER="/root/bin/ensure-train-ham-folders.timer"
    if [[ -f "$TRAIN_HAM_SVC" && -f "$TRAIN_HAM_TIMER" ]]; then
        install -m 0644 "$TRAIN_HAM_SVC" /etc/systemd/system/ensure-train-ham-folders.service
        install -m 0644 "$TRAIN_HAM_TIMER" /etc/systemd/system/ensure-train-ham-folders.timer
        systemctl daemon-reload
        systemctl enable --now ensure-train-ham-folders.timer \
            || die "Could not enable ensure-train-ham-folders.timer."
        log "[ OK ] Installed and enabled ensure-train-ham-folders.timer (daily, catches users created after today)."
    else
        log "[WARN] ensure-train-ham-folders.service/.timer not found next to ensure-train-ham-folders.sh - the daily check will not run, only today's one-time pass above."
    fi
else
    log "[WARN] /root/bin/ensure-train-ham-folders.sh not found - deploy it separately to create $HAM_FOLDER for active users."
fi

# 7. The DNS records to publish (by hand, at the DNS provider)
local RECORDS="/root/cfg-server/dkim-dns-records.txt"
local rec_value sel
backup_file "$RECORDS"
: > "$RECORDS"
chmod 0600 "$RECORDS"
for d in "${dkim_domains[@]}"; do
    for sel in "$RSPAMD_DKIM_ED_SELECTOR" "$RSPAMD_DKIM_RSA_SELECTOR"; do
        # keygen writes a zone-file line; take the quoted parts and join them into the TXT value
        rec_value="$(tr -d '\n' < "$RSPAMD_DKIM_DIR/$d.$sel.txt" | grep -oE '"[^"]*"' | tr -d '"' | tr -d '\n' | sed -E 's/;p=/; p=/; s/ +/ /g')"
        {
            echo "# $d ($sel)"
            echo "name:  ${sel}._domainkey"
            echo "type:  TXT"
            echo "value: $rec_value"
            echo
        } >> "$RECORDS"
    done
done
finalize_backup "$RECORDS"
log "[ OK ] DKIM DNS records written to $RECORDS (publish them, DKIM does not verify until they are in DNS)."
log "     SPF and DMARC were already published for ${dkim_domains[*]}."
}
