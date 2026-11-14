# Installation Manual

Everything below uses the **grommunio community Debian repository** as
the default, supported path — no packages of the author's own are
required. See [`custom-repo/README.md`](custom-repo/README.md) for the
optional, separate path that replaces a couple of specific packages
with the author's own rebuilds.

## 1. Prerequisites

- A clean Debian 13 (trixie) install - a fresh VM or dedicated server,
  nothing else running on it. Root access (console, or SSH as root).
- **DNS must be prepared *before* you start** - specifically, the
  server's reverse DNS (PTR) record, set with your hosting provider,
  must already point at the hostname you intend to give this server.
  This can't be fixed after the fact without re-doing TLS/DANE/HELO
  identity work, so get it right first. See step 2 below for how to
  check it.
- At least 4 GB RAM / 2 vCPU, a few GB free disk for the base install.

## 2. Quick start - pulling in this repo and checking DNS

On the clean server, as root:

```
apt-get install -y git
git clone https://github.com/thctlo/grommunio-hardened-setup.git /root/bin
cd /root/bin
```

Before running anything else, confirm your server's own DNS identity
is already correct:

```
./check-dns.sh --firstdomain
```

This checks the server's reverse DNS (PTR) and whether it's
forward-confirmed (the PTR target's own A/AAAA record points back to
this server) - the two things that must be true before a mail server
has any hope of a good reputation. If this reports a problem, fix it
with your hosting provider before continuing - everything else in this
manual assumes it's already correct.

Once you know which domain(s) you'll be hosting mail for, get a
ready-to-send DNS setup sheet for each one (with this server's real
IPs already filled in - hand it to whoever manages that domain's DNS,
even if that's you):

```
./check-dns.sh --report example.com
```

Example output (IPs replaced with documentation placeholders below -
yours will show this server's real addresses):

```
DNS records to set up for: example.com
(mail server: mail.example.com, IPv4: 203.0.113.10, IPv6: 2001:db8::10)
(MX currently: MX record found but has no target (null MX?))

-- Core mail routing --
@                       3600    A       203.0.113.10
@                       3600    AAAA    2001:db8::10
@                       3600    MX      10 mail.example.com.
mail                    3600    A       203.0.113.10
mail                    3600    AAAA    2001:db8::10

-- SPF / DKIM / DMARC (anti-spoofing) --
@                       3600    TXT     "v=spf1 mx -all"
mail                    3600    TXT     "v=spf1 a -all"
dkim-ed._domainkey      300     TXT     (generate with: manage-dkim.sh -domain example.com)
dkim-rsa._domainkey     300     TXT     (generate with: manage-dkim.sh -domain example.com)
dkim._domainkey         300     CNAME   dkim-rsa._domainkey.example.com.
_dmarc                  300     TXT     "v=DMARC1; p=quarantine; rua=mailto:admin@example.com"

-- Certificate issuance (optional, restricts which CA may issue certs) --
@                       3600    CAA     0 issue "letsencrypt.org"
@                       3600    CAA     128 issuewild "letsencrypt.org"

-- MTA-STS + TLS reporting (recommended - enforces TLS on inbound mail) --
(_mta-sts currently: no _mta-sts TXT record found)
(set up the policy file + nginx with: manage-mta-sts.sh -domain example.com)
_mta-sts                3600    TXT     "v=STSv1; id=202611112311"
mta-sts                 3600    A       203.0.113.10
mta-sts                 3600    AAAA    2001:db8::10
_smtp._tls              3600    TXT     "v=TLSRPTv1; rua=mailto:postmaster@example.com"

-- DANE (optional, only recommended if your DNS provider can be updated
   automatically - see note below) --
(DANE currently: no TLSA record at _25._tcp.mail.example.com)
(set up with: manage-dane.sh, see its own --status/--setup - mail.example.com
is already exclusive to this domain, not shared with the server's own
identity or any other domain, so no extra MX hostname is needed first)

-- Mail client autoconfiguration (Thunderbird + Outlook) --
autoconfig              86400   CNAME   mail.example.com.
autodiscover            86400   CNAME   mail.example.com.
_autodiscover._tcp      86400   SRV     0 0 443 mail.example.com.

-- CalDAV / CardDAV autodiscovery (optional) --
_caldav._tcp            86400   TXT     "https://mail.example.com/dav"
_caldav._tcp            86400   SRV     0 0 443 mail.example.com.
_caldavs._tcp           86400   TXT     "https://mail.example.com/dav"
_caldavs._tcp           86400   SRV     0 0 443 mail.example.com.
_carddav._tcp           86400   TXT     "https://mail.example.com/dav"
_carddav._tcp           86400   SRV     0 0 443 mail.example.com.
_carddavs._tcp          86400   TXT     "https://mail.example.com/dav"
_carddavs._tcp          86400   SRV     0 0 443 mail.example.com.

-- Mail protocol service discovery, RFC 6186 (optional) --
_imap._tcp              86400   SRV     0 0 143 mail.example.com.
_imaps._tcp             86400   SRV     0 0 993 mail.example.com.
_pop3._tcp              86400   SRV     0 0 110 mail.example.com.
_pop3s._tcp             86400   SRV     0 0 995 mail.example.com.
_submission._tcp        86400   SRV     0 0 587 mail.example.com.
_submissions._tcp       86400   SRV     0 0 465 mail.example.com.

Notes:
- DKIM: run "manage-dkim.sh -domain example.com" on this server first, then
  use the actual TXT values it prints in place of the two placeholder
  lines above.
- DMARC starts at p=quarantine (recommended first step); once DKIM/SPF
  are confirmed passing for real mail, consider moving to p=reject.
- MTA-STS: run "manage-mta-sts.sh -domain example.com" on this server
  once the DNS above is live. Bump the "id=" value whenever the policy
  changes later.
- DANE: only recommended if your DNS provider can be updated
  automatically - see the full note the real command prints, and
  docs/dns-records-reference.md.
- After these records are live, verify with:
  check-dns.sh -domain example.com  (once this domain resolves here)
```

(The real output includes a few more notes - e.g. about a cosmetic
quirk in grommunio-admin's own MX-health indicator - trimmed here for
length. Run the command yourself to see the full text.)

Now you're ready to start the actual installation (section 3).

## 3. Installation walkthrough

Run `sudo ./server-setup.sh` and answer its prompts, or pass flags to
skip them. The sections below explain what each step actually does,
in order - **not everything you need to run by hand**, this is what
the one `server-setup.sh` command does internally, step by step, so
you know what to expect and how to verify each part afterward.

```
./server-setup.sh --help
```

```
server-setup.sh

Orchestrator for building a mail server from a clean Debian 13 install.
Sources every functions/*.sh in numeric-filename order, then calls each
step's step_<name> function in that same order, stopping on the first
failure.

Usage:
  sudo ./server-setup.sh [--domain example.com] [--hostname mx1]
                         [--no-grommunio-setup]

  --domain <domain>       Pre-fills step 10's hostname/domain prompt (and,
                          through it, step 31's domain-to-create) - skips
                          being asked interactively. Combine with
                          --hostname for the full FQDN (<hostname>.<domain>).
  --hostname <name>       Same, for the hostname half.
  --no-grommunio-setup    Stop BEFORE step 30 (the grommunio-setup
                          wizard) instead of running it - for running
                          that wizard by hand (interactively, or because
                          it already ran once and its own "already
                          completed" branch would otherwise ask to wipe
                          everything via removealldata). The script
                          prints the exact command to resume with
                          afterwards (START_AT=<next step>).
```

### Running `grommunio-setup` yourself with `--no-grommunio-setup`

Step 30 is the one step this project deliberately does **not** try to
automate (see that step's own entry below for why) - if you'd rather
run the official wizard yourself instead of letting `server-setup.sh`
launch it, stop right before it:

```
sudo ./server-setup.sh --domain example.com --hostname mail --no-grommunio-setup
```

```
############################################################
# Stopping before step: 30-grommunio-setup (--no-grommunio-setup)
############################################################

Two ways to continue, depending on what you want:

  1) Let this script run grommunio-setup after all: just run it
     again WITHOUT --no-grommunio-setup. Step 10 will not ask
     again (replayed from its saved config), and the script will
     naturally reach and run step 30-grommunio-setup this time.

       sudo ./server-setup.sh

  2) Run grommunio-setup yourself (interactively, or however you
     prefer), then skip past it here and resume from the next
     step:

       sudo START_AT=31 ./server-setup.sh

     (--domain/--hostname do not need to be repeated either way -
     step 10 already saved them for replay.)
```

Once you've run `grommunio-setup` by hand (and it's finished
successfully), use the exact command the script just printed to
resume - option 2 above:

```
sudo START_AT=31 ./server-setup.sh
```

This skips every step numbered below 31 (they already ran and saved
their own state before the stop) and picks back up at step 31 - the
mail domain creation - continuing normally from there through to the
end. The `31` isn't a fixed number to memorize: it's computed fresh
from whatever step actually comes right after grommunio-setup in
`functions/`, so trust whatever the script's own output says over
this example if the two ever disagree (e.g. after this project adds
or renumbers a step in a later version).

---

### Step 10 — Network & hostname

**What it does:** detects the server's own primary IPv4/IPv6 address
and asks for (or re-derives) the FQDN this server should identify as,
then configures that via `systemd-networkd` and sets `/etc/hostname`
and `/etc/hosts` to match.

**Why:** this hostname becomes Postfix's own identity (HELO/EHLO) and
is checked against the PTR record you confirmed in section 2 - a
mismatch here is one of the most common reasons outbound mail from a
new server gets rejected or spam-flagged by other providers.

**Result:** `hostnamectl` shows the FQDN you confirmed; `resolvectl
query <that FQDN>` resolves back to this server's own IP (the same
forward-confirmation check `check-dns.sh --firstdomain` already did in
section 2, now re-verified against what this step actually configured).

---

### Step 15 — Locale & timezone

**What it does:** asks for the system default locale (`en_US.UTF-8`
recommended) and which additional languages to generate (every
language grommunio Web itself supports is offered), then confirms the
timezone and makes sure the clock is NTP-synced.

**Why:** a wrong system clock breaks TLS certificate validation,
Let's Encrypt issuance, log timestamps and fail2ban ban durations -
small to set up, expensive to debug later if it's wrong.

**Result:** `timedatectl` shows `System clock synchronized: yes` and
the correct timezone; `locale -a` lists every language you chose.

---

### Step 18 — SSH hardening

**What it does:** two small tweaks on top of Debian 13's already
strong OpenSSH 10 defaults - restricts the MAC algorithms to
encrypt-then-MAC/SHA-2 variants only, and turns off X11 forwarding
(this is a headless mail server; `AllowTcpForwarding` stays on, since
that's used for unrelated SSH tunnelling).

**Why:** Debian 13's own OpenSSH defaults are already strong (modern
ciphers, post-quantum hybrid key exchange, no legacy ssh-rsa/SHA-1) -
this step only closes a couple of narrow fallback paths rather than
fixing something actually broken.

**Result:** `sshd -T | grep -i macs` shows only ETM/SHA-2 entries;
`ssh -v` to the server no longer offers X11 forwarding.

---

### Step 20 — Firewall & fail2ban

**What it does:** installs a firewall (firewalld by default, matching
grommunio's own documented setup - ufw is offered as an alternative)
plus fail2ban, and locks SSH down to a whitelist of IPs (your current
session's IP is always detected and included automatically) *before*
anything else is opened.

**Why:** doing this first, before any other port is opened, avoids a
window where the server is reachable but not yet protected. The
whitelist step is the one prompt in the whole installer that is never
silently skipped on a replay, specifically so a stale list can't lock
out whoever is running the replay.

Also enables `recidive` - a jail that watches fail2ban's own ban log
(not a service log) and escalates any IP repeatedly banned by *any*
other jail to a much longer ban. See
[`docs/fail2ban-jails-reference.md`](fail2ban-jails-reference.md) for
the full jail list this framework ends up with once every later
fail2ban step has also run.

**Result:** `firewall-cmd --list-all` (or `ufw status`) shows SSH
allowed only from your whitelist; `fail2ban-client status` shows the
`sshd` and `recidive` jails active.

---

### Step 21 — Base packages

**What it does:** installs a small set of general-purpose tools
(`gnupg`, `ca-certificates`, `curl`, `wget`, `dnsutils`, `lsb-release`,
`apt-transport-https`, `ipset`) that later steps rely on.

**Why:** step 25 (next) needs `gpg` to import grommunio's repository
signing key - this just makes sure the basics are present before
anything repo- or grommunio-specific happens.

**Result:** no visible change - just confirms the listed commands
exist (`command -v gpg`, etc.).

---

### Step 25 — Where packages come from

**What it does:** always adds the APT source and signing key for
grommunio's **community package repository**
(`download.grommunio.com`, `Debian_13` suite) - that part is never
skipped, regardless of which option you pick below. The choice is
only about whether a *second* source gets layered on top of it:

1. **Community only** (option 1, default) - just the above, nothing
   else. The right choice unless you specifically have your own
   rebuilt package pool to layer on top - option 2's local file repo
   does not exist on a fresh server.
2. **Community + your own rebuilt packages** (option 2) -
   additionally registers a local, file-based repo (a package pool
   you've copied onto this server yourself) and pins it *above*
   community via APT preferences (`Pin: release o=personal-build`,
   priority 900 - matching a unique `Origin:` this repo's own
   generated `Release` file sets, not a bare "local source" match,
   which turned out to also match Debian's own base/backports sources
   when configured via a `mirror+file://` URI). This is selective and
   automatic: whatever package names actually exist in your local
   pool resolve from there; every other package - `grommunio-setup`,
   `grommunio-chat-v10`, `grommunio-auth`, everything - still resolves
   from community, with no list of package names to maintain by hand.
   This step verifies both halves after `apt-get update`: that
   `grommunio-setup`'s candidate still comes from community, and that
   one package from your local pool actually resolves from there (not
   silently shadowed by a higher community version - priority wins
   over version number here, so a stale local pool is still preferred,
   which is itself a reason to keep it refreshed).

**Why:** this is the one step with a real choice in it - see the box
below for when option 2 is actually useful.

**Result:** `apt-cache policy grommunio-setup` shows a candidate
version coming from `download.grommunio.com` either way; if using
option 2, `apt-cache policy <your-package>` shows its candidate coming
from `file://<your repo dir>` instead, at priority 900 in the version
table; `apt-get update` runs without errors.

> **Using the author's own rebuilt packages too?** A small number of
> packages in this stack are maintained as separate, independent
> rebuilds rather than taken from the community repo as-is. This is
> **entirely optional** and not needed for a working install - choose
> option 1 above and skip straight to Step 30 unless you specifically
> want this. See [`custom-repo/README.md`](custom-repo/README.md) for
> how to set up the local pool option 2 expects. A couple of these are
> kept private - personal, modified-for-own-use builds, not part of
> this public path at all (see that page's own note).

---

### Step 30 — grommunio-setup (the official wizard)

**What it does:** installs `grommunio-setup` and launches its own
interactive dialog wizard - this step hands control to *you* for the
actual questions (FQDN, domain, TLS choice, mail relay), rather than
trying to drive the dialog UI automatically. One thing it does
automate: installing `mariadb-client` beforehand, which works around
a real bug in the package's own "remove all data and reinstall" path
that otherwise crashes with `mysql: command not found` on a clean box.

**Why:** an interactive wizard is genuinely the right tool here - this
project adds everything *around* it (DNS, DANE, WAF, SSO, backups),
not a replacement for it.

**Result:** the wizard reports success; `grommunio-admin domain list`
shows your domain; webmail is reachable at `https://<FQDN>/web` (still
using the wizard's own default TLS/cert choice at this point - step 34
is what points Postfix/nginx at the real Let's Encrypt certificate if
that wasn't already done).

---

### Step 31 — Mail domain & admin hub mailbox

**What it does:** creates the mail domain in grommunio via the
`grommunio-admin` CLI (the wizard's own dialog doesn't do this), and -
for whichever domain turns out to be this server's own canonical
hostname (see the box below) - creates a shared `admin@<domain>`
mailbox with `postmaster`/`hostmaster`/`root`/`webmaster`/`abuse`/
`security` aliases pointing at it, so those standard addresses are
never dead ends. Also fixes grommunio-admin's own stock mailbox-quota
defaults, which are internally inconsistent out of the box
(send/receive both blocked at 150 MiB while the nominal hard limit
sits at ~9.8 GiB and is never actually reached) - replaced with a
single consistent staircase (9 GiB send / 9.5 GiB receive / 10 GiB
hard limit). Only affects mailboxes created *after* this runs -
grommunio-admin reads this default fresh at creation time, never
retroactively.

**Why:** without a domain, later steps (like the test mailbox in step
45) fail outright with "Invalid domain." The admin hub mailbox exists
because RFC 2142 expects those addresses to work, and because some of
this project's own tooling (e.g. the protected-package upgrade alert
from `install-unattended-upgrades.sh`) mails `hostmaster@` and expects
it to actually be read by someone. The quota fix closes a real,
found-by-reviewing-every-default gap - not a hypothetical one.

**Result:** `grommunio-admin domain list` shows the new domain active;
mail to `postmaster@<domain>` lands in the admin hub mailbox.

> **A dedicated `mx1.<domain>` hostname, if needed:** if this domain's
> `mail.<domain>` happens to be the exact same hostname step 10 gave
> this server (common, but not guaranteed - depends on what your
> hosting provider's PTR record says), this step tells you so and
> explains why: DANE (TLSA records, set up later via
> `manage-dane.sh`) is keyed on the MX hostname, so a shared
> `mail.<domain>` would force the same DANE policy onto every other
> domain sharing it. See `docs/dns-records-reference.md` for the full
> reasoning - nothing to act on yet at this point, just something to
> be aware of before you get to DANE.

---

### Step 32 — gromox services, TLS enforcement & small default fixes

Two separate, independent scripts run at this point:

**`32-gromox-services.sh`**:
- Disables the `gromox-istore` unit when nothing actually needs it
  (the community package enables it by default, but it only does
  anything when `gromox.cfg` sets `istore_standalone` - otherwise it
  just fails on every boot with a harmless but noisy error).
- **Enforces IMAP/POP3 TLS.** The community default only *offers*
  STARTTLS/STLS on `gromox-imap`/`gromox-pop3` - it never *requires*
  it, so a plaintext login is silently accepted if a client simply
  doesn't upgrade. This sets `imap_support_tls=yes` +
  `imap_force_tls=yes` (and the same pair for POP3), which gromox
  requires together - `force_tls=yes` alone is rejected at startup.
- **Excludes CBC-mode TLS cipher suites** on `gromox-imap`,
  `gromox-pop3`, `gromox-http` and `gromox-delivery-queue`, via a
  scoped `OPENSSL_CONF` (gromox has no native cipher-list setting for
  these daemons, unlike nginx/Postfix - this is the only way to
  remove CBC from what they offer).
- Migrates five deprecated per-daemon `listen_port`/`listen_ssl_port`
  settings (in `http.cfg`/`imap.cfg`/`pop3.cfg`/`smtp.cfg`) into the
  equivalent `gromox.cfg` keys, matching current gromox's own
  deprecation warnings.

**`32-grommunio-optimizations.sh`** is a small home for narrow,
independent default-tuning fixes that don't warrant their own step
number - currently: marking LDAP as explicitly disabled when this
server doesn't use it (removes a cosmetic but recurring `[ERROR]` log
line), and raising webmail's own attachment-upload size limit to
150MB (PHP-FPM's defaults are 2MB/8MB, far below what grommunio Web
itself is capable of handling - see step 39's matching ModSecurity
body-size fix, both need to agree).

**Why:** the TLS-enforcement and CBC-exclusion fixes close a real gap
- plaintext IMAP/POP3 login being silently accepted is a genuine
security issue, not just a rough edge. The rest are "the official
installer leaves a rough edge here" fixes - cleans up noise, removes
an artificially low limit, and keeps config in the location gromox
itself says it should be.

**Result:** `grep -E 'force_tls|support_tls' /etc/gromox/imap.cfg
/etc/gromox/pop3.cfg` shows both set to `yes`; an IMAP client that
tries a plaintext login without STARTTLS is now rejected, not
silently accepted; `OPENSSL_CONF=/etc/gromox/openssl-no-cbc.cnf
openssl ciphers -v` lists no CBC suites; `systemctl status
gromox-istore` shows it disabled (if it was ever an issue here);
`grep ldap_disabled /etc/gromox/ldap_adaptor.cfg` shows `true`;
uploading a >8MB attachment in webmail's compose window now works.

---

### Step 33 — nginx sites

**What it does:**
- Removes Debian's own default nginx site (which conflicts with
  grommunio's catch-all vhost over the same `server_name _` - without
  this, requests to unrecognized hostnames got Debian's welcome page
  instead of grommunio's own catch-all behavior).
- Writes an AEAD-only (GCM/ChaCha20), post-quantum-hybrid-capable TLS
  cipher config applied to every vhost.
- **Fixes a real gap on admin-web (port 8443) specifically**:
  `grommunio-admin-common` ships its own, separate SSL params file
  included only by the admin-web server block, with an older, weaker
  cipher list (two CBC-mode suites) and `TLSv1`/`TLSv1.1` still
  enabled - bypassing the hardened config above entirely. Confirmed
  with `testssl.sh`: 8443 offered CBC and TLSv1/1.1 while 443 (the
  main site) did not. This step edits that package-shipped file
  directly to match.
- Creates a missing `manifest.webmanifest` for grommunio Web (the
  package never ships one; nginx returned a 404 on every page load
  without it).

**Why:** this is literally in grommunio's own community install
instructions, but easy to miss since there's no dedicated step for it
in the wizard itself. The admin-web cipher gap is a real, independently
discovered security issue - a separate included file silently escaping
the server's main TLS hardening, not a cosmetic difference.

**Result:** `nginx -t` shows no "conflicting server name" warning;
`curl -k https://<server-ip>/` (using the IP, not a real hostname)
gets grommunio's own catch-all response, not Debian's welcome page;
`testssl.sh <FQDN>:8443` no longer offers CBC or TLSv1/1.1, matching
port 443.

---

### Step 34 — grommunio Chat, Postfix hardening & Postfix TLS

Three separate scripts:

**`34-grommunio-chat.sh`** - optional (asks first, default no).
Installs grommunio Chat v10 (Mattermost-based) on PostgreSQL if you
want it, including Keycloak SSO via grommunio's own official adaptor
path, and turns off the bundled AI plugin (its license check fails
without a Mattermost license - everything else works fine unlicensed).

**`34-postfix-hardening.sh`** - eleven settings total,
`grommunio-setup` leaves every one of them at Debian's/Postfix's own
plain defaults:
- `disable_vrfy_command` - VRFY lets anyone probe whether an address
  exists (account-enumeration risk).
- `smtpd_sender_restrictions` += `reject_unknown_sender_domain` -
  rejects mail claiming a sender domain with no valid DNS at all.
- `tls_ssl_options = NO_COMPRESSION` - CRIME-attack mitigation +
  anti-renegotiation.
- `show_user_unknown_table_name = no` - stops "user unknown" bounces
  leaking the internal lookup-table name to external senders.
- `allow_percent_hack = no` / `swap_bangpath = no` - close two old
  relay tricks (`user%domain`/`user!domain` addressing bypassing
  checks).
- `message_size_limit` raised to 150MB (from Debian's 10MB default).
- `strict_rfc821_envelopes = yes` - rejects malformed envelope syntax.
- `delay_warning_time = 4h` - sender gets a "still queued" notice.
- `smtpd_client_restrictions` - **was completely empty: no reverse-DNS
  (PTR) check on connecting clients at all.** Now rejects unknown/
  non-resolving client hostnames, with `permit_mynetworks`/
  `permit_sasl_authenticated` ordered first so authenticated senders
  never hit the PTR check.
- `smtpd_helo_restrictions` += `reject_unknown_helo_hostname`.

Deliberately left alone (the operator's own call, not an oversight):
`milter_default_action=accept` (fail-open if rspamd is ever
unreachable - see step 35's own relay-restriction fix, which exists
specifically because of this).

**`34-postfix-tls.sh`** - also far more than a certificate check:
- Makes sure Postfix's STARTTLS certificate is actually the real
  Let's Encrypt one (found live once that `grommunio-setup` hadn't
  applied this, leaving Postfix offering a self-signed snakeoil
  certificate instead).
- **Fixes a real upstream bug that silently breaks on every future
  renewal**: grommunio's own setup symlinks the cert bundle (so
  renewals are picked up automatically) but *copies* the private key
  instead - and nothing ever refreshes that copy again. Every
  `certbot renew` after the first one leaves a stale key, breaking
  nginx/Postfix/gromox-http/imap/pop3 all at once (a cert/key
  mismatch). Fixed by comparing content on every run of this step
  *and* a new certbot deploy-hook that re-syncs the key on every
  renewal going forward (see `manage-certs.sh`'s own docs for the
  deploy-hook side).
- Hardens Postfix's own TLS protocol/cipher policy (TLS 1.2+ only, no
  CBC ciphers) to match nginx and gromox-imap/pop3 - Postfix's
  defaults otherwise still offered deprecated TLS 1.0/1.1 and CBC,
  flagged as "potentially VULNERABLE to LUCKY13" by an external scan.
  Applied once in `main.cf`, covering ports 25/587/465 uniformly. Sets
  `smtpd_tls_loglevel=1` too (Postfix's own default is 0) - one
  summary line per connection (protocol, cipher, key-exchange,
  signature), useful for spotting a real client compatibility problem
  without the much noisier per-record dumps higher levels add.
- Blocks SHA-1 as a TLS 1.2 signature algorithm, prompted by an
  external mail-security scan report - verified live with a
  SHA-1-only TLS offer actually failing and a SHA-256 offer still
  working.
- Enables **postscreen** on port 25 - a cheap pre-SMTPD triage layer
  (PREGREET, pipelining, non-SMTP command, bare newline) that rejects
  obviously-broken/bot connections before they ever reach Postfix
  proper. Deliberately not applied to submission/submissions (587/465)
  - those are authenticated-client ports postscreen's tests must never
  see.
- Sets up outbound MTA-STS enforcement (Postfix validating *other*
  servers' MTA-STS policies when sending to them - the reverse
  direction from your own domain's own MTA-STS policy, which
  `manage-mta-sts.sh` sets up later).

**Why:** each of these is a real, confirmed gap between what
`grommunio-setup` does and what a production mail server actually
needs - not hypothetical hardening. Several were found via external
security scans against a live, already-deployed instance of this
framework, not written speculatively.

**Result:** `openssl s_client -starttls smtp -connect <FQDN>:25` shows
the real Let's Encrypt certificate, not snakeoil, and no longer offers
TLS 1.0/1.1, CBC ciphers, or a SHA-1 signature; `postconf
disable_vrfy_command` returns `yes`; `postconf smtpd_client_restrictions`
is no longer empty; `postconf -M | grep postscreen` shows it wired to
`smtp:25` only; (if Chat was installed) `https://<FQDN>/chat` loads
and SSO login works.

---

### Step 35 — SMTP AUTH (saslauthd)

**What it does:** starts and enables the `saslauthd` daemon, then
goes well beyond that single fix:
- Creates the `submission` (587, STARTTLS) listener if missing,
  matching grommunio-setup's own documented recipe exactly - found
  live with only a hand-added `submissions` (465) block present and
  587 missing entirely, even though grommunio's own docs/DNS checks
  treat 587 as the baseline and 465 as an optional addition.
- Creates the `submissions` (465, implicit TLS / RFC 8314) listener
  if missing, mirroring `submission` with implicit instead of
  opportunistic TLS.
- **Closes a real unauthenticated-relay gap on 587**: without
  `submission`'s own `permit_sasl_authenticated,reject`, an
  unauthenticated client could `MAIL FROM`/`RCPT TO` a local mailbox
  over 587 and only get rejected by rspamd's milter - not by Postfix
  itself (the global `permit_mynetworks` chain would let a loopback
  connection through). A confirmed `milter_default_action=accept`
  fail-open during an rspamd outage would have let that mail relay
  through unauthenticated. Fixed by giving both `submission` and
  `submissions` their own narrow recipient restriction, so this no
  longer depends on the milter being up.
- Sets both listeners to `chroot=y` (matching Debian's own stock
  default) and bind-mounts saslauthd's socket into the chroot jail if
  needed (same pattern as the existing MySQL-socket bind mount for
  `smtp:25`).
- Fixes SASL mechanisms: grommunio-setup writes a `mech_list`
  including `CRAM-MD5`/`DIGEST-MD5`, which PAM-backed `saslauthd`
  cannot actually perform - narrowed to `LOGIN PLAIN` (safe since both
  listeners require TLS).

**Why:** `grommunio-setup` correctly configures *most* of what SMTP
AUTH needs but never starts `saslauthd` itself - a real, confirmed gap
(grommunio's own post-install checklist lists it as an expected
running service). The listener/relay-restriction fixes close a second,
independent gap found the same way: config that looked complete but
left an authenticated-only port reachable without authentication under
a specific failure condition.

**Result:** `systemctl status saslauthd` is active; `postconf -M |
grep -E 'submissions?\s'` shows both 587 and 465 listeners; a mail
client configured for SMTP AUTH can send mail on either port; an
unauthenticated `MAIL FROM`/`RCPT TO` attempt on 587 is rejected by
Postfix itself, not left to rspamd's milter.

---

### Step 36 — fail2ban: mail & web jails

**What it does:** enables 11 jails covering Postfix (SASL brute-force,
general abuse patterns, SMTP AUTH including a subnet-aggregating jail
for distributed attacks, postscreen rejects) and nginx (bot/scan
patterns, the catch-all vhost, malformed requests, admin-web's SPA,
oversized request bodies). See
[`docs/fail2ban-jails-reference.md`](fail2ban-jails-reference.md) for
the full table - every jail's watch target, tuning, and how several of
them relate to each other (e.g. the subnet-aggregating jail layered on
top of the per-IP one).

**Why:** found live via a post-reboot log sweep - Postfix's submission
port was already seeing hundreds of automated SASL brute-force
attempts with nothing banning them, since step 20 only protects SSH.
Every `bantime`/`findtime` that isn't a simple round number was tuned
against real attacker pacing found during a full-log evasion sweep,
not picked speculatively.

**Result:** `fail2ban-client status` lists all 11 jails from this
step as active; `fail2ban-client status <jail-name>` shows real ban
activity over time as scans happen.

---

### Step 37 — fail2ban: gromox/grommunio jails

**What it does:** adds 7 more jails for everything still uncovered
after step 36: IMAP, POP3, WebDAV/CalDAV/CardDAV, ActiveSync,
grommunio Web's own login form, the admin API, and the generic gromox
HTTP auth path (EWS/RPC/OAB/Autodiscover) - full details in the same
[`docs/fail2ban-jails-reference.md`](fail2ban-jails-reference.md)
table as step 36.

**Why:** each of these is a real authentication endpoint exposed to
the internet - without a dedicated jail, a brute-force attempt against
any one of them runs unopposed.

**Result:** `fail2ban-client status` lists a jail per service above
(20 jails total across steps 20/36/37), each showing real ban activity
over time as scans happen.

---

### Step 38 — Antispam (rspamd)

**What it does:** installs and configures `grommunio-antispam`
(rspamd under the hood) wired into Postfix via milter, generates DKIM
keys for each active domain (signed twice - Ed25519 and RSA, two
selectors), and points the server at its own local DNS resolver
(needed for rspamd's own DNS-based checks - SPF, DKIM, DNSBLs,
`mx_check`/`known_senders` - to be fast and not depend on an upstream
resolver's rate limits). Well beyond the base setup, it also:
- **Fixes virus handling.** grommunio-setup's own antivirus config has
  a nesting bug that fails rspamd's config test, and even once fixed,
  a confirmed virus only added a small score contribution - verified
  live with a real EICAR test file sailing through completely
  unflagged. Now a virus hit is a hard, immediate `reject`.
- **Fixes two real pipeline gaps that left scored mail invisible**:
  `milter_headers`' `X-Spam-Flag` routine name was wrong (never
  fired), and nothing told gromox to actually move a flagged message
  to Junk (`lda_junk_rules` in `gromox.cfg`) - without both, a message
  could be correctly scored as spam yet still land in the Inbox with
  no visible marker.
- **Adds a local sender whitelist/blacklist**, gated by more than a
  bare domain match: a blacklist hit is an immediate reject; a
  whitelist hit only gets its strong score discount through a
  composite rule that also requires a *passing* SPF/DKIM check. An
  earlier, naive whitelist (plain domain-name match) was found to make
  spoofing a whitelisted domain *easier*, not safer, and was fixed the
  same day.
- **Disables greylisting.** The module forces its own temporary-reject
  action independent of the normal score path - `enabled = false`
  alone does nothing, confirmed live; disabling it needed the
  documented settings-module workaround.
- Adds a Redis-backed sender-reputation module (IP/SPF/DKIM history)
  and disables one DNSBL (`senderscore_reputation`) found permanently
  exhausted/unusable.
- **Installs the TRAIN-HAM ham-training loop**: `grommunio-ham-run`
  learns a `TRAIN-HAM` folder as ham on an interval (4h, widened from
  the package's 30min default). grommunio-admin has no hook to create
  this folder for a new user automatically, so this step also installs
  `ensure-train-ham-folders.sh` as both a one-time pass (every
  currently-active user) and a daily systemd timer (every user created
  afterward) - found live 2026-10-28 that 0 of 19 users on a fresh
  testvps had the folder, since all had been created/restored after
  the one-time pass last ran.

**Known, unmitigated risk**: a false-positive `add_header` match gets
reinforced as *confirmed* spam the next night by the same ham/spam
training run, if the message isn't moved out of Junk first - not
fixed, only documented. Check Junk folders for false positives
occasionally.

**Why:** grommunio-setup's own wizard does not configure the base
antispam setup at all - without this step, inbound mail is never
scored for spam, and outbound mail is never DKIM-signed. Everything
above that base setup is a real, confirmed gap found by actually
testing the pipeline end-to-end (a real virus, a real spoofing
attempt, a real new user), not speculative hardening.

**Result:** `systemctl status grommunio-antispam` is active;
`rspamc stat` reports normally; a real test message shows
`X-Rspamd-*` headers and a `DKIM-Signature` header on outbound mail; a
real EICAR test is hard-rejected, not just scored; `systemctl
is-enabled ensure-train-ham-folders.timer` shows `enabled`. Run
`./manage-dkim.sh --validate` afterward to confirm the DKIM DNS
records you were given in section 2's report are actually published.

---

### Step 39 — ModSecurity (WAF)

**What it does:** puts ModSecurity (OWASP Core Rule Set) in front of
every nginx vhost - webmail and every grommunio component alike - and
switches it from the package's own default `DetectionOnly` mode to
actually blocking. Ships with a growing set of scoped exclusions for
real false positives found live (CRS's generic rules don't know about
WebDAV uploads, ActiveSync's content types, etc. - see the file's own
`id:9000001`-and-up comments for the full, ongoing list and exactly
why each one exists). Also raises `SecRequestBodyLimit`/
`SecRequestBodyNoFilesLimit` to 150MB, matching step 32's webmail
upload limit and Postfix's own `message_size_limit` - without this, a
large WebDAV file upload was being silently blocked by ModSecurity's
own much lower package default (found live via a real failed upload
from a phone/tablet client).

**Why:** a mail/groupware stack exposes a lot of authenticated HTTP
surface (webmail, admin API, WebDAV, EAS, EWS) - a WAF catches generic
web attacks (SQLi, XSS, path traversal) none of the other hardening
steps are about.

**Result:** `systemctl status nginx` is active with ModSecurity
loaded (`journalctl -u nginx` shows `ModSecurity-nginx ... rules
loaded`); normal use of every grommunio component keeps working
(if something legitimate gets blocked, that's exactly what the scoped
exclusions mechanism in this file is for - see its own comments for
the pattern to extend it).

---

### Step 40 — Keycloak SSO

**What it does:** installs Keycloak, creates a dedicated realm, and
wires grommunio Web into it as an OpenID Connect client - including a
few claim-mapper and user-profile fixes the official setup scripts
don't apply on their own (see the script's own header comments for
exactly which ones and why, if you're curious).

**Why:** this is what lets every grommunio component (Web, Chat,
Files, Archive) share one login and one place to configure per-user
MFA, instead of each having its own separate account system.

**Result:** logging into grommunio Web redirects through Keycloak's
own login page and back; `./manage-mfa.sh --status <user>` shows
MFA as available (opt-in) for that account.

---

### Step 45 — grommunio Files

**What it does:** installs and configures grommunio Files
(Nextcloud-based):
- Always exports `DEBIAN_FRONTEND=noninteractive` explicitly and
  preseeds every debconf value its installer needs *before*
  installing - found live that without this, the package's own
  postinst can hang completely (over an hour, surviving even a
  session restart) waiting on a password prompt that never arrives
  over a non-interactive SSH session.
- Grants `privFiles` to the `admin` account (a per-user attribute
  neither grommunio-setup nor the package itself sets for anyone) -
  without it, even the admin account can't use Files. Any other
  mailbox that needs Files access needs the same flag set by hand
  (`grommunio-admin user modify <user> --privFiles true`).
- Sets `PLUGIN_FILES_USER_DEFAULT_ENABLE` to `true` in grommunio Web's
  own config - the system-wide gate that gives newly created users
  the Files app at all.
- **Fixes a real upstream bug that leaves Files completely inert
  after the first boot**: the package's own
  `grommunio-files-cron.timer` ships with only `OnBootSec=120` in its
  `[Timer]` section - no repeat interval at all. Nextcloud's own
  `cron.php` needs to run every few minutes for trash cleanup,
  sharing, and notifications to work; with the stock unit it instead
  runs exactly once, 2 minutes after boot, and never again. Confirmed
  live: 3 days of total inactivity on a server that had been rebooted
  only once in that window. Fixed with a drop-in adding
  `OnUnitActiveSec=5min`, leaving the package's own `OnBootSec=120`
  alone.

**Why:** the debconf hang and the `privFiles`/plugin-enable gaps are
real, reproducible packaging gaps - the fix has to happen before/
during install, not after. The cron-timer bug is the most consequential
of the three: without it Files silently stops doing anything useful
shortly after the one boot it was installed on, with no error anywhere
to point at the cause.

**Result:** `https://<FQDN>/files` loads and logs in with the same
grommunio credentials; `systemctl status php8.4-fpm` shows the
`pool-grommunio-files` pool active; `systemctl show
grommunio-files-cron.timer -p NextElapseUSecRealtime` shows a real,
near-future scheduled run, not empty.

---

### Step 46 — grommunio Files SSO

**What it does:** adds Keycloak/OIDC SSO to grommunio Files
(Nextcloud's `user_oidc` app) as an *additional* login method
alongside the existing username/password form - both keep working.
Always passes `--unique-uid=0` to the setup command.

**Why:** found and avoided live - the app's own default
(`uniqueUid=true`) would make a user's first SSO login silently
create a brand-new, disconnected account under a hashed ID, invisible
to and disconnected from their real, already-provisioned account and
files. `--unique-uid=0` keeps the Nextcloud user ID matched to the
real username instead.

**Result:** a "Login with grommunio" option appears on the Files
login page; logging in that way reaches the *same* account as the
existing username/password login, not a new empty one.

---

### Step 50 — grommunio Archive

**What it does:** installs grommunio Archive (Piler-based email
archiving) and runs its own `grommunio-archive-setup` CLI tool -
creates its database, two archive-only web accounts (`admin@local`,
`auditor@local`, passwords shown once and logged, then the log file
deleted automatically once you've seen them), and wires Postfix with
a transport map + pcre header rule that can route a message to the
archive SMTP listener. `grommunio-archive-setup` itself turns on
`always_bcc` (archive *every* message, server-wide) as its own
default, but this step then explicitly **unsets `always_bcc` right
after** - archiving is opt-in **per mailbox**, not automatic, as of
2026-11-05 (the transport/pcre wiring stays either way; it's what
actually delivers a message once one is BCC'd, by whichever means).
To archive a specific mailbox: Admin UI → that user → SMTP tab →
E-Mail forward (CC mode) → destination `archive@<FQDN>` - there is no
CLI flag or scripting for this in grommunio-admin today.

**Why:** separate, deliberate design choice: unlike other grommunio
components, Archive isn't driven by debconf at all - its own setup
script is the documented way to configure it, so this step follows
that exactly rather than reimplementing it. Opt-in-per-user (instead
of archive-everyone) was a deliberate change from this step's own
original default, made because archiving every message server-wide
has real storage/compliance implications that shouldn't be silently
switched on for an operator who didn't ask for it.

**Result:** `systemctl status grommunio-archive-searchd
grommunio-archive-smtp grommunio-archive` are all active; `postconf -h
always_bcc` prints nothing (confirms opt-in-per-user, not
archive-everyone); a test email sent via a temporarily-reenabled
`always_bcc` shows up in the archive's own web UI, confirming the
capture/storage/indexing chain works end-to-end before handing control
back to opt-in mode. **Back up
`/etc/grommunio-archive/grommunio-archive.key` somewhere safe** -
without it, archived messages are permanently unreadable.

---

### Step 60 — Boot order

**What it does:** adds systemd drop-ins that order services correctly
relative to each other at boot (e.g. the admin API after MariaDB, not
before), and adds "readiness" units for the slow-starting ones
(Keycloak takes ~14s, Chat ~33s to actually open their port - without
ordering, nginx could get a request in before either was ready and
return a 502 right after boot).

**Why:** found live via exactly that symptom after a reboot - nothing
else in `grommunio-setup` or this project enforces any particular
start order, so without this step it only worked by chance.

**Result:** reboot the server; everything comes up cleanly with no
502s in the first few minutes, and `systemctl status` for every
service shows no "fallback to offline mode" style warnings.

---

That's every step `server-setup.sh` runs. Continue to section 4 below.

## 4. After installation

- Reboot once and re-verify (some changes - networking, firewall - are
  applied live but should also be confirmed to persist across a real
  boot).
- See the main [README](../README.md) for the standalone tools
  (`manage-certs.sh`, `manage-dane.sh`, etc.) you'll use afterward any
  time a domain is added or removed.
