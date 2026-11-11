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

**Result:** `firewall-cmd --list-all` (or `ufw status`) shows SSH
allowed only from your whitelist; `fail2ban-client status` shows the
`sshd` jail active.

---

### Step 21 — Base packages

**What it does:** installs a small set of general-purpose tools
(`curl`, `jq`, `gnupg`, etc.) that later steps rely on.

**Why:** step 25 (next) needs `gpg` to import grommunio's repository
signing key - this just makes sure the basics are present before
anything repo- or grommunio-specific happens.

**Result:** no visible change - just confirms the listed commands
exist (`command -v gpg`, etc.).

---

### Step 25 — Where packages come from

**What it does:** adds the APT source and signing key for grommunio's
**community package repository** (`download.grommunio.com`,
`Debian_13` suite) and nothing else.

**Why:** this is the one step with a real choice in it - see the box
below.

**Result:** `apt-cache policy grommunio-setup` shows a candidate
version coming from `download.grommunio.com`; `apt-get update` runs
without errors.

> **Using the author's own rebuilt packages instead?** A small number
> of packages in this stack are maintained as separate, independent
> rebuilds rather than taken from the community repo as-is. This is
> **entirely optional** and not needed for a working install - skip
> straight to Step 30 unless you specifically want this. See
> [`custom-repo/README.md`](custom-repo/README.md) for that separate
> path: it replaces *only* the packages that differ, on top of the
> same community repo, not instead of it. A couple of these are kept
> private - personal, modified-for-own-use builds, not part of this
> public path at all (see that page's own note).

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
never dead ends.

**Why:** without a domain, later steps (like the test mailbox in step
45) fail outright with "Invalid domain." The admin hub mailbox exists
because RFC 2142 expects those addresses to work, and because some of
this project's own tooling (e.g. the protected-package upgrade alert
from `install-unattended-upgrades.sh`) mails `hostmaster@` and expects
it to actually be read by someone.

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

### Step 32 — gromox services & small default fixes

Two separate, independent scripts run at this point:

**`32-gromox-services.sh`** disables the `gromox-istore` unit when
nothing actually needs it (the community package enables it by
default, but it only does anything when `gromox.cfg` sets
`istore_standalone` - otherwise it just fails on every boot with a
harmless but noisy error).

**`32-grommunio-optimizations.sh`** is a small home for narrow,
independent default-tuning fixes that don't warrant their own step
number - currently: marking LDAP as explicitly disabled when this
server doesn't use it (removes a cosmetic but recurring `[ERROR]` log
line), and raising webmail's own attachment-upload size limit to
150MB (PHP-FPM's defaults are 2MB/8MB, far below what grommunio Web
itself is capable of handling).

**Why:** both are "the official installer leaves a rough edge here"
fixes - neither changes how the mail stack actually behaves, just
cleans up noise and removes an artificially low limit.

**Result:** `systemctl status gromox-istore` shows it disabled (if it
was ever an issue here); `grep ldap_disabled /etc/gromox/ldap_adaptor.cfg`
shows `true`; uploading a >8MB attachment in webmail's compose window
now works.

---

### Step 33 — nginx sites

**What it does:** removes Debian's own default nginx site (which
conflicts with grommunio's catch-all vhost over the same `server_name
_` - without this, requests to unrecognized hostnames got Debian's
welcome page instead of grommunio's own catch-all behavior).

**Why:** this is literally in grommunio's own community install
instructions, but easy to miss since there's no dedicated step for it
in the wizard itself.

**Result:** `nginx -t` shows no "conflicting server name" warning;
`curl -k https://<server-ip>/` (using the IP, not a real hostname)
gets grommunio's own catch-all response, not Debian's welcome page.

---

### Step 34 — grommunio Chat, Postfix hardening & Postfix TLS

Three separate scripts:

**`34-grommunio-chat.sh`** - optional (asks first, default no).
Installs grommunio Chat v10 (Mattermost-based) on PostgreSQL if you
want it, including Keycloak SSO via grommunio's own official adaptor
path, and turns off the bundled AI plugin (its license check fails
without a Mattermost license - everything else works fine unlicensed).

**`34-postfix-hardening.sh`** - two small, low-risk settings
`grommunio-setup` leaves at Debian's plain defaults: turns off the
`VRFY` command (lets anyone probe whether an address exists -
account-enumeration risk) and adds `reject_unknown_sender_domain` to
`smtpd_sender_restrictions` (rejects mail claiming to be from a sender
domain with no valid DNS at all - cuts spoofing/backscatter with
essentially no risk to real senders).

**`34-postfix-tls.sh`** - makes sure Postfix's STARTTLS certificate is
actually the real Let's Encrypt one (found live once that
`grommunio-setup` hadn't applied this, leaving Postfix offering a
self-signed snakeoil certificate instead), and sets up outbound
MTA-STS enforcement (Postfix validating *other* servers' MTA-STS
policies when sending to them, the reverse direction from your own
domain's own MTA-STS policy which `manage-mta-sts.sh` sets up later).

**Why:** each of these is a real, confirmed gap between what
`grommunio-setup` does and what a production mail server actually
needs - not hypothetical hardening.

**Result:** `openssl s_client -starttls smtp -connect <FQDN>:25` shows
the real Let's Encrypt certificate, not snakeoil; `postconf
disable_vrfy_command` returns `yes`; (if Chat was installed)
`https://<FQDN>/chat` loads and SSO login works.

---

### Step 35 — SMTP AUTH (saslauthd)

**What it does:** starts and enables the `saslauthd` daemon.

**Why:** `grommunio-setup` correctly configures *everything else* SMTP
AUTH needs (the PAM module, the SASL config, `/etc/default/saslauthd`)
but never actually starts the daemon itself - a real, confirmed gap
(grommunio's own post-install checklist lists `saslauthd` as an
expected running service). Without it, no mail client can
authenticate to send mail via the submission port at all.

**Result:** `systemctl status saslauthd` is active; a mail client
configured for SMTP AUTH (port 587) can actually send mail.

---

### Step 36 — fail2ban: mail & web jails

**What it does:** enables two stock fail2ban jails that ship with
fail2ban itself but aren't on by default: `postfix-sasl` (brute-force
attempts against SMTP AUTH) and `nginx-botsearch` (generic bad-request
scanning against nginx).

**Why:** found live via a post-reboot log sweep - Postfix's submission
port was already seeing hundreds of automated SASL brute-force
attempts with nothing banning them, since step 20 only protects SSH.

**Result:** `fail2ban-client status postfix-sasl` and `... status
nginx-botsearch` both show as active jails.

---

### Step 37 — fail2ban: gromox/grommunio jails

**What it does:** adds fail2ban protection for everything still
uncovered after step 36: IMAP, POP3, WebDAV/CalDAV/CardDAV,
ActiveSync, grommunio Web's own login form, the admin API, and the
generic gromox HTTP auth path (EWS/RPC/OAB/Autodiscover).

**Why:** each of these is a real authentication endpoint exposed to
the internet - without a dedicated jail, a brute-force attempt against
any one of them runs unopposed.

**Result:** `fail2ban-client status` lists a jail per service above,
each showing real ban activity over time as scans happen.

---

### Step 38 — Antispam (rspamd)

**What it does:** installs and configures `grommunio-antispam`
(rspamd under the hood) wired into Postfix via milter, generates DKIM
keys for each active domain, and points the server at its own local
DNS resolver (needed for rspamd's own DNS-based checks - SPF, DKIM,
DNSBLs - to be fast and not depend on an upstream resolver's rate
limits).

**Why:** grommunio-setup's own wizard does not configure this part at
all - without this step, inbound mail is never scored for spam, and
outbound mail is never DKIM-signed (so it's far more likely to be
rejected or junked by other providers).

**Result:** `systemctl status grommunio-antispam` is active;
`rspamc stat` reports normally; a real test message shows
`X-Rspamd-*` headers and a `DKIM-Signature` header on outbound mail.
Run `./manage-dkim.sh --validate` afterward to confirm the DKIM DNS
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
why each one exists).

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
(Nextcloud-based). Always exports `DEBIAN_FRONTEND=noninteractive`
explicitly and preseeds every debconf value its installer needs
*before* installing - found live that without this, the package's own
postinst can hang completely (over an hour, surviving even a session
restart) waiting on a password prompt that never arrives over a
non-interactive SSH session.

**Why:** this is a real, reproducible packaging bug, not a
hypothetical edge case - the fix has to happen before the package
installs, not after.

**Result:** `https://<FQDN>/files` loads and logs in with the same
grommunio credentials; `systemctl status php8.4-fpm` shows the
`pool-grommunio-files` pool active.

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
deleted automatically once you've seen them), and wires Postfix to
copy every message to the archive via `always_bcc`.

**Why:** separate, deliberate design choice: unlike other grommunio
components, Archive isn't driven by debconf at all - its own setup
script is the documented way to configure it, so this step follows
that exactly rather than reimplementing it.

**Result:** `systemctl status grommunio-archive-searchd
grommunio-archive-smtp grommunio-archive` are all active; a test email
shows up in the archive's own web UI shortly after being sent/received.
**Back up `/etc/grommunio-archive/grommunio-archive.key` somewhere
safe** - without it, archived messages are permanently unreadable.

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
