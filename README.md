# grommunio-hardened-setup

A one-shot, replay-safe provisioning framework that turns a clean Debian 13
install into a fully configured, hardened, multi-domain
[grommunio](https://grommunio.com/) mail server — plus a set of standalone
tools to keep it that way afterward.

This is an independent, community project. It is not affiliated with or
endorsed by grommunio GmbH.

## What makes this different from grommunio's own setup wizard

`grommunio-setup` gets the mail stack itself running. This framework picks
up from there and closes the gaps a production deployment actually needs:

- **DNS automation, not just a checklist** — DANE/TLSA records that
  re-publish themselves on every certificate renewal, MTA-STS policy +
  nginx wiring, DKIM key generation, and a DNS pre-flight tool
  (`check-dns.sh`) that tells you exactly what to set up, what's already
  live, and what's still missing — for a domain not even hosted here yet.
- **Correct multi-domain DANE** — detects when a domain's natural
  `mail.<domain>` MX target collides with the server's own canonical
  hostname (from its PTR record) and gives it an independent MX hostname
  automatically, so DANE never gets silently shared between domains.
- **Keycloak-native SSO** — grommunio Web, Chat, Files and Archive all
  wired into one Keycloak realm, including the claim-mapper and
  user-profile fixes the official adaptor scripts don't apply on their own.
- **A real WAF and brute-force defense** — ModSecurity (OWASP CRS) in
  front of every vhost, tuned with real false-positive exclusions found
  live, plus 20 fail2ban jails covering every exposed service, including
  a subnet-aggregating jail that catches distributed brute-force attempts
  spread across many IPs in the same network block, and a `recidive` jail
  that escalates repeat offenders caught by any of the others. See
  [`docs/fail2ban-jails-reference.md`](docs/fail2ban-jails-reference.md)
  for the full list.
- **Nothing gets overwritten without a trace** — every file a step
  creates or changes is backed up first, to `/root/backups/<run
  timestamp>/<original path>`, with a manifest listing exactly what
  changed and by which step. Safe to inspect or roll back by hand after
  any run, including a failed one.
- **Idempotent and resumable** — every step persists what it decided
  under `/root/cfg-server/`, so re-running the whole script (or starting
  partway through with `START_AT=NN`) skips the interactive prompts and
  safely re-applies/verifies instead of asking again or duplicating work.

## Requirements

- **Debian 13 (trixie)** only — this is not tested against any other
  release or distribution, and relies on trixie-specific package
  versions throughout.
- A clean, dedicated install (a container or VM is fine). This
  framework assumes it owns the machine — it edits system-wide
  config (networking, firewall, SSH) and installs/configures a full
  mail stack.
- Root access (run as root, or via `sudo`).
- At least 4 GB RAM / 2 vCPU, more if `grommunio-files`/`grommunio-chat`
  see real load. A few GB of free disk for the base install; mail and
  archive storage grow from there depending on retention.
- Working outbound internet access (package repos, Let's Encrypt,
  Keycloak/OIDC endpoints if used).
- See "Before you start" below for the DNS prerequisites — these are
  **not optional**, and are easiest to get right before this script
  runs rather than after.

## Before you start

**For the full step-by-step walkthrough (prerequisites, pulling this
repo in, every installation step explained), see
[`docs/INSTALL.md`](docs/INSTALL.md).** The checklist below covers
just the DNS part on its own.

A mail server's reputation depends on DNS being right *before* it goes
live, not after:

1. **PTR (reverse DNS)** for the server's public IPv4 (and IPv6, if used)
   must already point to the FQDN you intend to give this server — set
   with your **hosting provider**, not in any domain's own DNS zone.
2. That FQDN needs its own **A/AAAA record** pointing back to the
   server (forward-confirmed reverse DNS, FCrDNS) — receiving mail
   servers check this.
3. Run `check-dns.sh --firstdomain` after step 10 has run once to verify
   both of the above automatically.
4. For each domain you plan to host, run `check-dns.sh --report
   <domain>` to get a ready-to-send DNS setup guide with this server's
   real IPs filled in — hand it to whoever manages that domain's DNS.

See `docs/dns-records-reference.md` for the full record-by-record
reference and the reasoning behind each one.

## Quick start

```
sudo ./server-setup.sh --domain example.com --hostname mail
```

Run this **on the target server**, not on the machine you built it from.
Omit the flags to be asked interactively. See `server-setup.sh --help`
for every option, including `--no-grommunio-setup` (stop before the
grommunio-setup wizard, e.g. to run it yourself, then resume with
`START_AT=<N>`).

After every step completes, reboot once and re-verify — some changes
(networkd, firewall) are applied live but should also be confirmed to
persist across a real boot.

## What it sets up, in order

| Step | Does |
|---|---|
| `10` | Network/hostname discovery, systemd-networkd, PTR-based FQDN suggestion |
| `15` | Locale, timezone |
| `18` | SSH hardening (MACs, X11Forwarding) on top of Debian's already-strong defaults |
| `20` | Firewall (firewalld or ufw) + fail2ban, SSH-only-from-whitelist first |
| `21` | Base packages later steps rely on |
| `25` | Package source: grommunio community repo, or your own rebuilt packages |
| `30` | `grommunio-setup` itself (the official wizard) |
| `31` | Mail domain creation, admin hub mailbox, dedicated-MX-hostname detection |
| `32` | gromox service selection, CBC-cipher exclusion, small default-tuning fixes |
| `33` | nginx site selection |
| `34` | grommunio-chat, Postfix hardening, Postfix TLS/cipher hardening |
| `35` | saslauthd / SMTP AUTH (a real gap in grommunio-setup) |
| `36`–`37` | fail2ban jails for every mail and gromox service |
| `38` | Antispam (rspamd) actually filtering mail, DKIM signing, local resolver |
| `39` | ModSecurity WAF |
| `40` | Keycloak SSO |
| `45`–`46` | grommunio-files + its Keycloak SSO |
| `50` | grommunio-archive |
| `60` | Service boot order, readiness units |

## Backups & persisted state

Three different things get called "backup" or "config" across this
project — here's what each one actually is and where it lives:

| What | Where | Comes from |
|---|---|---|
| Pre-change safety backup | `/root/backups/<run-timestamp>/<original path>` | Taken automatically by every step in *this* repo, before it touches a file. Manifest at `.../modified-files.txt`. Not scheduled, not off-host — a local undo trail for this run only. |
| Persisted setup decisions | `/root/cfg-server/` | Written by each step after it runs (chosen domains, package source, which services got enabled, etc.) — read back on every re-run so the script is idempotent and `START_AT=NN` can skip ahead safely. Not a backup; losing it just means the next run re-asks its prompts. |
| Full system/mail-data backup | Off-host, via Borg | **Not part of this repo.** A separate `backup-testvps.sh` + restore runbook lives in the companion [`tools`](https://github.com/thctlo/tools) repository — covers mail data, databases, and `/etc` configuration, meant to survive losing the whole server. |

So: this repo's own safety net only protects against *this run*
breaking something; for disaster recovery, see the `tools` repo.

### Where things live

A quick reference for anyone debugging a deployment made with this
framework — these are all standard Debian/gromox locations, not
anything this framework invents:

| Kind | Path |
|---|---|
| Mail/gromox service configs | `/etc/gromox/` |
| Postfix config | `/etc/postfix/` |
| nginx config (vhosts, snippets) | `/etc/nginx/` |
| Keycloak realm/client config | managed via `manage-mfa.sh`/Keycloak admin, not a flat file |
| ModSecurity rules/exclusions | `/etc/modsecurity/`, `/etc/nginx/modsecurity/` |
| fail2ban jails | `/etc/fail2ban/jail.d/` |
| Mail/archive data | `/var/lib/gromox/`, grommunio Archive's own store |
| Service logs | `journalctl -u <service>`; nginx has its own per-vhost error logs under `/var/log/nginx/` (see `docs/` for the one upstream bug around this) |

## Tools included

| Tool | Purpose |
|---|---|
| `check-dns.sh` | Read-only DNS audit, per-domain setup guide (`--report`), server-identity check (`--firstdomain`) |
| `manage-certs.sh` | Keeps the shared Let's Encrypt certificate's SAN list in sync with every active domain |
| `manage-dane.sh` / `update-dane-tlsa.sh` | DANE/TLSA setup and automatic re-publishing on renewal |
| `manage-dkim.sh` | DKIM key generation and DNS record output |
| `manage-mta-sts.sh` | MTA-STS policy file + nginx wiring; `--status` validates DNS/served policy/mx correctness, `--reconfigure` fixes a wrong mx without resetting mode/max_age |
| `manage-mfa.sh` | Per-user opt-in MFA (TOTP) via Keycloak |
| `fix-keycloak-json-perm.sh` | Installed as an apt hook; guards against a real upstream permission regression |
| `f2b-subnet-detect.sh` | Resolves an IP's real registered network block for fail2ban's subnet-ban action |
| `ensure-train-ham-folders.sh` | Creates the TRAIN-HAM folder for users grommunio-admin has no hook for; also installed as a daily timer by step 38 |
| `install-unattended-upgrades.sh` | Unattended-upgrades setup with a protected-package pre-flight check (optional local override file for site-specific additions) |

## Project structure

- `server-setup.sh` + `functions/*.sh` — the provisioning pipeline above.
- `manage-*.sh`, `check-dns.sh`, `*.sh` at the top level — standalone
  tools, safe to run independently at any time after setup.
- `docs/` — reference material (DNS records, known upstream bug
  reports).

Standalone operational tools that aren't part of this pipeline at all
(a backup script, one-off utilities) live in a separate `tools/`
repository alongside this one.

## Related projects

- [`grommunio-archive`](https://github.com/thctlo/grommunio-archive) — Debian packaging for grommunio's email archiver (piler-based)
- [`certbot-dns-transip`](https://github.com/thctlo/certbot-dns-transip) — certbot DNS-01 plugin for TransIP, used by this framework's `manage-dane.sh`/cert renewal
- [`transip-rest`](https://github.com/thctlo/transip-rest) — the TransIP API client the plugin above is built on
- [`tools`](https://github.com/thctlo/tools) — standalone backup/restore and maintenance scripts (not part of the provisioning pipeline)

## Status

Built from and tested against a real multi-domain production
deployment.

## Contributing

Contributions, issues and corrections welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT - see [LICENSE](LICENSE).
