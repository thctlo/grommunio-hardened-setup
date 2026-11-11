# DNS records required for a grommunio mail server

Reference example, captured from a real working deployment and anonymized to
`example.com`. Use this as the checklist when setting up DNS for any new
domain on this mail server stack.

Replace `example.com` with the real domain, `mail.example.com` with the
real mail server FQDN, and `203.0.113.10` / `2001:db8::10` with
the server's real public IPv4/IPv6 addresses. The DKIM public keys and the
`_acme-challenge` TXT value below are placeholders - DKIM keys are
generated per domain (see `/root/cfg-server/dkim-dns-records.txt` on the
server for the real values once set up), and `_acme-challenge` is a
transient value only present while certbot's DNS-01 validation is running -
it does not stay in place permanently and should not be copied from here.

**Don't fill this template in by hand** - run `check-dns.sh --report
<domain>` on the server instead. It generates the same checklist with this
server's real IPs, hostname and DKIM selectors already filled in, plus the
live status of what's already set up vs. still missing for that domain.
See the main [README](../README.md#tools-included) for the other DNS
tools (`manage-dane.sh`, `manage-dkim.sh`, `manage-mta-sts.sh`) that set
up what this reference and `check-dns.sh --report` describe.

## Core mail routing

| Name | TTL | Type | Value |
|---|---|---|---|
| `@` | 1h | A | `203.0.113.10` |
| `@` | 1h | AAAA | `2001:db8::10` |
| `@` | 1h | MX | `10 mail.example.com.` |
| `mail` | 1h | A | `203.0.113.10` |
| `mail` | 1h | AAAA | `2001:db8::10` |

The bare domain (`@`) needs its own A/AAAA records (not just the MX target)
because mail clients and some validators resolve the domain itself, not
only the mail server's own hostname.

## Only when mail.<domain> is this server's own hostname: a dedicated `mx1` MX target

This server has exactly one canonical hostname: whatever its PTR (reverse
DNS) record says, found by step 10 and confirmed via that name's own
forward A/AAAA record (FCrDNS). That hostname is what `hostnamectl` sets,
and what Postfix uses as `myhostname`/HELO/EHLO identity. It is **not**
inherently tied to any one domain - it is simply whatever name the PTR
was set up with, by whoever controls reverse DNS for this IP (usually the
hosting provider).

**The collision this section is about**: if that canonical hostname
happens to be `mail.<domain>` for one specific domain hosted here - a
common pattern, since admins often set the PTR that way for their primary
domain, but not a rule this stack enforces - then `mail.<domain>` is
already "spoken for" as the *server's* shared identity, not something
exclusive to that domain alone.

**Why that matters**: DANE (TLSA records) is looked up by the *MX target
hostname*, not by the recipient domain. Anything else that ever shares
that same MX hostname would be forced to share the exact same DANE policy
too, with no way to enable it for just the one domain. The fix is to give
that one domain a second, independent MX hostname that nothing else
uses - by convention `mx1.<domain>`, though literally any unused name
works the same way:

| Name | TTL | Type | Value |
|---|---|---|---|
| `mx1` | 1d | A | `203.0.113.10` |
| `mx1` | 1d | AAAA | `2001:db8::10` |
| `@` | 1h | MX | `10 mx1.example.com.` *(instead of the `mail.example.com.` shown above)* |

`mx1` points at the exact same IP addresses as `mail` - it is not a
different server, not a different certificate (it is added as an extra
SAN on the one shared certificate, via `manage-certs.sh` - see its own
comments), and Postfix itself needs no configuration change at all (it
listens on the IP regardless of which name was used to reach it; its own
HELO/EHLO identity and the server's PTR record both stay on
`mail.example.com`, unchanged, so there is no FCrDNS/HELO-mismatch risk).

**If the server's own hostname is something else entirely** (a
provider-assigned rDNS string unrelated to any domain hosted here, for
example) - there is no collision: `mail.<domain>` is already exclusive to
that domain, nothing else shares it, and no dedicated MX hostname is
needed for it at all. This is decided per domain by what the PTR/A record
actually say, not by which domain happened to be created first.

`31-grommunio-domain.sh`'s `hint_dedicated_mx_if_needed` checks this
automatically for every domain it creates (comparing that domain's
`mail.<domain>` against the server's saved `NEW_FQDN` from step 10) and
only prints the `mx1` instructions when the comparison actually matches -
the DNS record itself (and the `manage-certs.sh --all` / `manage-dane.sh
--setup` follow-up) still has to be done by hand, this only tells you
whether it is needed.

## SPF, DKIM, DMARC

| Name | TTL | Type | Value |
|---|---|---|---|
| `@` | 1h | TXT | `v=spf1 mx -all` |
| `mail` | 1h | TXT | `v=spf1 a -all` |
| `dkim-ed._domainkey` | 5m | TXT | `v=DKIM1; k=ed25519; p=<ed25519 public key, base64>` |
| `dkim-rsa._domainkey` | 5m | TXT | `v=DKIM1; k=rsa; p=<RSA public key, base64>` |
| `dkim._domainkey` | 5m | CNAME | `dkim-rsa._domainkey.example.com.` |
| `_dmarc` | 5m | TXT | `v=DMARC1; p=quarantine; rua=mailto:admin@example.com` |

Two SPF records exist on purpose: one for the bare domain (`@`, authorizing
the MX hosts) and one for the `mail` subdomain itself (authorizing its own
A/AAAA record) - mail is sometimes sent with an envelope sender at either
name, so both need coverage.

Both an Ed25519 and an RSA DKIM key are published under separate selectors
(`dkim-ed`, `dkim-rsa`); the plain `dkim._domainkey` selector is a CNAME
alias to the RSA one, for anything that only knows to look up the
conventional unqualified selector name. Short TTLs (5 minutes) on the DKIM
and DMARC records make key rotation and DMARC policy changes take effect
quickly.

## Certificate issuance (CAA)

| Name | TTL | Type | Value |
|---|---|---|---|
| `@` | 1h | CAA | `0 issue "letsencrypt.org"` |
| `@` | 1h | CAA | `128 issuewild "letsencrypt.org"` |

Restricts which certificate authorities may issue certificates (including
wildcards) for this domain to Let's Encrypt, matching this stack's certbot
setup.

## Mail client autoconfiguration

| Name | TTL | Type | Value |
|---|---|---|---|
| `autoconfig` | 1d | CNAME | `mail.example.com.` |
| `autodiscover` | 1d | CNAME | `mail.example.com.` |
| `_autodiscover._tcp` | 1d | SRV | `0 0 443 mail.example.com.` |

`autoconfig` is Thunderbird's/Mozilla's convention, `autodiscover` and the
matching SRV record are Outlook's/Microsoft's. Both let mail clients find
server settings automatically from just the user's email address.

## CalDAV / CardDAV autodiscovery

| Name | TTL | Type | Value |
|---|---|---|---|
| `_caldav._tcp` | 1d | TXT | `https://mail.example.com/dav` |
| `_caldav._tcp` | 1d | SRV | `0 0 443 mail.example.com.` |
| `_caldavs._tcp` | 1d | TXT | `https://mail.example.com/dav` |
| `_caldavs._tcp` | 1d | SRV | `0 0 443 mail.example.com.` |
| `_carddav._tcp` | 1d | TXT | `https://mail.example.com/dav` |
| `_carddav._tcp` | 1d | SRV | `0 0 443 mail.example.com.` |
| `_carddavs._tcp` | 1d | TXT | `https://mail.example.com/dav` |
| `_carddavs._tcp` | 1d | SRV | `0 0 443 mail.example.com.` |

Both the plain (`caldav`/`carddav`) and explicit-TLS (`caldavs`/`carddavs`)
service names are published, each with both a TXT record (the actual DAV
base path) and an SRV record (the port), since different clients look for
different combinations.

## Mail protocol service discovery (RFC 6186)

| Name | TTL | Type | Value |
|---|---|---|---|
| `_imap._tcp` | 1d | SRV | `0 0 143 mail.example.com.` |
| `_imaps._tcp` | 1d | SRV | `0 0 993 mail.example.com.` |
| `_pop3._tcp` | 1d | SRV | `0 0 110 mail.example.com.` |
| `_pop3s._tcp` | 1d | SRV | `0 0 995 mail.example.com.` |
| `_submission._tcp` | 1d | SRV | `0 0 587 mail.example.com.` |
| `_submissions._tcp` | 1d | SRV | `0 0 465 mail.example.com.` |

Lets mail clients that support RFC 6186 discover IMAP/POP3/SMTP submission
ports automatically, as a fallback/complement to the vendor-specific
`autoconfig`/`autodiscover` records above.

## Other subdomains seen in this setup

| Name | TTL | Type | Value |
|---|---|---|---|
| `www` | 1h | A | `203.0.113.10` |
| `www` | 1h | AAAA | `2001:db8::10` |
| `meet` | 1d | A | `203.0.113.10` |
| `meet` | 1d | AAAA | `2001:db8::10` |

`www` is a plain web alias to the same server; `meet` is a separate
subdomain reserved for a video-conferencing service (e.g. grommunio
Meet/Jitsi) on the same host - not part of the mail stack itself, but
pointed at the same server IPs.

## Transient / per-renewal

| Name | TTL | Type | Value |
|---|---|---|---|
| `_acme-challenge` | 1m | TXT | *(set by certbot during DNS-01 validation, removed after)* |

Only present momentarily while a certificate is being issued or renewed via
DNS-01 validation. If this record is "missing," that is normal - it is not
meant to persist.
