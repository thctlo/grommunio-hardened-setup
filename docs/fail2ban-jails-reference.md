# fail2ban jails set up by this framework

Reference list of every jail this framework enables, across three
steps (`20-firewall-fail2ban.sh`, `36-fail2ban-mail-jails.sh`,
`37-fail2ban-gromox-jails.sh`) - **20 jails total**. None of this is
hypothetical hardening: every `bantime`/`findtime` value below that
differs from a simple round number was arrived at by sweeping real
logs on a live, internet-facing deployment and widening whatever a
real attacker was found pacing just outside.

## How the jails relate to each other

- **`recidive` escalates repeat offenders from every other jail on
  this list.** It does not watch a service log - it watches
  fail2ban's own ban log (`/var/log/fail2ban.log`, hence
  `backend = auto`, not the `[DEFAULT]` `backend = systemd` every
  other jail uses - under `systemd` this jail silently watches an
  empty source and never fires). An IP banned repeatedly by *any*
  combination of the jails below gets escalated to a 1-week ban here,
  regardless of which jail(s) caught it each time.
- **`postfix-smtp-auth-subnet` is layered on top of
  `postfix-smtp-auth`**, watching the exact same log line but keyed by
  a 3-octet IP prefix instead of the full address (`fid`-based
  aggregation), with a much higher `maxretry`. This exists specifically
  to catch a distributed attack - many different IPs in the same /24,
  each individually staying under `postfix-smtp-auth`'s own
  per-IP `maxretry = 5` - by aggregating hits across the whole subnet.
  When this jail fires, it shells out to `f2b-subnet-detect.sh`, which
  does a live `whois` lookup to find that IP's *real* registered
  network block (not a blind guess at a /24) and bans that actual CIDR.
- **`grommunio-admin-400` and `grommunio-admin-api` both watch the same
  admin-web login traffic from different angles** (nginx access log vs.
  journal) and are tuned independently (`maxretry = 2` on both,
  lowered from a higher default after a real targeted burst that split
  across both logs and didn't alone reach either jail's old threshold).
  A single login-brute-force burst can trip both.
- **`gromox-http` and `grommunio-web-auth` can both fire on one failed
  `/web` login** (gromox-http's filter is generic across every gromox
  protocol - EWS/RPC/OAB/Autodiscover in addition to the web backend).
  Harmless double-counting, not a bug.
- Every jail shares one `ignoreip` list (loopback + the detected SSH
  client + the saved/entered whitelist) - the same addresses the
  firewall itself gives full access to.

## The jails

| Jail | Step | Watches | bantime | findtime | maxretry |
|---|---|---|---|---|---|
| `sshd` | 20 | sshd auth failures (journal) | 1d | 3h | 5 |
| `recidive` | 20 | fail2ban's own ban log - see above | 1w | 3d | (default, repeat-ban-count based) |
| `postfix-sasl` | 36 | stock jail, SASL auth failures | 1h | 1h | 5 |
| `postfix-abuse` | 36 | `postfix[mode=aggressive]` - broader Postfix abuse patterns | 24h | 8h | 3 |
| `postfix-smtp-auth` | 36 | custom filter, SMTP AUTH `disconnect...auth=0` | 24h | 24h | 5 |
| `postfix-smtp-auth-subnet` | 36 | same log line as above, aggregated per /24 - see above | 24h | 24h | 15 |
| `postfix-postscreen` | 36 | postscreen rejects (PREGREET, pipelining, non-SMTP, bare newline) | 1d | 1h | 2 |
| `nginx-botsearch` | 36 | stock jail, nginx error log, generic bot/scan patterns | 1h | 1h | 2 |
| `nginx-catchall-scan` | 36 | any 404 on the catch-all vhost | 24h | 12h | 3 |
| `nginx-bad-request` | 36 | stock filter, malformed/400 requests | 24h | 6h | 3 |
| `grommunio-admin-web-scan` | 36 | custom path-list probing (admin-web SPA always returns 200) | 1h | 1h | 3 |
| `grommunio-admin-400` | 36 | admin-web access log, bad requests - see above | 1h | 1h | 2 |
| `nginx-large-body` | 36 | `client_max_body_size` rejections | 1h | 1h | 3 |
| `gromox-imap` | 37 | IMAP login rejects | 2h | 1h | 3 |
| `gromox-pop3` | 37 | POP3 login rejects | 2h | 1h | 3 |
| `grommunio-web-auth` | 37 | `nginx-web-error.log`, grommunio Web login failures | 1h | 1h | 5 |
| `grommunio-dav` | 37 | `grommunio-dav/dav.log` | 2h | 1h | 3 |
| `grommunio-sync` | 37 | `grommunio-sync/grommunio-sync.log` (needs `LOGAUTHFAIL`, enabled by this step) | 1h | 1h | 9 (mobile clients legitimately re-register often) |
| `grommunio-admin-api` | 37 | admin-api journal, login failures - see above | 2h | 1h | 2 |
| `gromox-http` | 37 | generic auth-rejected across EWS/RPC/OAB/Autodiscover/web | 1h | 1h | 5 |

## Checking jail status

```
fail2ban-client status                 # list every active jail
fail2ban-client status <jail-name>     # that jail's current ban list
fail2ban-client set <jail-name> unbanip <ip>   # manual unban
```
