# Package source differences

The framework supports two package sources, chosen in step 25:

- **personal**: our rebuilt packages, from the file repo copied to `/var/www/html/apt-repo`.
- **community**: grommunio's `download.grommunio.com/community/Debian_13` (suite `Debian_13`).

Each step must work with either source. A step checks the live state and changes
only what is wrong (see functions/40 and functions/46). Use this table to record
any difference that needs its own handling. When a difference is found, add a
row, and say which step handles it and whether it is verified.

Versions in use on 2026-10-03: community gromox 3.12.36, grommunio-web 5.1.20,
grommunio-sync 2.6.10, grommunio-admin-api 1.21.25, grommunio-dav 1.8.7,
grommunio-setup 1.8. Our personal build used gromox 3.11.5, grommunio-web 5.1.18.

| # | Item | Personal | Community | Handled in | Status |
|---|------|----------|-----------|------------|--------|
| 1 | Source choice | file repo, `[trusted=yes]` | signed apt repo, key in `/usr/share/keyrings/download.grommunio.com.gpg` | 25 | verified both |
| 2 | `grommunio-archive` | packaged | not published | 50 skips when source is community | verified (community) |
| 3 | gromox-istore unit | not confirmed | enabled, fails on every start (`istore_standalone` not set) | 32 disables it when istore_standalone is not set | verified (community) |
| 4 | Postfix SASL `mech_list` | written by grommunio-setup with CRAM-MD5 and DIGEST-MD5 | same file, same content | 35 sets `LOGIN PLAIN` | verified (community) |
| 5 | Postfix aliases database | not confirmed | not confirmed | 35 rebuilds it when `/etc/aliases` is newer | verified (community) |
| 6 | saslauthd enabled at boot | not confirmed | not enabled by package after reinstall | 35 always enables it | verified (community) |
| 7 | Keycloak network default for `/auth/admin` | not confirmed | `0.0.0.0/0` (open) | 40 preseeds localhost | verified (community) |
| 8 | nginx upstream for Keycloak | not confirmed | `localhost:9080`, which resolves to `::1`; Keycloak listens on IPv4 only | 40 sets `127.0.0.1:9080` | verified (community) |
| 9 | grommunio-web audience mapper | created by hand | not created by package | 40 | verified (community) |
| 10 | Files audience mapper on grommunio-web client | needed for Files SSO add-account | needed | 40 | verified (community) |
| 11 | Files OIDC provider `uniqueUid` | 0 required | set by step 46 | 46 | verified (community) |
| 12 | Files bearer check (`checkBearer`) | not confirmed | off by default | 46 | verified (community) |
| 13 | Files post-logout redirect URI | not confirmed | not set | 46 | verified (community) |
| 14 | Files plugin default in grommunio-web | off by default | off by default | 45 | verified (community) |
| 15 | grommunio-sync `LOGAUTHFAIL` | off by default | off by default | 37 | verified (community) |
| 16 | grommunio-sync log file | created on first use | created on first use | 37 creates it empty for fail2ban | verified (community) |
| 17 | Keycloak audience check (mapper on own client) | per install | per install | 40 | verified (community) |
| 18 | Postfix chroot MySQL socket | fstab bind (manual, step 30) | fstab bind (manual, step 30) | 35 adds the bind to fstab and verifies the socket | verified (community) |
| 19 | Domain creation | manual | manual | 31 creates it from step 10 (active, deleted or missing) | verified (community) |
| 20 | Debian default nginx site enabled | enabled by the nginx package (conflicts with grommunio's `_` catch-all on port 80) | same; community docs say to remove it | 33 disables it (removes the sites-enabled link, keeps the file) | verified (community) |

## Rules for new entries

- Write each entry for both sources, even when one of them is "not confirmed".
- A step that fixes a difference checks the state first, then fixes it, then verifies it.
- When a difference is only needed by one source, the step must say so in its own
  header and must do nothing for the other source.
