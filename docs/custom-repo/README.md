# Using the author's own package repository (optional)

> **You don't need this.** The main [installation manual](../INSTALL.md)
> works completely from grommunio's own community repository. This
> page is only for replacing a handful of specific packages with the
> author's own independent rebuilds - useful if you want exactly the
> same setup as the testvps this project was built against, or if
> you've found and want to use one of the fixes described below before
> it (if ever) lands upstream.

## What's different, and why

| Package | Why it's rebuilt instead of taken from community | Repo |
|---|---|---|
| `grommunio-archive` | Same source grommunio ships, repackaged with grommunio's own patches tracked explicitly on top of piler's real upstream git history (see that repo's own README) - functionally identical to the community package, this just makes the provenance fully auditable. | [`grommunio-archive`](https://github.com/thctlo/grommunio-archive) |
| `certbot-dns-transip` / `transip-rest` | Not a grommunio package at all - a certbot DNS-01 plugin (and the TransIP API client underneath it) for the author's own registrar, TransIP. This is the actual reason this page exists: see the note below on why it matters. | [`certbot-dns-transip`](https://github.com/thctlo/certbot-dns-transip) / [`transip-rest`](https://github.com/thctlo/transip-rest) |

A couple of further packages are also built this way, for this
server's own use, but are kept private - not published here or
anywhere else, personal.

> **Why the certbot plugin matters: DANE/TLSA needs DNS automation.**
> `manage-dane.sh` (see the main README) publishes and keeps TLSA
> records in sync automatically on every certificate renewal - but it
> can only do that if *something* can update your DNS zone without a
> human in the loop. Don't turn on DANE/TLSA if you can't automate
> your own DNS - a TLSA record that falls out of sync with the
> certificate it's supposed to match breaks mail delivery to you, not
> just a warning. That automation is obligatory for TLSA to be safe to
> run at all, not optional polish.
>
> The author built one such plugin, for TransIP (the author's own
> registrar) - maybe you can build (or find) one for yours.

## Setting it up

This adds a *second* apt source alongside the community one from Step
25 - it does not replace it; only the specific package names above
ever come from here, everything else still resolves from the
community repo as normal.

```
# on the build/package host, or wherever you build these from source -
# see each package repo's own README for how to build it
sudo bash build-dsc.sh path/to/grommunio-archive.dsc
sudo bash repo-add.sh /path/to/results/grommunio-archive_*.changes

# same pattern for certbot-dns-transip / transip-rest
sudo bash build-dsc.sh path/to/certbot-dns-transip.dsc
sudo bash repo-add.sh /path/to/results/certbot-dns-transip_*.changes
```

(`build-dsc.sh`/`repo-add.sh` come from the separate
[`repo-setup`](https://github.com/thctlo/repo-setup) repo - the
orchestration layer for building/publishing these, kept separate from
this one since it's about *maintaining* packages, not installing a
server.)

Then, on the mail server itself, add that repo as an additional apt
source (same pattern Step 25 uses for the community one, see
`functions/25-apt-repo-personal.sh` for the exact mechanism) and
`apt-get install grommunio-archive`/`python3-certbot-dns-transip` as
normal - apt resolves each one from whichever configured source
currently has it.
