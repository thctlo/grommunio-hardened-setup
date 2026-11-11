# Contributing

This started as the provisioning setup for one real, multi-domain
grommunio deployment, so most changes are driven by something that
actually broke or was missing in production — that's the kind of
contribution most welcome here too.

## Reporting an issue

Please include:

- The exact step (`NN` in `server-setup.sh --help`'s step list) or
  tool involved.
- Debian version (`cat /etc/debian_version`) — this project only
  targets Debian 13 (trixie); issues on anything else will likely be
  closed as out of scope unless they turn out to be generic.
- What you expected vs. what happened, with the relevant log output
  (`journalctl -u <service>`, or the script's own output).

## Proposing a change

- Keep steps idempotent and resumable — re-running a step (or the
  whole script) must not break something that already worked, and
  must not ask again for something already decided
  (see `/root/cfg-server/` in the README).
- Any file a change touches must go through the existing
  `backup_file()` helper (`functions/00-common.sh`) before being
  modified, so the pre-change safety backup keeps covering
  everything.
- If a fix is for a real upstream bug (gromox, grommunio-setup,
  etc.), link the upstream issue/report if one exists, or add one
  under `docs/` if not.
- Test against a real install, not just a dry read of the diff —
  this framework modifies live system state (networking, firewall,
  services), so a change that looks right on paper can still break a
  running server.

## Scope

Pull requests for the provisioning pipeline and the tools in this
repository are welcome. Packaging for individual grommunio
components lives in their own repositories (see "Related projects"
in the README) — issues/changes for those belong there instead.
