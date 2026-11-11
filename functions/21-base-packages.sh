#!/usr/bin/env bash
#
# 21-base-packages.sh
#
# Installs the small set of general-purpose tools later steps (and a human
# operator) rely on, before anything repo- or grommunio-specific happens.
# Runs right after firewall/fail2ban (20) and before the lvb repo is added
# (25), since 25 needs gpg to import the repo signing key.
#
# No prompts, no destructive action, nothing to persist to /root/cfg-server —
# this step is pure "make sure these commands exist," safe to re-run.
#
# Extend BASE_PACKAGES below as new steps need new tools; each entry has a
# one-line reason so it's obvious why it's here later.

step_base_packages()
{
require_cmd apt-get

# package               -> why it's here
# gnupg (provides gpg)  -> 25-apt-repo-personal.sh imports/verifies the repo signing key
# ca-certificates       -> HTTPS (apt over https, Let's Encrypt, curl/wget)
# curl                  -> general fetching/debugging, used by later steps
# wget                  -> same, some tools/docs assume wget specifically
# dnsutils (dig/host)   -> verifying DNS records before Let's Encrypt / MX checks
# lsb-release           -> some installers/scripts probe this for OS detection
# apt-transport-https   -> harmless on modern apt, kept for older doc compatibility
# ipset                 -> 20-firewall-fail2ban.sh's firewalld path needs it for banaction=firewallcmd-ipset
local -a BASE_PACKAGES=(
    gnupg
    ca-certificates
    curl
    wget
    dnsutils
    lsb-release
    apt-transport-https
    ipset
)

log "Updating apt package lists..."
apt-get update -qq

log "Installing base tools: ${BASE_PACKAGES[*]}"
apt-get install -y "${BASE_PACKAGES[@]}"

echo
log "Verifying key commands are now available..."
local -a CHECK_CMDS=(gpg curl wget dig ipset)
local cmd all_ok=1
for cmd in "${CHECK_CMDS[@]}"; do
    if command -v "$cmd" >/dev/null 2>&1; then
        log "  [ OK ] $cmd"
    else
        err "  [FAIL] $cmd still not found after install."
        all_ok=0
    fi
done

[[ "$all_ok" -eq 1 ]] || die "One or more expected commands are still missing after installing base packages."

echo
log "Base packages installed."
echo
}
