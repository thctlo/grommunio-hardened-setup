
#!/usr/bin/env bash
#
# Unattended Upgrades Installer
#
# Supported:
#   Debian 11+
#   Ubuntu 18.04+
#
# Repository policies:
#   security-only : Distribution security updates
#   all-trusted   : Security + manually approved third-party repositories
#
# Protected packages: any package listed in PROTECTED_PACKAGES below
# (default: grommunio-archive, a custom rebuild that tracks piler's own
# upstream git history explicitly - see that package's own repo) gets
# its own pre-flight check, wired in as an ExecStartPre= on
# apt-daily-upgrade.service. If that check finds either a new version
# of the protected package itself, or that a simulated dist-upgrade
# would REMOVE it (e.g. a same-named package from another configured
# repo becoming newer and winning, such as a Conflicts/Replaces
# relationship with an official counterpart - relevant if you add your
# own forked packages here), it mails PROTECTED_PACKAGE_ALERT_MAILTO
# and exits non-zero - which, for a oneshot systemd service, means the
# ENTIRE scheduled upgrade run is aborted before ExecStart (the actual
# upgrade) ever runs, not just that one package skipped. Nothing on the
# server gets auto-upgraded that run until a human resolves it by hand.
# Leave PROTECTED_PACKAGES empty to disable this feature entirely.
#
# Usage:
#   sudo bash install-unattended-upgrades.sh
#

set -Eeuo pipefail
umask 022

# ==================================================
# CONFIGURATION - EDIT THESE SETTINGS
# ==================================================

# Repository policy
REPO_POLICY="security-only"
# Options: security-only | all-trusted

# Package list refresh schedule (24-hour clock)
PACKAGE_LIST_HOURS="00,08,16"

# Automatic upgrade schedule
UPGRADE_HOURS="01,09,17"

# Random delay to distribute server load
RANDOMIZED_DELAY="15m"

# Catch up on missed timer executions
PERSISTENT_TIMERS="true"

# Automatic reboot
AUTO_REBOOT="true"

# Reboot time (local server time)
REBOOT_TIME="04:00"

# Allow reboot when users are logged in
AUTO_REBOOT_WITH_USERS="true"

# Package cleanup interval (days)
AUTOCLEAN_INTERVAL="7"

# Remove unused dependencies
REMOVE_UNUSED_DEPENDENCIES="true"

# Remove unused kernel packages
REMOVE_UNUSED_KERNEL_PACKAGES="true"

# Logging
ENABLE_SYSLOG="true"

# Dry-run retry settings
DRY_RUN_MAX_RETRIES=10
DRY_RUN_RETRY_INTERVAL=30

# Packages that must never be silently upgraded or replaced. Space-
# separated, empty string disables the feature entirely.
PROTECTED_PACKAGES="grommunio-archive"

# Optional local override, never tracked in this repo: a deployment
# that maintains its own additional forked/rebuilt packages (beyond
# what this public repo documents) can list them here instead of
# editing this script directly, so a `git pull` of this repo never
# clobbers that server's real list.
PROTECTED_PACKAGES_OVERRIDE_FILE="/etc/apt/install-unattended-upgrades.local.conf"
# shellcheck disable=SC1090
[[ -f "$PROTECTED_PACKAGES_OVERRIDE_FILE" ]] && source "$PROTECTED_PACKAGES_OVERRIDE_FILE"

# Where to mail when a protected package has a pending change. Default:
# hostmaster@<this server's own DNS domain> - already a real, deliverable
# alias on this project's admin hub mailbox (see 31-grommunio-domain.sh).
# Requires a local/relayed MTA (sendmail) - validated below, only if
# PROTECTED_PACKAGES is non-empty.
PROTECTED_PACKAGE_ALERT_MAILTO="hostmaster@$(hostname -d 2>/dev/null || true)"

# ==================================================
# END CONFIGURATION
# ==================================================

readonly AUTO_CONFIG="/etc/apt/apt.conf.d/20auto-upgrades"
readonly LOCAL_CONFIG="/etc/apt/apt.conf.d/99local-unattended-upgrades"
readonly REPO_CONFIG="/etc/apt/apt.conf.d/98approved-repositories"

readonly APPROVED_FILE="/etc/apt/approved-origins"
readonly INVENTORY_FILE="/etc/apt/repository-inventory.txt"

# Same pre-change backup convention as the rest of this project
# (functions/00-common.sh's backup_file(), reimplemented standalone here
# on purpose - this script has no dependency on that framework):
# /root/backups/<run-timestamp>/<original path>, numbered on repeat
# touches within the same run, with a manifest listing what changed.
RUN_TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
readonly BACKUP_ROOT="/root/backups/${RUN_TIMESTAMP}"
readonly MANIFEST_FILE="${BACKUP_ROOT}/modified-files.txt"

readonly LOG_FILE="/var/log/unattended-upgrades-installer.log"

readonly DAILY_TIMER_DIR="/etc/systemd/system/apt-daily.timer.d"
readonly UPGRADE_TIMER_DIR="/etc/systemd/system/apt-daily-upgrade.timer.d"

readonly PROTECTED_CHECK_SCRIPT="/usr/local/sbin/check-protected-packages.sh"
readonly PROTECTED_DROPIN_DIR="/etc/systemd/system/apt-daily-upgrade.service.d"

# ==================================================
# LOGGING
# ==================================================

mkdir -p /var/log
touch "$LOG_FILE"
chmod 640 "$LOG_FILE"

log() {
    echo "[$(date '+%F %T')] $*" | tee -a "$LOG_FILE"
}

die() {
    log "ERROR: $*"
    exit 1
}

# ==================================================
# BACKUP CONFIGURATION
# ==================================================
#
# Same convention as functions/00-common.sh (server-setup.sh's own
# framework) and this project's other standalone tools: full original
# path preserved under BACKUP_ROOT, numbered on repeat touches within
# this run, with a manifest of what changed. Defined here, before
# VALIDATION, so the ERR trap below can always call
# print_backup_manifest(), however early a failure happens.

# Tracked per-target-path via an associative array (not a single
# last-call slot): this script backs up AUTO_CONFIG/LOCAL_CONFIG/
# REPO_CONFIG/both timer override.conf files up front, in a batch,
# before any of their actual writes happen later in the script - a
# single-slot "last backup" variable would only let finalize_backup
# correctly finalize the LAST of those five.
declare -A _BACKUP_DEST_FOR

backup_file() {
    local target="$1"
    unset '_BACKUP_DEST_FOR[$target]' 2>/dev/null
    [[ -e "$target" ]] || return 0
    local dest="${BACKUP_ROOT}${target}"
    mkdir -p "$(dirname "$dest")"
    if [[ -e "$dest" ]]; then
        local n=1
        while [[ -e "${dest}.${n}" ]]; do
            n=$((n + 1))
        done
        dest="${dest}.${n}"
    fi
    cp -a "$target" "$dest"
    mkdir -p "$(dirname "$MANIFEST_FILE")"
    printf '%-40s %-50s %s\n' "$(basename "$0")" "$target" "$dest" >> "$MANIFEST_FILE"
    _BACKUP_DEST_FOR["$target"]="$dest"
}

# finalize_backup <same path just passed to backup_file>
#
# Call once, right after whatever write/edit just finished for that same
# path. If the file ended up byte-identical to the backup backup_file
# just took (i.e. nothing actually changed this run - the common case,
# since this script regenerates its managed files from scratch every
# time), removes that backup and its manifest line again, so re-running
# this installer repeatedly (it IS meant to be re-run, e.g. to change a
# setting) doesn't leave a pile of identical backups behind every time.
finalize_backup() {
    local target="$1"
    local dest="${_BACKUP_DEST_FOR[$target]:-}"
    [[ -n "$dest" ]] || return 0
    [[ -e "$target" && -e "$dest" ]] || return 0
    if cmp -s "$target" "$dest"; then
        rm -f "$dest"
        if [[ -f "$MANIFEST_FILE" ]]; then
            # grep -v exits 1 (not an error here) when the filtered
            # result is empty - the "|| true" matters even without an
            # explicit "&&" after it: under this script's own set
            # -Eeuo pipefail, a bare command returning non-zero still
            # aborts the whole run, found live when this was the only
            # remaining manifest line.
            grep -vF "$dest" "$MANIFEST_FILE" > "${MANIFEST_FILE}.tmp" 2>/dev/null || true
            mv "${MANIFEST_FILE}.tmp" "$MANIFEST_FILE"
        fi
    fi
    unset '_BACKUP_DEST_FOR[$target]'
}

print_backup_manifest() {
    echo
    echo "------------------------------------------------------------"
    echo "Files modified this run"
    echo "------------------------------------------------------------"
    if [[ -s "$MANIFEST_FILE" ]]; then
        column -t "$MANIFEST_FILE" 2>/dev/null || cat "$MANIFEST_FILE"
        echo
        echo "Originals backed up under: $BACKUP_ROOT"
        echo "This list: $MANIFEST_FILE"
    else
        echo "(none yet)"
    fi
    echo
}

trap 'rc=$?; log "ERROR: command failed on line $LINENO (exit $rc)"; print_backup_manifest; exit "$rc"' ERR

# ==================================================
# VALIDATION
# ==================================================

[[ "$EUID" -eq 0 ]] || die "Run this script as root."

[[ -f /etc/os-release ]] || die "Cannot detect operating system."

source /etc/os-release

VERSION_MAJOR="${VERSION_ID%%.*}"

case "$ID" in
    debian)
        (( VERSION_MAJOR >= 11 )) ||
            die "Debian 11 or newer required."
        ;;
    ubuntu)
        (( VERSION_MAJOR >= 18 )) ||
            die "Ubuntu 18.04 or newer required."
        ;;
    *)
        die "Unsupported distribution: $ID"
        ;;
esac

[[ "$REPO_POLICY" == "security-only" ||
   "$REPO_POLICY" == "all-trusted" ]] ||
    die "Invalid repository policy."

[[ "$AUTO_REBOOT" == "true" ||
   "$AUTO_REBOOT" == "false" ]] ||
    die "AUTO_REBOOT must be true or false."

[[ "$AUTO_REBOOT_WITH_USERS" == "true" ||
   "$AUTO_REBOOT_WITH_USERS" == "false" ]] ||
    die "AUTO_REBOOT_WITH_USERS must be true or false."

[[ "$PERSISTENT_TIMERS" == "true" ||
   "$PERSISTENT_TIMERS" == "false" ]] ||
    die "PERSISTENT_TIMERS must be true or false."

[[ "$REMOVE_UNUSED_DEPENDENCIES" == "true" ||
   "$REMOVE_UNUSED_DEPENDENCIES" == "false" ]] ||
    die "REMOVE_UNUSED_DEPENDENCIES must be true or false."

[[ "$REMOVE_UNUSED_KERNEL_PACKAGES" == "true" ||
   "$REMOVE_UNUSED_KERNEL_PACKAGES" == "false" ]] ||
    die "REMOVE_UNUSED_KERNEL_PACKAGES must be true or false."

[[ "$ENABLE_SYSLOG" == "true" ||
   "$ENABLE_SYSLOG" == "false" ]] ||
    die "ENABLE_SYSLOG must be true or false."

[[ "$REBOOT_TIME" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] ||
    die "Invalid reboot time. Use HH:MM."

[[ "$AUTOCLEAN_INTERVAL" =~ ^[0-9]+$ ]] ||
    die "AUTOCLEAN_INTERVAL must be a number."

[[ "$RANDOMIZED_DELAY" =~ ^[0-9]+(s|m|min|h|d)$ ]] ||
    die "Invalid RANDOMIZED_DELAY."

[[ "$DRY_RUN_MAX_RETRIES" =~ ^[1-9][0-9]*$ ]] ||
    die "Invalid DRY_RUN_MAX_RETRIES."

[[ "$DRY_RUN_RETRY_INTERVAL" =~ ^[1-9][0-9]*$ ]] ||
    die "Invalid DRY_RUN_RETRY_INTERVAL."

if [[ -n "$PROTECTED_PACKAGES" ]]; then

    for pkg in $PROTECTED_PACKAGES; do
        [[ "$pkg" =~ ^[a-z0-9][a-z0-9.+-]*$ ]] ||
            die "Invalid package name in PROTECTED_PACKAGES: $pkg"
    done

    [[ "$PROTECTED_PACKAGE_ALERT_MAILTO" =~ ^[^@[:space:]]+@[^@[:space:]]+$ ]] ||
        die "PROTECTED_PACKAGE_ALERT_MAILTO is not a valid address (is this host's hostname missing its domain part? check 'hostname -f')."

    command -v sendmail >/dev/null ||
        die "sendmail not found, but PROTECTED_PACKAGES is set - without a working MTA, a halted upgrade would go completely unnoticed. Install one (e.g. this is normally already present via postfix) or clear PROTECTED_PACKAGES."

fi

# ==================================================
# SCHEDULE VALIDATION
# ==================================================

command -v systemd-analyze >/dev/null ||
    die "systemd-analyze is required."

validate_schedule() {
    local hours="$1"
    local schedule

    [[ "$hours" =~ ^[0-9]{2}(,[0-9]{2})*$ ]] ||
        die "Invalid schedule: $hours"

    schedule="*-*-* ${hours}:00:00"

    systemd-analyze calendar "$schedule" >/dev/null ||
        die "Invalid systemd schedule: $schedule"
}

validate_schedule "$PACKAGE_LIST_HOURS"
validate_schedule "$UPGRADE_HOURS"

log "Detected: $PRETTY_NAME"
log "Repository policy: $REPO_POLICY"

# ==================================================
# DIRECTORY PREPARATION
# ==================================================

mkdir -p /etc/apt
mkdir -p /var/lib/unattended-upgrades

# ==================================================
# MIGRATE EXISTING CUSTOM FILES
# ==================================================

if [[ -f /etc/unattended-upgrades/approved-origins &&
      ! -f "$APPROVED_FILE" ]]; then

    mv /etc/unattended-upgrades/approved-origins "$APPROVED_FILE"

    log "Migrated repository approvals to $APPROVED_FILE"
fi

if [[ -f /var/lib/unattended-upgrades/repository-inventory.txt &&
      ! -f "$INVENTORY_FILE" ]]; then

    mv /var/lib/unattended-upgrades/repository-inventory.txt "$INVENTORY_FILE"

    log "Migrated repository inventory to $INVENTORY_FILE"
fi

# ==================================================
# CREATE BACKUPS
# ==================================================

backup_file "$AUTO_CONFIG"
backup_file "$LOCAL_CONFIG"
backup_file "$REPO_CONFIG"

backup_file "$DAILY_TIMER_DIR/override.conf"
backup_file "$UPGRADE_TIMER_DIR/override.conf"

# ==================================================
# INSTALL PACKAGES
# ==================================================

export DEBIAN_FRONTEND=noninteractive

log "Updating package lists..."

apt-get update

log "Installing required packages..."

apt-get install -y \
    unattended-upgrades \
    apt-listchanges \
    python3

# ==================================================
# REPOSITORY APPROVAL FILE
# ==================================================

if [[ ! -f "$APPROVED_FILE" ]]; then

    cat > "$APPROVED_FILE" <<'EOF'
# Approved APT repositories
#
# Format:
# origin|codename|label
#
# Add only repositories you explicitly trust.
#
# Examples:
# Docker|bookworm|Docker CE
# PostgreSQL|bookworm|PostgreSQL
EOF

    chmod 644 "$APPROVED_FILE"

    log "Created repository approval file: $APPROVED_FILE"
fi

# ==================================================
# AUTOMATIC UPDATE CONFIGURATION
# ==================================================

log "Configuring automatic updates..."

cat > "$AUTO_CONFIG" <<EOF
APT::Periodic::Update-Package-Lists "always";
APT::Periodic::Download-Upgradeable-Packages "always";
APT::Periodic::Unattended-Upgrade "always";
APT::Periodic::AutocleanInterval "$AUTOCLEAN_INTERVAL";
APT::Periodic::Verbose "1";
EOF

chmod 644 "$AUTO_CONFIG"
finalize_backup "$AUTO_CONFIG"

# ==================================================
# UNATTENDED-UPGRADES CONFIGURATION
# ==================================================

log "Configuring unattended-upgrades..."

cat > "$LOCAL_CONFIG" <<EOF
// Generated by unattended-upgrades installer

Unattended-Upgrade::Automatic-Reboot "$AUTO_REBOOT";
Unattended-Upgrade::Automatic-Reboot-WithUsers "$AUTO_REBOOT_WITH_USERS";
Unattended-Upgrade::Automatic-Reboot-Time "$REBOOT_TIME";

Unattended-Upgrade::Remove-Unused-Dependencies "$REMOVE_UNUSED_DEPENDENCIES";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "$REMOVE_UNUSED_KERNEL_PACKAGES";

Unattended-Upgrade::SyslogEnable "$ENABLE_SYSLOG";
EOF

chmod 644 "$LOCAL_CONFIG"
finalize_backup "$LOCAL_CONFIG"

# ==================================================
# REPOSITORY DISCOVERY
# ==================================================

log "Discovering APT repositories..."

python3 - \
    "$REPO_POLICY" \
    "$APPROVED_FILE" \
    "$INVENTORY_FILE" \
    "$REPO_CONFIG" <<'PYTHON'

import subprocess
import sys
import re
import os

policy, approved_file, inventory_file, config_file = sys.argv[1:]

result = subprocess.run(
    ["apt-cache", "policy"],
    capture_output=True,
    text=True,
    check=True
)

repositories = set()

for line in result.stdout.splitlines():

    line = line.strip()

    if not line.startswith("release "):
        continue

    fields = dict(
        re.findall(r'(?:^|,)([a-z])=([^,]*)', line[8:])
    )

    origin = fields.get("o", "")
    codename = fields.get("n", "")
    label = fields.get("l", "")

    if not origin or not codename:
        continue

    values = [origin, codename, label]

    if any(
        not re.fullmatch(r'[A-Za-z0-9_.:+~ -]+', value)
        for value in values
    ):
        continue

    repositories.add((origin, codename, label))

# Save detected repository inventory.

with open(inventory_file, "w") as inventory:

    inventory.write("# Detected APT repositories\n")
    inventory.write("# origin|codename|label\n")

    for repo in sorted(repositories):
        inventory.write("|".join(repo) + "\n")

os.chmod(inventory_file, 0o644)

print("\nDetected repositories:")

for repo in sorted(repositories):
    print("  " + " | ".join(repo))

# Load explicitly approved repositories.

approved = set()

with open(approved_file) as file:

    for line in file:

        line = line.strip()

        if not line or line.startswith("#"):
            continue

        parts = line.split("|")

        if len(parts) != 3:
            print(f"WARNING: Invalid approval entry: {line}")
            continue

        if any(
            not re.fullmatch(r'[A-Za-z0-9_.:+~ -]*', value)
            for value in parts
        ):
            print(f"WARNING: Invalid characters in approval: {line}")
            continue

        approved.add(tuple(parts))

# Match approved repositories against detected metadata.

matched = approved.intersection(repositories)

for repo in sorted(approved - repositories):
    print(
        "WARNING: Approved repository not currently detected: "
        + " | ".join(repo)
    )

# Generate third-party whitelist.

with open(config_file, "w") as config:

    config.write("// Generated repository whitelist\n")

    if policy == "all-trusted":

        config.write(
            "Unattended-Upgrade::Origins-Pattern {\n"
        )

        for origin, codename, label in sorted(matched):

            pattern = (
                f"origin={origin},codename={codename}"
            )

            if label:
                pattern += f",label={label}"

            config.write(f'    "{pattern}";\n')

        config.write("};\n")

    config.write("\n")

os.chmod(config_file, 0o644)

print(f"\nRepository policy: {policy}")
print(f"Approved repositories matched: {len(matched)}")
print(f"Generated: {config_file}")

PYTHON

finalize_backup "$REPO_CONFIG"

# ==================================================
# SYSTEMD TIMER CONFIGURATION
# ==================================================

configure_timer() {

    local directory="$1"
    local hours="$2"
    local description="$3"

    mkdir -p "$directory"

    cat > "$directory/override.conf" <<EOF
[Timer]
OnCalendar=
OnCalendar=*-*-* ${hours}:00:00
RandomizedDelaySec=$RANDOMIZED_DELAY
AccuracySec=1m
Persistent=$PERSISTENT_TIMERS
EOF

    finalize_backup "$directory/override.conf"

    log "Configured timer: $description ($hours)"
}

log "Configuring systemd timers..."

configure_timer \
    "$DAILY_TIMER_DIR" \
    "$PACKAGE_LIST_HOURS" \
    "APT package list refresh"

configure_timer \
    "$UPGRADE_TIMER_DIR" \
    "$UPGRADE_HOURS" \
    "APT automatic upgrades"

# ==================================================
# PROTECTED PACKAGE ALERTING
# ==================================================

if [[ -n "$PROTECTED_PACKAGES" ]]; then

    log "Installing protected-package pre-flight check for: $PROTECTED_PACKAGES"

    backup_file "$PROTECTED_CHECK_SCRIPT"

    cat > "$PROTECTED_CHECK_SCRIPT" <<CHECKSCRIPT
#!/usr/bin/env bash
#
# Generated by install-unattended-upgrades.sh - re-run that installer to
# change PROTECTED_PACKAGES or PROTECTED_PACKAGE_ALERT_MAILTO, don't edit
# this file directly (it will be overwritten).
#
# Wired in as apt-daily-upgrade.service's ExecStartPre= (see
# $PROTECTED_DROPIN_DIR/). Exits non-zero - which, for this oneshot
# service, aborts the ENTIRE scheduled upgrade run before it starts - if
# any protected package either has a new version available, or would be
# REMOVED by a simulated dist-upgrade (e.g. its official, non-forked
# counterpart becoming newer and winning a Conflicts/Replaces). Mails
# $PROTECTED_PACKAGE_ALERT_MAILTO either way. Safe/idempotent to run by
# hand any time; exits 0 with no mail if nothing is pending.

set -euo pipefail

PROTECTED_PACKAGES=($PROTECTED_PACKAGES)
MAILTO="$PROTECTED_PACKAGE_ALERT_MAILTO"

log() { logger -t check-protected-packages -- "\$*"; echo "\$*" >&2; }

apt-get update -qq >/dev/null 2>&1 || true

findings=()
sim="\$(apt-get -s dist-upgrade 2>/dev/null || true)"

for pkg in "\${PROTECTED_PACKAGES[@]}"; do

    dpkg-query -W -f='' "\$pkg" 2>/dev/null || continue

    installed="\$(dpkg-query -W -f='\${Version}' "\$pkg")"
    candidate="\$(apt-cache policy "\$pkg" 2>/dev/null | awk '/Candidate:/{print \$2; exit}')"

    if [[ -n "\$candidate" && "\$candidate" != "(none)" && "\$candidate" != "\$installed" ]]; then
        findings+=("\${pkg}: new version available (\${installed} -> \${candidate}) - review before upgrading.")
    fi

    if grep -qE "^Remv \${pkg} " <<<"\$sim"; then
        replacement="\$(grep -oE '^Inst [^ ]+' <<<"\$sim" | awk '{print \$2}' | paste -sd' ' -)"
        findings+=("\${pkg}: a dist-upgrade would REMOVE it (likely via Conflicts/Replaces - candidate replacement(s): \${replacement:-unknown}). This would silently drop this package's own patches - do not let this happen automatically.")
    fi

done

if [[ "\${#findings[@]}" -eq 0 ]]; then
    exit 0
fi

# The halt below is unconditional, every run, for as long as a finding
# exists - only the MAIL is throttled to once per day, via this stamp
# file, so a 3x/day schedule doesn't send 3 identical alerts.
STAMP_FILE="/var/lib/check-protected-packages/last-alert-date"
mkdir -p "\$(dirname "\$STAMP_FILE")"

TODAY="\$(date +%Y-%m-%d)"
LAST_ALERT="\$(cat "\$STAMP_FILE" 2>/dev/null || true)"

if [[ "\$LAST_ALERT" != "\$TODAY" ]]; then

    BODY="\$(
        echo "Automatic upgrades were halted on \$(hostname -f) because a"
        echo "protected package has a pending change that needs manual review:"
        echo
        printf '  - %s\n' "\${findings[@]}"
        echo
        echo "Nothing was upgraded this run - not even unrelated packages -"
        echo "until this is resolved by hand. Once reviewed (and the protected"
        echo "package rebuilt/republished if needed), re-run"
        echo "'apt-get dist-upgrade' yourself; unattended upgrades resume"
        echo "automatically on the next scheduled run once nothing is pending."
        echo
        echo "(This mail is sent at most once per day - the upgrade run"
        echo "itself is still halted on every scheduled run until resolved.)"
    )"

    {
        echo "To: \${MAILTO}"
        echo "Subject: ACTION REQUIRED: protected package upgrade pending on \$(hostname -f)"
        echo "Content-Type: text/plain; charset=UTF-8"
        echo
        echo "\$BODY"
    } | sendmail -t

    echo "\$TODAY" > "\$STAMP_FILE"
    log "Halting upgrade run, mailed \${MAILTO}: \${#findings[@]} protected-package finding(s)."

else
    log "Halting upgrade run: \${#findings[@]} protected-package finding(s) (already mailed \${MAILTO} today, not mailing again)."
fi

exit 1
CHECKSCRIPT

    chmod 755 "$PROTECTED_CHECK_SCRIPT"
    finalize_backup "$PROTECTED_CHECK_SCRIPT"

    backup_file "$PROTECTED_DROPIN_DIR/protected-packages.conf"

    mkdir -p "$PROTECTED_DROPIN_DIR"

    cat > "$PROTECTED_DROPIN_DIR/protected-packages.conf" <<EOF
[Service]
ExecStartPre=$PROTECTED_CHECK_SCRIPT
EOF

    chmod 644 "$PROTECTED_DROPIN_DIR/protected-packages.conf"
    finalize_backup "$PROTECTED_DROPIN_DIR/protected-packages.conf"

else

    if [[ -f "$PROTECTED_DROPIN_DIR/protected-packages.conf" ]]; then
        log "PROTECTED_PACKAGES is empty - removing existing protected-package drop-in."
        backup_file "$PROTECTED_DROPIN_DIR/protected-packages.conf"
        rm -f "$PROTECTED_DROPIN_DIR/protected-packages.conf"
    fi

fi

systemctl daemon-reload

systemctl enable apt-daily.timer
systemctl enable apt-daily-upgrade.timer

systemctl restart apt-daily.timer
systemctl restart apt-daily-upgrade.timer

# ==================================================
# VALIDATION
# ==================================================

log "Validating APT configuration..."

apt-config dump >/dev/null ||
    die "APT configuration validation failed."

command -v unattended-upgrade >/dev/null ||
    die "unattended-upgrade executable missing."

# ==================================================
# UNATTENDED-UPGRADES DRY-RUN
# ==================================================

log "Running unattended-upgrades dry-run..."

DRY_RUN_SUCCESS=false

for ((attempt=1; attempt<=DRY_RUN_MAX_RETRIES; attempt++)); do

    log "Dry-run attempt $attempt of $DRY_RUN_MAX_RETRIES..."

    if unattended-upgrade --dry-run --debug; then

        DRY_RUN_SUCCESS=true
        break

    fi

    if (( attempt < DRY_RUN_MAX_RETRIES )); then

        log "Dry-run failed. Waiting ${DRY_RUN_RETRY_INTERVAL}s before retry..."

        sleep "$DRY_RUN_RETRY_INTERVAL"

    fi

done

[[ "$DRY_RUN_SUCCESS" == "true" ]] ||
    die "Unattended-upgrades dry-run failed after $DRY_RUN_MAX_RETRIES attempts."

# ==================================================
# SUMMARY
# ==================================================

log "=============================================="
log "UNATTENDED UPGRADES CONFIGURED SUCCESSFULLY"
log "=============================================="

log "OS: $PRETTY_NAME"
log "Repository policy: $REPO_POLICY"
log "Package list schedule: $PACKAGE_LIST_HOURS"
log "Upgrade schedule: $UPGRADE_HOURS"
log "Randomized delay: $RANDOMIZED_DELAY"
log "Automatic reboot: $AUTO_REBOOT"
log "Reboot time: $REBOOT_TIME"
log "Reboot with logged-in users: $AUTO_REBOOT_WITH_USERS"
log "Package cleanup: Every $AUTOCLEAN_INTERVAL days"

log "Repository inventory: $INVENTORY_FILE"
log "Repository approvals: $APPROVED_FILE"

if [[ -n "$PROTECTED_PACKAGES" ]]; then
    log "Protected packages (halt + mail on pending change): $PROTECTED_PACKAGES"
    log "Protected package alerts go to: $PROTECTED_PACKAGE_ALERT_MAILTO"
else
    log "Protected packages: none (feature disabled)"
fi

log "Backup directory: $BACKUP_ROOT"
log "Installer log: $LOG_FILE"

log "=============================================="

print_backup_manifest | tee -a "$LOG_FILE"
