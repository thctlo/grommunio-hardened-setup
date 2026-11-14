#!/usr/bin/env bash
#
# refresh-personal-repo.sh
#
# Standalone, re-runnable refresh of the personal package pool set up by
# functions/25-apt-repo-personal.sh's "option 2" (community + personal
# build packages on top) - regenerates the Packages/Release index and
# re-verifies the apt pin, without going through the rest of
# server-setup.sh's interactive flow. Pairs with repo-setup's own
# publish-to-server.sh on the build host (see that project's README):
#
#   build host:  ./publish-to-server.sh <ssh-target>   (rsyncs the pool)
#   this server: sudo ./refresh-personal-repo.sh        (regenerates the index)
#
# This is deliberately NOT a copy of step 25's full logic - it skips the
# "choose community vs personal" question and the community-baseline
# setup entirely (both already done once, during initial setup), and
# only does the part that genuinely needs re-running every time the pool
# changes: regenerate the index, re-verify the pin still works. Requires
# step 25 to have already configured option 2 at least once - this
# script refuses to guess a repo directory step 25 was never told.
#
# Safe to re-run any number of times: every write here is check-before-
# write (same as step 25), and apt-get update + the dual verification at
# the end run every time regardless.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/functions/00-common.sh"

if [[ "$(id -u)" -ne 0 ]]; then
    die "Run this script as root."
fi

require_cmd apt-get
require_cmd dpkg

PERSONAL_SOURCES="/etc/apt/sources.list.d/personal.list"
PERSONAL_PIN_FILE="/etc/apt/preferences.d/90-personal-repo"
PERSONAL_REPO_ORIGIN="personal-build"
COMMUNITY_URL="https://download.grommunio.com/community/Debian_13"

# pkg_candidate_source <pkg>: same exact logic as step 25's own helper -
# see that file's header comment on this function for the "***"/version-
# table parsing pitfalls it avoids. Kept in sync by hand; if step 25's
# copy ever changes, update this one to match.
pkg_candidate_source()
{
    local pkg="$1" out cand
    out="$(apt-cache policy "$pkg" 2>/dev/null)"
    cand="$(awk '/^  Candidate:/{print $2}' <<< "$out")"
    [[ -n "$cand" ]] || return 1
    awk -v v="$cand" '
        /^  Version table:/ { intable=1; next }
        intable && ($1==v || $2==v) { getline; print; exit }
    ' <<< "$out"
}

# ============================================================
# REPO_DIR: reuse exactly what step 25 already saved - never re-asked
# here. If step 25 was never run in "personal" mode, there is nothing to
# refresh and no safe directory to guess.
# ============================================================

STEP25_CFG="$(cfg_file 25-apt-repo-personal)"
PKG_SOURCE=""
REPO_DIR=""
if [[ -f "$STEP25_CFG" ]]; then
    # shellcheck disable=SC1090
    source "$STEP25_CFG"
fi

if [[ "${PKG_SOURCE:-}" != "personal" || -z "${REPO_DIR:-}" ]]; then
    die "Step 25 (functions/25-apt-repo-personal.sh, part of server-setup.sh) has not been run in \"personal\" mode on this server yet ($STEP25_CFG missing or not set to option 2) - run that first, then this script."
fi
REPO_DIR="${REPO_DIR%/}"
log "Refreshing the personal repo at: $REPO_DIR (from $STEP25_CFG)"

if [[ ! -d "$REPO_DIR" ]]; then
    die "Repo directory does not exist: $REPO_DIR. Publish the pool here first (e.g. publish-to-server.sh from the build host), then re-run this script."
fi

DEB_COUNT="$(find "$REPO_DIR" -name '*.deb' 2>/dev/null | wc -l)"
if [[ "$DEB_COUNT" -eq 0 ]]; then
    die "No .deb files found under $REPO_DIR. Publish the pool here first (e.g. publish-to-server.sh from the build host), then re-run this script."
fi
log "Found $DEB_COUNT .deb file(s) under $REPO_DIR."

if ! command -v dpkg-scanpackages >/dev/null 2>&1; then
    log "Installing dpkg-dev (provides dpkg-scanpackages)..."
    apt-get update -qq
    apt-get install -y dpkg-dev
fi

log "Generating package index in $REPO_DIR..."
( cd "$REPO_DIR" && dpkg-scanpackages --multiversion . /dev/null > Packages )
gzip -kf "$REPO_DIR/Packages"
log "Wrote $REPO_DIR/Packages(.gz)"

(
    cd "$REPO_DIR"
    {
        echo "Origin: ${PERSONAL_REPO_ORIGIN}"
        echo "Label: ${PERSONAL_REPO_ORIGIN}"
        echo "Suite: personal"
        echo "Codename: personal"
        echo "Components: main"
        echo "Architectures: $(dpkg --print-architecture) all"
        echo "Date: $(date -Ru)"
        echo "MD5Sum:"
        for f in Packages Packages.gz; do
            printf ' %s %16d %s\n' "$(md5sum "$f" | cut -d' ' -f1)" "$(stat -c%s "$f")" "$f"
        done
        echo "SHA256:"
        for f in Packages Packages.gz; do
            printf ' %s %16d %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$(stat -c%s "$f")" "$f"
        done
    } > Release
)
chmod 644 "$REPO_DIR/Release"
log "Wrote $REPO_DIR/Release (Origin: ${PERSONAL_REPO_ORIGIN})."

# One of the package names actually in REPO_DIR right now, used below to
# verify pinning still works - read from the just-generated Packages
# index, not a filesystem find (a real repo pool is nested,
# pool/main/<letter>/<pkg>/..., a shallow find finds nothing there).
SAMPLE_PKG="$(awk -F': ' '/^Package:/{print $2; exit}' "$REPO_DIR/Packages")"

if [[ ! -f "$PERSONAL_SOURCES" ]]; then
    backup_file "$PERSONAL_SOURCES"
    echo "deb [trusted=yes] file://${REPO_DIR} ./" > "$PERSONAL_SOURCES"
    chmod 644 "$PERSONAL_SOURCES"
    finalize_backup "$PERSONAL_SOURCES"
    log "Wrote $PERSONAL_SOURCES (was missing - step 25 should have created this already)."
else
    log "[ OK ] $PERSONAL_SOURCES already present."
fi

if [[ ! -f "$PERSONAL_PIN_FILE" ]]; then
    backup_file "$PERSONAL_PIN_FILE"
    cat > "$PERSONAL_PIN_FILE" <<EOF
# Managed by 25-apt-repo-personal.sh / refresh-personal-repo.sh - do not
# edit by hand. Prefers this server's own local package pool over the
# grommunio community repo, for whichever packages it actually contains.
Package: *
Pin: release o=${PERSONAL_REPO_ORIGIN}
Pin-Priority: 900
EOF
    chmod 644 "$PERSONAL_PIN_FILE"
    finalize_backup "$PERSONAL_PIN_FILE"
    log "Wrote $PERSONAL_PIN_FILE (was missing - step 25 should have created this already)."
else
    log "[ OK ] $PERSONAL_PIN_FILE already present."
fi

echo
log "Running apt-get update..."
apt-get update

echo
log "Verifying community packages are still reachable (looking for grommunio-setup)..."
if pkg_candidate_source grommunio-setup | grep -qF "$COMMUNITY_URL"; then
    log "OK: grommunio-setup's candidate still comes from $COMMUNITY_URL."
else
    die "grommunio-setup's candidate does not come from $COMMUNITY_URL after apt-get update - the community baseline should never be affected by refreshing the personal repo."
fi

echo
log "Verifying the local pool's own packages are preferred over community..."
if [[ -n "$SAMPLE_PKG" ]] && pkg_candidate_source "$SAMPLE_PKG" | grep -qF "file:${REPO_DIR}"; then
    log "OK: $SAMPLE_PKG's candidate comes from the local pool (file://${REPO_DIR}), confirming the pin works."
else
    err "Could not confirm a local-pool package ($SAMPLE_PKG) is actually preferred over community."
    err "Check apt-cache policy $SAMPLE_PKG by hand, and that $PERSONAL_PIN_FILE was applied."
    die "Pin verification failed."
fi

echo
echo "============================================================"
echo " Done"
echo "============================================================"
echo
echo "Personal repo refreshed: file://${REPO_DIR} ($DEB_COUNT package(s))."
echo
