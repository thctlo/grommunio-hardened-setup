#!/usr/bin/env bash
#
# 25-apt-repo-personal.sh
#
# Chooses where the grommunio/gromox packages come from:
#
#   1) Personal build packages (default). A LOCAL, file-based copy of the
#      admin's own rebuilt package pool. The build host's HTTP repo typically
#      lives on an internal LAN a public VPS has no route to, so the .deb
#      pool is copied onto THIS server (manually, e.g. via scp
#      from the build host's /srv/apt-repo/pool, which is outside this
#      script's scope) into REPO_DIR. This step turns it into an apt flat
#      repository:
#        a. verify REPO_DIR exists and contains .deb files
#        b. generate Packages(.gz) with dpkg-scanpackages
#        c. add `deb [trusted=yes] file://REPO_DIR ./` (trusted=yes because the
#           files arrived over a channel we already trust, scp/ssh)
#        d. apt-get update, then verify grommunio-setup is visible
#
#   2) grommunio community packages, as documented by grommunio: suite
#      Debian_13 at download.grommunio.com/community/Debian_13, signed with the
#      grommunio key. Only the apt source and the key are installed; the
#      community setup script and the licence file are not used.
#
# Switching options disables the other source file (moved aside, not deleted).
# Must run before functions/30-grommunio-setup.sh.

step_apt_repo_personal()
{
local PERSONAL_SOURCES="/etc/apt/sources.list.d/personal.list"
local COMMUNITY_SOURCES="/etc/apt/sources.list.d/grommunio.sources"
local COMMUNITY_KEYRING="/usr/share/keyrings/download.grommunio.com.gpg"
local COMMUNITY_URL="https://download.grommunio.com/community/Debian_13"
local COMMUNITY_SUITE="Debian_13"
local COMMUNITY_KEY_URL="https://download.grommunio.com/RPM-GPG-KEY-grommunio"
local NO_TRANSLATIONS_FILE="/etc/apt/apt.conf.d/99no-translations"

local CFG="$(cfg_file 25-apt-repo-personal)"
local SAVED_SOURCE=""
local SAVED_REPO_DIR=""
local PKG_SOURCE=""
local REPO_DIR=""

require_cmd apt-get

# ============================================================
# Load saved config, if any
# ============================================================

if [[ -f "$CFG" ]]; then
    # shellcheck disable=SC1090
    source "$CFG"
    SAVED_SOURCE="${PKG_SOURCE:-}"
    SAVED_REPO_DIR="${REPO_DIR:-}"
    PKG_SOURCE=""
    REPO_DIR=""
    [[ -n "$SAVED_SOURCE" ]] && log "Found saved configuration: $CFG"
fi

# ============================================================
# Choose the package source
# ============================================================

if [[ -n "$SAVED_SOURCE" ]]; then
    PKG_SOURCE="$SAVED_SOURCE"
    log "Using saved package source (delete $CFG to be asked again): $PKG_SOURCE"
else
    echo
    echo "============================================================"
    echo " Package source for grommunio"
    echo "============================================================"
    echo
    echo "  1) Personal build packages (local file repo, copied from the build host)"
    echo "  2) grommunio community packages (download.grommunio.com)"
    echo
    read -r -p "Choose [1/2] [1]: " PKG_CHOICE
    case "${PKG_CHOICE:-1}" in
        1) PKG_SOURCE="personal" ;;
        2) PKG_SOURCE="community" ;;
        *) err "Invalid choice: $PKG_CHOICE"; return 1 ;;
    esac
fi

# ============================================================
# Option 2: grommunio community packages
# ============================================================

configure_community()
{
    require_cmd curl
    require_cmd gpg

    log "Checking that $COMMUNITY_URL publishes apt suite $COMMUNITY_SUITE..."
    if ! curl -fsI --max-time 30 "$COMMUNITY_URL/dists/$COMMUNITY_SUITE/InRelease" >/dev/null 2>&1; then
        err "No apt suite $COMMUNITY_SUITE at $COMMUNITY_URL/dists/$COMMUNITY_SUITE/InRelease."
        err "Check your network to download.grommunio.com, or choose option 1 (personal build packages)."
        return 1
    fi

    log "Installing the grommunio signing key to $COMMUNITY_KEYRING..."
    mkdir -p "$(dirname "$COMMUNITY_KEYRING")"
    curl -fsSL --max-time 30 "$COMMUNITY_KEY_URL" | gpg --dearmor > "${COMMUNITY_KEYRING}.tmp"
    mv "${COMMUNITY_KEYRING}.tmp" "$COMMUNITY_KEYRING"
    chmod 644 "$COMMUNITY_KEYRING"

    if [[ -f "$PERSONAL_SOURCES" ]]; then
        mv "$PERSONAL_SOURCES" "${PERSONAL_SOURCES}.disabled"
        log "Disabled the personal repo source (${PERSONAL_SOURCES}.disabled)."
    fi

    backup_file "$COMMUNITY_SOURCES"
    cat > "$COMMUNITY_SOURCES" <<EOF
Types: deb
URIs: ${COMMUNITY_URL}
Suites: ${COMMUNITY_SUITE}
Components: main
Signed-By: ${COMMUNITY_KEYRING}
EOF
    chmod 644 "$COMMUNITY_SOURCES"
    finalize_backup "$COMMUNITY_SOURCES"
    log "Wrote $COMMUNITY_SOURCES"

    echo
    log "Running apt-get update..."
    apt-get update

    echo
    log "Verifying the community repo is visible to apt (looking for grommunio-setup)..."
    if apt-cache policy grommunio-setup 2>/dev/null | grep -q "$COMMUNITY_URL"; then
        log "OK: grommunio-setup is available from $COMMUNITY_URL."
    else
        die "grommunio-setup was not found from $COMMUNITY_URL after apt-get update."
    fi

    save_cfg "$CFG" "PKG_SOURCE=$PKG_SOURCE"
    log "Saved configuration for replay: $CFG"

    echo
    echo "============================================================"
    echo " Done"
    echo "============================================================"
    echo
    echo "Repo configured: $COMMUNITY_URL (signed, grommunio community)"
    echo
}

# ============================================================
# Option 1: personal build packages (file-based flat repo)
# ============================================================

configure_personal()
{
    if [[ -n "$SAVED_REPO_DIR" ]]; then
        REPO_DIR="$SAVED_REPO_DIR"
        log "Using saved repo directory: $REPO_DIR"
    else
        read -r -p "Local repo directory [/var/www/html/apt-repo]: " REPO_DIR
        REPO_DIR="${REPO_DIR:-/var/www/html/apt-repo}"
    fi
    REPO_DIR="${REPO_DIR%/}"

    # Precondition: the pool must already be copied here (manual step).
    if [[ ! -d "$REPO_DIR" ]]; then
        err "Repo directory does not exist: $REPO_DIR"
        err "Copy the package pool here first (e.g. scp -r from the build host's /srv/apt-repo/pool), then re-run this step."
        return 1
    fi

    local deb_count
    deb_count="$(find "$REPO_DIR" -name '*.deb' 2>/dev/null | wc -l)"
    if [[ "$deb_count" -eq 0 ]]; then
        err "No .deb files found under $REPO_DIR."
        err "Copy the package pool here first (e.g. scp -r from the build host's /srv/apt-repo/pool), then re-run this step."
        return 1
    fi
    log "Found $deb_count .deb file(s) under $REPO_DIR."

    if ! command -v dpkg-scanpackages >/dev/null 2>&1; then
        log "Installing dpkg-dev (provides dpkg-scanpackages)..."
        apt-get update -qq
        apt-get install -y dpkg-dev
    fi

    log "Generating package index in $REPO_DIR..."
    ( cd "$REPO_DIR" && dpkg-scanpackages --multiversion . /dev/null > Packages )
    gzip -kf "$REPO_DIR/Packages"
    log "Wrote $REPO_DIR/Packages(.gz)"

    backup_file "$PERSONAL_SOURCES"
    if [[ -f "$COMMUNITY_SOURCES" ]]; then
        mv "$COMMUNITY_SOURCES" "${COMMUNITY_SOURCES}.disabled"
        log "Disabled the community source (${COMMUNITY_SOURCES}.disabled)."
    fi

    echo "deb [trusted=yes] file://${REPO_DIR} ./" > "$PERSONAL_SOURCES"
    chmod 644 "$PERSONAL_SOURCES"
    finalize_backup "$PERSONAL_SOURCES"
    log "Wrote $PERSONAL_SOURCES"

    # The flat repo has no Release/i18n manifest, so apt logs harmless
    # Translation-en fetch errors. We ship no translation catalogs.
    if [[ ! -f "$NO_TRANSLATIONS_FILE" ]]; then
        echo 'Acquire::Languages "none";' > "$NO_TRANSLATIONS_FILE"
        chmod 644 "$NO_TRANSLATIONS_FILE"
        log "Wrote $NO_TRANSLATIONS_FILE (silences Translation-en fetch noise)"
    fi

    echo
    log "Running apt-get update..."
    apt-get update

    echo
    log "Verifying the repo is visible to apt (looking for grommunio-setup)..."
    if apt-cache policy grommunio-setup 2>/dev/null | grep -q "file:${REPO_DIR}"; then
        log "OK: grommunio-setup is available from $REPO_DIR."
    else
        err "grommunio-setup was not found from $REPO_DIR after apt-get update."
        err "Check that the copied pool actually contains it, and that $REPO_DIR/Packages lists it."
        die "Repo verification failed."
    fi

    save_cfg "$CFG" "PKG_SOURCE=$PKG_SOURCE" "REPO_DIR=$REPO_DIR"
    log "Saved configuration for replay: $CFG"

    echo
    echo "============================================================"
    echo " Done"
    echo "============================================================"
    echo
    echo "Repo configured: file://${REPO_DIR} (flat, trusted, $deb_count package(s))"
    echo
    echo "Refresh anytime by re-copying .debs into $REPO_DIR and re-running this step."
    echo
}

case "$PKG_SOURCE" in
    personal)  configure_personal ;;
    community) configure_community ;;
    *)         err "Unknown package source in $CFG: $PKG_SOURCE"; return 1 ;;
esac
}
