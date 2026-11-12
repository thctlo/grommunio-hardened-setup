#!/usr/bin/env bash
#
# 25-apt-repo-personal.sh
#
# Chooses where the grommunio/gromox packages come from:
#
#   1) Personal build packages + community (default). The community
#      repo (see option 2) is ALWAYS configured as the baseline - this
#      option then additionally layers a LOCAL, file-based copy of the
#      admin's own rebuilt package pool on top of it, via APT pinning,
#      so only the specific packages that pool actually contains ever
#      come from it; everything else (grommunio-setup, grommunio-chat-v10,
#      grommunio-auth, etc.) still resolves from community as normal.
#      The build host's HTTP repo typically lives on an internal LAN a
#      public VPS has no route to, so the .deb pool is copied onto THIS
#      server (manually, e.g. via scp from the build host's
#      /srv/apt-repo/pool, which is outside this script's scope) into
#      REPO_DIR. This step then:
#        a. configures the community repo (see option 2), if not already done
#        b. verifies REPO_DIR exists and contains .deb files
#        c. generates Packages(.gz) with dpkg-scanpackages
#        d. adds `deb [trusted=yes] file://REPO_DIR ./` (trusted=yes
#           because the files arrived over a channel we already trust,
#           scp/ssh) ALONGSIDE the community source, not instead of it
#        e. pins that local repo to a higher priority than community
#           (APT preferences, `Pin: origin ""` - the standard way to
#           target a local/file-based source with no Release Origin
#           field) so a package present in BOTH resolves from the
#           local repo, and anything only in community still resolves
#           from there, with zero package-name list to maintain
#        f. apt-get update, then verifies grommunio-setup still
#           resolves from community AND at least one package from
#           REPO_DIR resolves from the local repo
#
#   2) grommunio community packages only, as documented by grommunio:
#      suite Debian_13 at download.grommunio.com/community/Debian_13,
#      signed with the grommunio key. Only the apt source and the key
#      are installed; the community setup script and the licence file
#      are not used. Choosing this explicitly disables any existing
#      personal-repo overlay (moved aside, not deleted) - option 1 is
#      what re-enables it.
#
# Must run before functions/30-grommunio-setup.sh.

step_apt_repo_personal()
{
local PERSONAL_SOURCES="/etc/apt/sources.list.d/personal.list"
local PERSONAL_PIN_FILE="/etc/apt/preferences.d/90-personal-repo"
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

# pkg_candidate_source <pkg>: prints the source line apt would actually
# install FROM for <pkg>'s current candidate version - not just "is this
# source listed somewhere in the output" (true even for a losing,
# lower-priority entry) and not "***" (apt-cache policy only marks an
# INSTALLED version that way, never shown on a fresh system with
# nothing installed yet - exactly this step's own situation). Finds the
# "Candidate: X" line, then the line directly below wherever the
# version table lists exactly X.
pkg_candidate_source()
{
    local pkg="$1" out cand
    out="$(apt-cache policy "$pkg" 2>/dev/null)"
    cand="$(awk '/^  Candidate:/{print $2}' <<< "$out")"
    [[ -n "$cand" ]] || return 1
    awk -v v="$cand" '$1==v{getline; print; exit}' <<< "$out"
}

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
    echo "  1) Community packages + personal build packages on top (local file repo, copied from the build host)"
    echo "  2) grommunio community packages only (download.grommunio.com)"
    echo
    read -r -p "Choose [1/2] [1]: " PKG_CHOICE
    case "${PKG_CHOICE:-1}" in
        1) PKG_SOURCE="personal" ;;
        2) PKG_SOURCE="community" ;;
        *) err "Invalid choice: $PKG_CHOICE"; return 1 ;;
    esac
fi

# ============================================================
# Community repo baseline - used by both options (option 1 layers the
# personal repo on top of this; option 2 stops here).
# ============================================================

configure_community_baseline()
{
    require_cmd curl
    require_cmd gpg

    log "Checking that $COMMUNITY_URL publishes apt suite $COMMUNITY_SUITE..."
    if ! curl -fsI --max-time 30 "$COMMUNITY_URL/dists/$COMMUNITY_SUITE/InRelease" >/dev/null 2>&1; then
        err "No apt suite $COMMUNITY_SUITE at $COMMUNITY_URL/dists/$COMMUNITY_SUITE/InRelease."
        err "Check your network to download.grommunio.com."
        return 1
    fi

    log "Installing the grommunio signing key to $COMMUNITY_KEYRING..."
    mkdir -p "$(dirname "$COMMUNITY_KEYRING")"
    curl -fsSL --max-time 30 "$COMMUNITY_KEY_URL" | gpg --dearmor > "${COMMUNITY_KEYRING}.tmp"
    mv "${COMMUNITY_KEYRING}.tmp" "$COMMUNITY_KEYRING"
    chmod 644 "$COMMUNITY_KEYRING"

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
}

# ============================================================
# Option 2: grommunio community packages only
# ============================================================

configure_community()
{
    configure_community_baseline || return 1

    if [[ -f "$PERSONAL_SOURCES" ]]; then
        mv "$PERSONAL_SOURCES" "${PERSONAL_SOURCES}.disabled"
        log "Disabled the personal repo source (${PERSONAL_SOURCES}.disabled)."
    fi
    if [[ -f "$PERSONAL_PIN_FILE" ]]; then
        mv "$PERSONAL_PIN_FILE" "${PERSONAL_PIN_FILE}.disabled"
        log "Disabled the personal repo pin (${PERSONAL_PIN_FILE}.disabled)."
    fi

    echo
    log "Running apt-get update..."
    apt-get update

    echo
    log "Verifying the community repo is visible to apt (looking for grommunio-setup)..."
    if pkg_candidate_source grommunio-setup | grep -qF "$COMMUNITY_URL"; then
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
# Option 1: community baseline + personal build packages on top
# (file-based flat repo, pinned above community for whatever it
# actually contains - everything else still resolves from community)
# ============================================================

configure_personal()
{
    configure_community_baseline || return 1

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

    # One of the package names actually in REPO_DIR, used below to verify
    # pinning really took effect (not hardcoded to e.g. grommunio-archive,
    # since REPO_DIR's actual contents vary by server).
    local sample_pkg
    sample_pkg="$(dpkg-deb -f "$(find "$REPO_DIR" -maxdepth 1 -name '*.deb' | head -1)" Package 2>/dev/null)"

    backup_file "$PERSONAL_SOURCES"
    echo "deb [trusted=yes] file://${REPO_DIR} ./" > "$PERSONAL_SOURCES"
    chmod 644 "$PERSONAL_SOURCES"
    finalize_backup "$PERSONAL_SOURCES"
    log "Wrote $PERSONAL_SOURCES (added alongside $COMMUNITY_SOURCES, not instead of it)."

    # Pin: origin "" matches a local/file-based source with no Release
    # Origin field (exactly what dpkg-scanpackages produces - a flat
    # repo has no Release file at all) - the standard APT mechanism for
    # "prefer this local archive's packages over every other configured
    # source, for whichever packages it actually has." Priority 900 (not
    # >1000): prefer it when a package exists in both, but don't force a
    # downgrade if this pool is ever stale relative to community for the
    # same package - a real possibility since the pool is a manual copy,
    # not kept live in sync automatically.
    backup_file "$PERSONAL_PIN_FILE"
    cat > "$PERSONAL_PIN_FILE" <<EOF
# Managed by 25-apt-repo-personal.sh - do not edit by hand.
# Prefers this server's own local package pool over the grommunio
# community repo, for whichever packages it actually contains. Anything
# NOT in the local pool is unaffected and still resolves from community.
Package: *
Pin: origin ""
Pin-Priority: 900
EOF
    chmod 644 "$PERSONAL_PIN_FILE"
    finalize_backup "$PERSONAL_PIN_FILE"
    log "Wrote $PERSONAL_PIN_FILE (pins the local pool above community, selectively)."

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
    log "Verifying community packages are still reachable (looking for grommunio-setup)..."
    if pkg_candidate_source grommunio-setup | grep -qF "$COMMUNITY_URL"; then
        log "OK: grommunio-setup's candidate still comes from $COMMUNITY_URL."
    else
        die "grommunio-setup's candidate does not come from $COMMUNITY_URL after apt-get update - the community baseline should never be affected by adding the personal repo on top."
    fi

    echo
    log "Verifying the local pool's own packages are preferred over community..."
    if [[ -n "$sample_pkg" ]] && pkg_candidate_source "$sample_pkg" | grep -qF "file:${REPO_DIR}"; then
        log "OK: $sample_pkg's candidate comes from the local pool (file://${REPO_DIR}), confirming the pin works."
    else
        err "Could not confirm a local-pool package ($sample_pkg) is actually preferred over community."
        err "Check apt-cache policy $sample_pkg by hand, and that $PERSONAL_PIN_FILE was applied."
        die "Pin verification failed."
    fi

    save_cfg "$CFG" "PKG_SOURCE=$PKG_SOURCE" "REPO_DIR=$REPO_DIR"
    log "Saved configuration for replay: $CFG"

    echo
    echo "============================================================"
    echo " Done"
    echo "============================================================"
    echo
    echo "Repo configured: $COMMUNITY_URL (community, baseline) +"
    echo "file://${REPO_DIR} (personal, $deb_count package(s), pinned above community)"
    echo
    echo "Refresh the personal pool anytime by re-copying .debs into"
    echo "$REPO_DIR and re-running this step."
    echo
}

case "$PKG_SOURCE" in
    personal)  configure_personal ;;
    community) configure_community ;;
    *)         err "Unknown package source in $CFG: $PKG_SOURCE"; return 1 ;;
esac
}
