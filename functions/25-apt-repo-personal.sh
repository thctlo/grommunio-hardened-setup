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
#        c. generates Packages(.gz) and a minimal Release file (with a
#           unique Origin: this repo, and only this repo, ever sets)
#           with dpkg-scanpackages
#        d. adds `deb [trusted=yes] file://REPO_DIR ./` (trusted=yes
#           because the files arrived over a channel we already trust,
#           scp/ssh) ALONGSIDE the community source, not instead of it
#        e. pins that local repo to a higher priority than community
#           (APT preferences, `Pin: release o=personal-build` -
#           matches the Release file's Origin written in step c, NOT
#           "any source with no hostname" - that broader match was
#           tried first and turned out to also match Debian's own
#           base/backports sources when those are configured via a
#           `mirror+file://` URI, see the pin's own comment further
#           down in this file for the full story) so a package present
#           in BOTH resolves from the local repo, and anything only in
#           community (or Debian's own base/backports) still resolves
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
local PERSONAL_REPO_ORIGIN="personal-build"
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
# lower-priority entry) and not "***" (apt-cache policy only prefixes
# an INSTALLED version with that, so it's absent on a fresh system
# with nothing installed yet, but present - shifting every field one
# over - when the package is already installed, found live on testvps
# where grommunio-setup already was). Only starts matching after the
# "Version table:" line, so the "Installed:"/"Candidate:" summary
# lines above it (which also contain the version string as a field)
# can never be mistaken for a version-table entry.
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

    # A minimal Release file with a unique Origin, so the pin below can
    # target THIS repo specifically (see the pin comment further down
    # for why that precision matters - a bare "local source" match is
    # not specific enough). Includes real MD5Sum/SHA256 entries for
    # Packages/Packages.gz - without them apt logs a "No Hash entry"
    # warning on every update (found live: this warning did not exist
    # before this repo had a Release file at all, and a warning that
    # wasn't there before is worth actually fixing, not just living
    # with, now that the file exists anyway).
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

    # One of the package names actually in REPO_DIR, used below to verify
    # pinning really took effect (not hardcoded to e.g. grommunio-archive,
    # since REPO_DIR's actual contents vary by server). Read from the
    # Packages index just generated above, not a filesystem find - a
    # real repo pool is typically nested (pool/main/<letter>/<pkg>/...,
    # reprepro's own layout, confirmed live on testvps), so a shallow
    # find here found nothing and crashed this step entirely.
    local sample_pkg
    sample_pkg="$(awk -F': ' '/^Package:/{print $2; exit}' "$REPO_DIR/Packages")"

    backup_file "$PERSONAL_SOURCES"
    echo "deb [trusted=yes] file://${REPO_DIR} ./" > "$PERSONAL_SOURCES"
    chmod 644 "$PERSONAL_SOURCES"
    finalize_backup "$PERSONAL_SOURCES"
    log "Wrote $PERSONAL_SOURCES (added alongside $COMMUNITY_SOURCES, not instead of it)."

    # REAL BUG FOUND AND FIXED LIVE 2026-11-12: this pin originally used
    # `Pin: origin ""` (matches any source with no hostname - the
    # standard way to prefer "a local archive"). That is NOT specific
    # enough: Debian's own base sources can ALSO be configured via a
    # `mirror+file://` URI (a local mirror-selection file, confirmed
    # live on testvps's own /etc/apt/sources.list.d/debian.sources,
    # covering trixie/trixie-updates/trixie-security/trixie-backports
    # all at once) - which APT ALSO treats as hostname-less for pin
    # purposes. The old pin silently raised trixie-backports to the
    # same priority as stable (900, tied with everything else), which
    # would let apt pull a backports version of ANY package server-wide
    # on the next upgrade - confirmed live via apt-cache policy showing
    # every Debian suite, backports included, pinned to 900. No actual
    # package had been upgraded yet when this was caught, but
    # install-unattended-upgrades.sh runs unattended and would have hit
    # this on its own schedule.
    #
    # Fixed to `Pin: release o=${PERSONAL_REPO_ORIGIN}` instead - this
    # matches a Release file's own "Origin:" field (an arbitrary label,
    # unrelated to hostname matching - see apt_preferences(5) for the
    # explicit distinction between the two), which only the Release
    # file written above sets to this exact value. Verified in an
    # isolated apt sandbox with a real mirror+file-style source present
    # alongside the personal repo: the fixed pin leaves the mirror+file
    # source at its normal priority (500) and only raises the personal
    # repo's own packages to 900.
    backup_file "$PERSONAL_PIN_FILE"
    cat > "$PERSONAL_PIN_FILE" <<EOF
# Managed by 25-apt-repo-personal.sh - do not edit by hand.
# Prefers this server's own local package pool over the grommunio
# community repo, for whichever packages it actually contains. Anything
# NOT in the local pool is unaffected and still resolves from community
# (or any other configured source, e.g. Debian's own base/backports -
# this pin is scoped to this repo's own Release Origin specifically,
# not to "any local source" - see the comment above for why that
# distinction matters).
Package: *
Pin: release o=${PERSONAL_REPO_ORIGIN}
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
