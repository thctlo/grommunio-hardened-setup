#!/usr/bin/env bash
#
# 15-locale-timezone.sh
#
# Runs after hostname/network (10) and before firewall/fail2ban (20):
#   - Asks for the system default locale (recommended en_US.UTF-8), then for
#     the extra languages to install. The extra languages are the ones
#     grommunio-web supports (server/language in grommunio-web 5.1.18, all of
#     them enabled by default there). Each one is generated only if the system
#     has a matching UTF-8 locale.
#   - Asks to confirm the timezone and local time, then sets the timezone and
#     makes sure the clock is NTP synced (wrong time breaks TLS cert
#     validation, Let's Encrypt issuance, log timestamps and fail2ban ban
#     durations).
#
# Low risk, no SSH-disconnect danger like the network/firewall steps, so this
# step does not gate behind a "Proceed? [y/N]" confirmation. Saved answers are
# reused on replay; delete /root/cfg-server/15-locale-timezone.conf to be asked
# again.

# grommunio-web 5.1.18 server/language, all enabled by default (defaults.php)
GROMMUNIO_LANGS=(
    af_ZA am_ET ar_DZ ar_SA as_IN az_AZ be_BY bg_BG bn_BD bn_IN bs_BA
    ca_ES ca_ES@valencia cs_CZ cy_GB da_DK de_CH de_DE el_GR en_GB en_US
    es_ES et_EE eu_ES fa_IR fi_FI fil_PH fr_CA fr_FR ga_IE gd_GB gl_ES gu_IN
    he_IL hi_IN hr_HR hu_HU hy_AM id_ID is_IS it_IT ja_JP ka_GE kk_KZ km_KH
    kn_IN kok_IN ko_KR ky_KG lb_LU lo_LA lt_LT lv_LV mi_NZ mk_MK ml_IN mn_MN
    mr_IN ms_MY mt_MT my_MY nb_NO ne_NP nl_NL nn_NO or_IN pa_IN pl_PL prs_AF
    pt_BR pt_PT quz_PE ro_RO ru_RU sd_IN si_LK sk_SK sl_SI sq_AL sr_BA sr_RS
    sr_RS@latin sv_SE sw_KE ta_IN te_IN th_TH tk_TM tr_TR tt_RU ug_CN uk_UA
    ur_PK uz_UZ vi_VN zh_CN zh_TW zu_ZA
)

# Shown first in the prompt; any code in GROMMUNIO_LANGS is accepted.
GROMMUNIO_LANGS_COMMON=(nl_NL de_DE fr_FR es_ES it_IT pt_BR pl_PL ru_RU tr_TR sv_SE da_DK nb_NO fi_FI cs_CZ ja_JP zh_CN ko_KR en_GB de_CH fr_CA)

# Turns a grommunio language code (de_DE, ca_ES@valencia) into the locale
# name used in /usr/share/i18n/SUPPORTED (de_DE.UTF-8, ca_ES.UTF-8@valencia).
code_to_locale()
{
    local code="$1"
    if [[ "$code" == *@* ]]; then
        echo "${code%@*}.UTF-8@${code#*@}"
    else
        echo "${code}.UTF-8"
    fi
}

step_locale_timezone()
{
local CFG="$(cfg_file 15-locale-timezone)"
local SAVED_DEFAULT_LANG="" SAVED_TIMEZONE=""
local -a SAVED_LOCALES=()
local DEFAULT_LANG="" TIMEZONE=""
local -a LOCALES_TO_GENERATE=()
local -a EXTRA_LANGS=()

require_cmd apt-get
require_cmd sed
require_cmd timedatectl
require_cmd systemctl

# ============================================================
# Load saved config, if any
# ============================================================

if [[ -f "$CFG" ]]; then
    # shellcheck disable=SC1090
    source "$CFG"
    SAVED_DEFAULT_LANG="${DEFAULT_LANG:-}"
    SAVED_TIMEZONE="${TIMEZONE:-}"
    if [[ -n "${LOCALES_TO_GENERATE+x}" ]]; then
        SAVED_LOCALES=("${LOCALES_TO_GENERATE[@]}")
    fi
    DEFAULT_LANG=""; TIMEZONE=""; LOCALES_TO_GENERATE=()
    [[ -n "$SAVED_DEFAULT_LANG" ]] && log "Found saved configuration: $CFG"
fi

if [[ -n "$SAVED_DEFAULT_LANG" ]]; then
    DEFAULT_LANG="$SAVED_DEFAULT_LANG"
    TIMEZONE="$SAVED_TIMEZONE"
    LOCALES_TO_GENERATE=("${SAVED_LOCALES[@]}")
    log "Using saved locale/timezone settings (delete $CFG to be asked again):"
    log "  Default LANG : $DEFAULT_LANG"
    log "  Timezone     : $TIMEZONE"
    log "  Locales      : ${LOCALES_TO_GENERATE[*]}"
else
    echo
    echo "============================================================"
    echo " Locale and timezone"
    echo "============================================================"

    # --- 1. default system locale ------------------------------------
    echo
    echo "System default locale (LANG). Recommended: en_US.UTF-8"
    read -r -p "Default locale [en_US.UTF-8]: " DEFAULT_LANG
    DEFAULT_LANG="${DEFAULT_LANG:-en_US.UTF-8}"

    # --- 2. extra grommunio-supported languages ----------------------
    echo
    echo "Extra languages for grommunio (supported by grommunio-web)."
    echo "Common choices:"
    printf '    %s\n' "${GROMMUNIO_LANGS_COMMON[@]}" | paste -sd' ' | sed 's/^/    /'
    echo "Enter codes separated by spaces, 'all' for every grommunio language,"
    echo "or press Enter for none."
    read -r -p "Extra languages [none]: " extra_csv
    extra_csv="${extra_csv:-none}"
    if [[ "$extra_csv" == "all" ]]; then
        EXTRA_LANGS=("${GROMMUNIO_LANGS[@]}")
    elif [[ "$extra_csv" == "none" ]]; then
        EXTRA_LANGS=()
    else
        read -r -a EXTRA_LANGS <<< "$extra_csv"
        local code
        for code in "${EXTRA_LANGS[@]}"; do
            if ! printf '%s\n' "${GROMMUNIO_LANGS[@]}" | grep -qxF "$code"; then
                err "Not a grommunio-supported language: $code"
                return 1
            fi
        done
    fi

    # --- 3. timezone and local time ----------------------------------
    echo
    local CURRENT_TZ CURRENT_TIME
    CURRENT_TZ="$(timedatectl show -p Timezone --value 2>/dev/null || true)"
    CURRENT_TZ="${CURRENT_TZ:-Europe/Amsterdam}"
    CURRENT_TIME="$(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo "Current timezone : $CURRENT_TZ"
    echo "Current local time: $CURRENT_TIME"
    echo "The clock is kept exact by NTP once this step finishes. Check that the"
    echo "timezone and time shown are right for your location."
    read -r -p "Are the timezone and local time correct? [Y/n]: " tz_ok
    if [[ "${tz_ok:-Y}" =~ ^[Yy]$ ]]; then
        TIMEZONE="$CURRENT_TZ"
    else
        read -r -p "Timezone (as in /usr/share/zoneinfo, e.g. Europe/Amsterdam) [Europe/Amsterdam]: " TIMEZONE
        TIMEZONE="${TIMEZONE:-Europe/Amsterdam}"
    fi
fi

# ============================================================
# Locales: default + extras, each checked against the system's list
# ============================================================

echo
log "Ensuring 'locales' package is installed..."
if ! dpkg -s locales >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y locales
fi

SUPPORTED_FILE="/usr/share/i18n/SUPPORTED"
[[ -f "$SUPPORTED_FILE" ]] || die "Missing $SUPPORTED_FILE (is the locales package installed?)"

locale_supported()
{
    grep -qxF "$1 UTF-8" "$SUPPORTED_FILE"
}

# Build LOCALES_TO_GENERATE from the default locale and the extras.
# On replay the saved list is kept as it is.
if [[ -z "$SAVED_DEFAULT_LANG" ]]; then
    if ! locale_supported "$DEFAULT_LANG"; then
        die "Default locale is not available on this system: $DEFAULT_LANG"
    fi
    LOCALES_TO_GENERATE=("$DEFAULT_LANG")
    if [[ ${#EXTRA_LANGS[@]} -gt 0 ]]; then
        for code in "${EXTRA_LANGS[@]}"; do
            loc="$(code_to_locale "$code")"
            if locale_supported "$loc"; then
                LOCALES_TO_GENERATE+=("$loc")
            else
                err "No system locale for $code ($loc). Skipped."
            fi
        done
    fi
fi

# Locales of the admin's own SSH session (LANG and LC_*, forwarded by ssh). If
# they are not generated here, tools such as apt-listchanges and perl warn
# "Setting locale failed" and fall back to C.UTF-8. These are added on every
# run, including replay, so they are never missing from the saved list.
in_locale_list()
{
    local x
    for x in "${LOCALES_TO_GENERATE[@]}"; do
        [[ "$x" == "$1" ]] && return 0
    done
    return 1
}

local sess_var sess_val sess_loc
while IFS='=' read -r sess_var sess_val; do
    case "$sess_var" in
        LANG|LC_*) ;;
        *) continue ;;
    esac
    case "$sess_val" in
        ""|C|POSIX|C.UTF-8|C.utf8) continue ;;
    esac
    sess_loc="$sess_val"
    [[ "$sess_loc" == *.* ]] || sess_loc="${sess_loc}.UTF-8"
    if in_locale_list "$sess_loc"; then
        continue
    fi
    if locale_supported "$sess_loc"; then
        LOCALES_TO_GENERATE+=("$sess_loc")
        log "Adding the locale of your SSH session: $sess_loc"
    else
        err "Locale of your SSH session ($sess_loc) is not available on this system; skipped."
    fi
done < <(env)

local LOCALE_GEN_NEEDED=0

enable_locale()
{
    local entry="$1"                       # e.g. "en_US.UTF-8 UTF-8"
    local escaped="${entry//./\\.}"
    if grep -qxF "$entry" /etc/locale.gen; then
        return 0
    fi
    backup_file /etc/locale.gen
    if grep -qE "^# ?${escaped}\$" /etc/locale.gen; then
        sed -i -E "s/^# ?${escaped}\$/${entry}/" /etc/locale.gen
    else
        echo "$entry" >> /etc/locale.gen
    fi
    finalize_backup /etc/locale.gen
    LOCALE_GEN_NEEDED=1
}

local loc entry
for loc in "${LOCALES_TO_GENERATE[@]}"; do
    [[ -z "$loc" ]] && continue
    entry="${loc} UTF-8"
    log "Enabling locale: $entry"
    enable_locale "$entry"
done

if [[ "$LOCALE_GEN_NEEDED" -eq 1 ]]; then
    log "Running locale-gen..."
    locale-gen
else
    log "[ OK ] All requested locales were already enabled; locale-gen skipped."
fi

log "Setting system default locale: LANG=$DEFAULT_LANG"
update-locale LANG="$DEFAULT_LANG"

echo
log "Locales now available (locale -a):"
locale -a | sed 's/^/    /'

# ============================================================
# Timezone
# ============================================================

echo
log "Setting timezone: $TIMEZONE"
if [[ ! -e "/usr/share/zoneinfo/${TIMEZONE}" ]]; then
    die "Unknown timezone: $TIMEZONE (no /usr/share/zoneinfo/${TIMEZONE})"
fi
timedatectl set-timezone "$TIMEZONE"

local ACTUAL_TZ
ACTUAL_TZ="$(timedatectl show -p Timezone --value)"
[[ "$ACTUAL_TZ" == "$TIMEZONE" ]] || die "Timezone verification failed: expected $TIMEZONE, got $ACTUAL_TZ"
log "Timezone confirmed: $ACTUAL_TZ"

# ============================================================
# NTP time sync
# ============================================================

echo
if ! dpkg -s systemd-timesyncd >/dev/null 2>&1; then
    log "Installing systemd-timesyncd..."
    apt-get install -y systemd-timesyncd
fi

log "Enabling NTP sync..."
timedatectl set-ntp true
systemctl enable --now systemd-timesyncd >/dev/null 2>&1 || true

local waited=0 synced="no"
while (( waited < 20 )); do
    synced="$(timedatectl show -p NTPSynchronized --value)"
    [[ "$synced" == "yes" ]] && break
    sleep 2
    waited=$((waited + 2))
done

if [[ "$synced" == "yes" ]]; then
    log "Clock is NTP-synced."
else
    err "Clock did not report NTP-synced within ${waited}s — it may still catch up shortly on its own."
    err "Check manually with: timedatectl status"
fi

echo
echo "Current time status:"
timedatectl status | sed 's/^/    /'

save_cfg "$CFG" "DEFAULT_LANG=$DEFAULT_LANG" "TIMEZONE=$TIMEZONE"
save_cfg_array_append "$CFG" LOCALES_TO_GENERATE "${LOCALES_TO_GENERATE[@]}"
log "Saved configuration for replay: $CFG"

echo
echo "============================================================"
echo " Done"
echo "============================================================"
echo
}
