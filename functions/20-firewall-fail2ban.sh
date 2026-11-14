#!/usr/bin/env bash
#
# 20-firewall-fail2ban.sh
#
# Installs a firewall (firewalld or ufw — operator's choice, persisted) plus
# fail2ban, hardened for SSH-only-from-whitelist before anything else is
# opened. Ports functions/2-setup-firewalld-fail2ban.sh and
# functions/2-setup-ufw-fail2ban.sh (both under /srv/builder/bin/, kept as
# standalone scripts per the no-delete rule) into step_firewall_fail2ban()
# for server-setup.sh.
#
# Config persistence (/root/cfg-server/20-firewall-fail2ban.conf):
#   FW_BACKEND     - "firewalld" or "ufw". This is a DECISION, so it is
#                    reused on replay without asking again — this is the
#                    main point of the config file: it tells fail2ban which
#                    banaction to use so the override always matches
#                    whichever firewall is actually in charge.
#   WHITELIST_IPS  - array of IPs with full access. Reused as the starting
#                    point on replay, but NOT blindly trusted: the operator's
#                    current SSH session IP(s) are always freshly detected
#                    and merged in, and the final list is always shown again
#                    before the "Proceed?" confirmation. A stale whitelist
#                    that no longer includes whoever is running this replay
#                    would lock them out the moment the firewall reloads, so
#                    this is the one prompt that is NEVER fully skipped.
#
# SSH_PORT is never persisted — it is a live fact re-read from
# /etc/ssh/sshd_config(.d) on every run, not a decision.
#
# Target: Debian 13 (trixie). grommunio's own documented firewall is
# firewalld (see its setup wizard's firewall-cmd calls), so that is the
# default offered; ufw is kept as an option for servers that use it.

# firewalld_jail_sets <jail=ports>...: permanent firewalld ipsets f2b-<jail> (IPv4)
# and f2b-<jail>6 (IPv6), each with a permanent REJECT rule for the jail's ports
# (e.g. sshd=22). A ban blocks only those ports until recidive picks the address up;
# recidive=0:65535 blocks all ports. fail2ban adds banned
# addresses to these sets at ban time. The sets and rules exist before fail2ban
# starts, so no "NOT_ENABLED" warnings and no gap after a firewalld start.
# A firewalld reload clears ban entries, so the caller restarts fail2ban after
# the reload; fail2ban then puts its unexpired bans back (tested 2026-10-04).
firewalld_jail_sets()
{
    local spec jail ports set ipver reject line fam
    local existing_sets existing_rules
    for spec in "$@"; do
        jail="${spec%%=*}"; ports="${spec#*=}"
        for set in "f2b-${jail}" "f2b-${jail}6"; do
            if [[ "$set" == *6 ]]; then ipver="ipv6"; reject="icmp6-port-unreachable"; fam="inet6"
            else ipver="ipv4"; reject="icmp-port-unreachable"; fam="inet"; fi
            existing_sets=" $(firewall-cmd --permanent --get-ipsets) "
            if [[ "$existing_sets" != *" $set "* ]]; then
                firewall-cmd --permanent --new-ipset="$set" --type=hash:ip --option=timeout=3600 --option=maxelem=65536 --option=family="$fam" >/dev/null \
                    || die "firewalld could not create the permanent ipset $set."
            fi
            line="$ipver filter INPUT_direct 0 -p tcp -m multiport --dports $ports -m set --match-set $set src -j REJECT --reject-with $reject"
            existing_rules="$(firewall-cmd --permanent --direct --get-all-rules)"
            if ! grep -qxF "$line" <<< "$existing_rules"; then
                # shellcheck disable=SC2086
                firewall-cmd --permanent --direct --add-rule $line >/dev/null \
                    || die "firewalld could not add the permanent rule for $set."
            fi
        done
    done
    log "[ OK ] Permanent firewall sets and rules for fail2ban jails: $*"
}

# Scanners that fail2ban must never ban (its ignoreip only; they get no firewall access).
# SSL Labs (Qualys) test scanners, 2026-10-04: a test run got banned by nginx-bad-request.
# TrustConnect mail-TLS checker (https://mailcheck.trustconnect.nl/), 2026-11-04:
# a scan got banned by postfix-abuse (rapid sequential STARTTLS probes on port 25).
SCANNER_IGNORE_IPS=(69.67.183.0/24 2602:fdaa:c6:2::/64 64.39.109.20 31.160.87.193)

step_firewall_fail2ban()
{
local FAIL2BAN_OVERRIDE="/etc/fail2ban/jail.d/zz-hardening.local"
local ZONE="public"

local CFG="$(cfg_file 20-firewall-fail2ban)"
local SAVED_FW_BACKEND=""
local -a SAVED_WHITELIST_IPS=()
local FW_BACKEND=""
local SSH_PORT=""
local -a WHITELIST_IPS=()
local -a DETECTED_IPS=()

require_cmd apt-get
require_cmd systemctl
require_cmd awk
require_cmd grep

export DEBIAN_FRONTEND=noninteractive

# ============================================================
# Load saved config, if any
# ============================================================

if [[ -f "$CFG" ]]; then
    # shellcheck disable=SC1090
    source "$CFG"
    SAVED_FW_BACKEND="${FW_BACKEND:-}"
    if [[ -n "${WHITELIST_IPS+x}" ]]; then
        SAVED_WHITELIST_IPS=("${WHITELIST_IPS[@]}")
    fi
    FW_BACKEND=""
    WHITELIST_IPS=()
    if [[ -n "$SAVED_FW_BACKEND" ]]; then
        log "Found saved configuration: $CFG"
    fi
fi

# ============================================================
# 1. Determine the SSH port sshd is actually configured for
#    (always re-detected fresh, never persisted).
# ============================================================

detect_ssh_port()
{
    local port=""
    if [[ -d /etc/ssh/sshd_config.d ]]; then
        port="$(grep -h -i '^[[:space:]]*Port[[:space:]]' /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
                | awk '{print $2}' | head -n1 || true)"
    fi
    if [[ -z "$port" && -f /etc/ssh/sshd_config ]]; then
        port="$(grep -i '^[[:space:]]*Port[[:space:]]' /etc/ssh/sshd_config 2>/dev/null \
                | awk '{print $2}' | head -n1 || true)"
    fi
    [[ -z "$port" ]] && port="22"
    echo "$port"
}

SSH_PORT="$(detect_ssh_port)"
log "Detected SSH port: $SSH_PORT"

# ============================================================
# 2. Choose firewall backend: reuse saved decision, else ask
# ============================================================

if [[ -n "$SAVED_FW_BACKEND" ]]; then
    FW_BACKEND="$SAVED_FW_BACKEND"
    log "Using saved firewall backend (delete $CFG to be asked again): $FW_BACKEND"
else
    echo
    echo "============================================================"
    echo " Firewall backend"
    echo "============================================================"
    echo
    echo "grommunio's own documented firewall is firewalld (its setup wizard"
    echo "calls firewall-cmd directly). Choose ufw only for a server that is"
    echo "meant to keep using it."
    echo
    local BACKEND_CHOICE
    read -r -p "Use [f]irewalld or [u]fw? [f]: " BACKEND_CHOICE
    BACKEND_CHOICE="${BACKEND_CHOICE:-f}"
    case "${BACKEND_CHOICE,,}" in
        f|firewalld) FW_BACKEND="firewalld" ;;
        u|ufw)       FW_BACKEND="ufw" ;;
        *)           die "Invalid choice: $BACKEND_CHOICE" ;;
    esac
    log "Selected firewall backend: $FW_BACKEND"
fi

# ============================================================
# 3. Detect the IP(s) of the currently logged-in SSH user
#    (always freshly detected, merged with any saved whitelist)
# ============================================================

detect_from_ssh_connection()
{
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        local client_ip
        client_ip="$(awk '{print $1}' <<< "$SSH_CONNECTION")"
        [[ -n "$client_ip" ]] && echo "$client_ip"
    fi
}

detect_from_who()
{
    if command -v who >/dev/null 2>&1; then
        who 2>/dev/null | grep -oE '\(([0-9a-fA-F:.]+)\)' | tr -d '()' || true
    fi
}

detect_from_ss()
{
    if command -v ss >/dev/null 2>&1; then
        ss -tnH state established "( sport = :${SSH_PORT} )" 2>/dev/null \
            | awk '{print $4}' \
            | sed -E 's/^\[?([0-9a-fA-F:.]+)\]?:[0-9]+$/\1/' || true
    fi
}

local raw candidate ip
local ssh_connection_ip
ssh_connection_ip="$(detect_from_ssh_connection)"
raw=""
raw+="$ssh_connection_ip"$'\n'
raw+="$(detect_from_who)"$'\n'
raw+="$(detect_from_ss)"$'\n'

while IFS= read -r candidate; do
    [[ -z "$candidate" ]] && continue
    if is_valid_ipv4 "$candidate" || is_valid_ipv6 "$candidate"; then
        [[ "$candidate" == "127.0.0.1" || "$candidate" == "::1" ]] && continue
        DETECTED_IPS+=("$candidate")
    fi
done <<< "$raw"

[[ "${#DETECTED_IPS[@]}" -gt 0 ]] && mapfile -t DETECTED_IPS < <(printf '%s\n' "${DETECTED_IPS[@]}" | sort -u)

if [[ "${#SAVED_WHITELIST_IPS[@]}" -gt 0 ]]; then
    log "Saved whitelist from $CFG:"
    for ip in "${SAVED_WHITELIST_IPS[@]}"; do log "  - $ip"; done
fi

# There is exactly one real SSH client for this install session. who/ss can
# surface OTHER logged-in sessions too (another admin, a stale connection),
# so more than one candidate here is ambiguous - whitelisting the wrong one
# is a lockout risk, same reasoning as the manual-entry prompt below. Force
# an explicit single choice instead of silently trusting all of them.
if [[ "${#DETECTED_IPS[@]}" -eq 0 ]]; then
    log "No SSH client IP could be detected automatically for this session."
elif [[ "${#DETECTED_IPS[@]}" -eq 1 ]]; then
    log "Detected current SSH client IP:"
    log "  - ${DETECTED_IPS[0]}"
else
    log "Multiple possible SSH client IPs were detected - who/ss can also see"
    log "OTHER logged-in sessions, not just this one:"
    echo
    local default_idx=0 i
    for i in "${!DETECTED_IPS[@]}"; do
        if [[ -n "$ssh_connection_ip" && "${DETECTED_IPS[$i]}" == "$ssh_connection_ip" ]]; then
            printf '  %d) %s  (default - this session'"'"'s own SSH_CONNECTION)\n' "$((i + 1))" "${DETECTED_IPS[$i]}"
            default_idx=$((i + 1))
        else
            printf '  %d) %s\n' "$((i + 1))" "${DETECTED_IPS[$i]}"
        fi
    done
    echo "  0) None of these - skip, I'll enter it manually below"
    echo
    local choice chosen_ip="" prompt_suffix="0-${#DETECTED_IPS[@]}"
    [[ "$default_idx" -gt 0 ]] && prompt_suffix="$prompt_suffix, default ${default_idx}"
    while true; do
        read -r -p "Exactly one of these is your current SSH client IP - which one? [${prompt_suffix}]: " choice
        [[ -z "$choice" && "$default_idx" -gt 0 ]] && choice="$default_idx"
        if [[ "$choice" == "0" ]]; then
            break
        elif [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#DETECTED_IPS[@]} )); then
            chosen_ip="${DETECTED_IPS[$((choice - 1))]}"
            break
        fi
        echo "Invalid choice, try again."
    done
    DETECTED_IPS=()
    [[ -n "$chosen_ip" ]] && DETECTED_IPS+=("$chosen_ip")
    if [[ -n "$chosen_ip" ]]; then
        log "Using detected IP: $chosen_ip"
    else
        log "Skipped auto-detected IPs; add your own below if needed."
    fi
fi

WHITELIST_IPS=("${SAVED_WHITELIST_IPS[@]}" "${DETECTED_IPS[@]}")

# Always give the operator a chance to add IPs — detection can be wrong
# (jump hosts, NAT, multiple admins) and a wrong whitelist means a lockout.
local manual_v4 manual_v6
read -r -p "Enter an additional/override IPv4 address to whitelist (enter to skip): " manual_v4
if [[ -n "$manual_v4" ]]; then
    is_valid_ipv4 "$manual_v4" || die "Invalid IPv4 address: $manual_v4"
    WHITELIST_IPS+=("$manual_v4")
fi

read -r -p "Enter an additional/override IPv6 address to whitelist (enter to skip): " manual_v6
if [[ -n "$manual_v6" ]]; then
    is_valid_ipv6 "$manual_v6" || die "Invalid IPv6 address: $manual_v6"
    WHITELIST_IPS+=("$manual_v6")
fi

if [[ "${#WHITELIST_IPS[@]}" -eq 0 ]]; then
    die "No IP addresses to whitelist (none saved, none detected, none entered). Refusing to enable a default-deny firewall with no SSH access rule."
fi

mapfile -t WHITELIST_IPS < <(printf '%s\n' "${WHITELIST_IPS[@]}" | sort -u)

echo
echo "============================================================"
echo " Firewall + fail2ban configuration"
echo "============================================================"
echo
echo "Backend: $FW_BACKEND"
echo
echo "Final whitelist for SSH (port $SSH_PORT), full access:"
for ip in "${WHITELIST_IPS[@]}"; do echo "  - $ip"; done
echo

# ============================================================
# APPLY — always confirmed explicitly, saved config or not.
# ============================================================

local CONFIRM
read -r -p "Proceed and enable $FW_BACKEND with this whitelist? [y/N]: " CONFIRM
if [[ ! "${CONFIRM,,}" =~ ^(y|yes)$ ]]; then
    echo; echo "Aborted. Nothing was changed."; return 0
fi

if [[ "$FW_BACKEND" == "firewalld" ]]; then

    # --------------------------------------------------------
    # firewalld path
    # --------------------------------------------------------

    if ! command -v firewall-cmd >/dev/null 2>&1; then
        log "Installing firewalld..."
        apt-get update -qq
        apt-get install -y firewalld
    else
        log "firewalld already installed."
    fi

    systemctl enable --now firewalld >/dev/null 2>&1 || true

    log "Setting zone '$ZONE' target to DROP (deny everything not explicitly allowed)..."
    firewall-cmd --permanent --zone="$ZONE" --set-target=DROP

    # The Debian firewalld package ships the "ssh" service pre-enabled in
    # the public zone — that would open SSH to everyone via a SECOND,
    # redundant rule alongside the explicit port below. Remove it; access
    # is granted per-IP below.
    # Policy (2026-10-04): SSH is open to all public addresses. fail2ban's sshd
    # jail handles brute-force attempts. Whitelisted addresses also get full
    # access, below.
    #
    # REAL BUG FOUND 2026-10-25: this comment described removing the "ssh"
    # service, but no code ever actually called --remove-service=ssh - only
    # the explicit port below was added, so both the "ssh" service AND
    # port 22/tcp ended up listed side by side (`firewall-cmd --list-all`
    # showed "services: ... ssh" and "ports: 22/tcp ..." at the same time).
    # Harmless in effect (both allow the same port, from everyone, same as
    # the policy above already intends), but not what was documented or
    # idempotent-per-run - fixed to actually remove it, every run.
    if firewall-cmd --permanent --zone="$ZONE" --query-service=ssh >/dev/null 2>&1; then
        firewall-cmd --permanent --zone="$ZONE" --remove-service=ssh >/dev/null
        log "Removed the redundant 'ssh' firewalld service (port ${SSH_PORT}/tcp below already covers it)."
    fi

    if ! firewall-cmd --permanent --zone="$ZONE" --query-port="${SSH_PORT}/tcp" >/dev/null 2>&1; then
        log "Opening SSH (port ${SSH_PORT}/tcp) for all public addresses..."
        firewall-cmd --permanent --zone="$ZONE" --add-port="${SSH_PORT}/tcp"
    fi

    # dhcpv6-client only lets this host obtain its own IPv6 address; it does
    # not open a listening service to anyone. Keep it.
    firewall-cmd --permanent --zone="$ZONE" --add-service=dhcpv6-client >/dev/null 2>&1 || true

    # Known gap in grommunio-setup's own firewall-opening code (confirmed
    # directly in /usr/share/grommunio-setup/grommunio-setup: it opens
    # 25/80/110/143/587/993/8080/8443/tcp + the https service, but never
    # 995/tcp) — POP3S ends up listening but unreachable, asymmetric with
    # IMAPS (993) being open. grommunio-setup runs later (step 30) and only
    # ever ADDS its own ports idempotently, so pre-opening 995 here now is
    # safe and doesn't conflict with anything it does later.
    firewall-cmd --permanent --zone="$ZONE" --add-port=995/tcp >/dev/null 2>&1 || true

    # Port 465 (SMTPS/implicit-TLS submission, RFC 8314) - deliberately
    # deferred TODO until now (see 35-saslauthd.sh for the matching
    # 'submissions' master.cf listener this port exists for). Opened here
    # for the same reason 995 is: cheap to pre-open, idempotent, and
    # doesn't conflict with anything grommunio-setup (step 30) does later.
    firewall-cmd --permanent --zone="$ZONE" --add-port=465/tcp >/dev/null 2>&1 || true

    # WHITELIST_IPS get FULL access (no port restriction) — not just SSH.
    # Found live 2026-09-30: this had silently only ever granted port 22,
    # contradicting this file's own documented intent above ("array of IPs
    # with full access"). Upgrades any old port-22-only rule from a
    # previous run of this step to the broader one instead of leaving both.
    local family rule old_rule
    for ip in "${WHITELIST_IPS[@]}"; do
        family="$(ip_family "$ip")"
        old_rule="rule family=\"${family}\" source address=\"${ip}\" port port=\"${SSH_PORT}\" protocol=\"tcp\" accept"
        rule="rule family=\"${family}\" source address=\"${ip}\" accept"

        if firewall-cmd --permanent --zone="$ZONE" --query-rich-rule="$old_rule" >/dev/null 2>&1; then
            log "Removing superseded port-${SSH_PORT}-only rule for $ip (upgrading to full access)..."
            firewall-cmd --permanent --zone="$ZONE" --remove-rich-rule="$old_rule"
        fi

        if firewall-cmd --permanent --zone="$ZONE" --query-rich-rule="$rule" >/dev/null 2>&1; then
            log "Full-access rule for $ip already present, skipping."
            continue
        fi
        log "Allowing $ip -> full access (all ports)"
        firewall-cmd --permanent --zone="$ZONE" --add-rich-rule="$rule"
    done

    # fail2ban ban sets and their REJECT rules, permanent (see firewalld_jail_sets)
    firewalld_jail_sets sshd=22 recidive=0:65535

    log "Reloading firewalld..."
    firewall-cmd --reload

    log "Current firewalld zone '$ZONE':"
    firewall-cmd --zone="$ZONE" --list-all

    if ! command -v fail2ban-client >/dev/null 2>&1; then
        log "Installing fail2ban..."
        apt-get update -qq
        apt-get install -y fail2ban
    else
        log "fail2ban already installed."
    fi

    if [[ ! -f /etc/fail2ban/action.d/firewallcmd-ipset.conf ]]; then
        die "fail2ban's firewallcmd-ipset.conf action file is missing. Cannot set banaction=firewallcmd-ipset safely."
    fi
    require_cmd ipset

    backup_file "$FAIL2BAN_OVERRIDE"

    log "Writing fail2ban override: $FAIL2BAN_OVERRIDE (banaction = firewallcmd-ipset)"
    cat > "$FAIL2BAN_OVERRIDE" <<EOF
# Managed by server-setup.sh / 20-firewall-fail2ban.sh — do not edit
# Debian-shipped jail.conf/jail.local. This file is the override layer.
# Firewall backend: firewalld.

[DEFAULT]
banaction = firewallcmd-ipset
banaction_allports = firewallcmd-allports
backend = systemd
# Addresses fail2ban never bans: loopback plus the whitelist (detected SSH client and
# the saved or entered whitelist), the same list the firewall gives full access.
ignoreip = 127.0.0.1/8 ::1 ${SCANNER_IGNORE_IPS[*]} ${WHITELIST_IPS[*]}
bantime = 1h
findtime = 1h
maxretry = 5

[sshd]
enabled = true
port = ${SSH_PORT}
# Longer than the [DEFAULT] 1h (2026-10-30, by request): sshd's own
# scanners are near-constant background internet noise (confirmed live -
# generic usernames, never a real account), and this box only allows
# pubkey auth anyway (PasswordAuthentication no), so a day-long ban here
# has no legitimate-user risk, just less repeat log noise/connection churn.
bantime = 1d
# findtime widened from the [DEFAULT] 1h too (2026-10-30): a full-log
# sweep found several IPs (e.g. 2.57.121.25, 95 hits) connecting on a
# near-exact ~65 minute cadence for days, every attempt landing just
# outside a 1h window so maxretry=5 never accumulated - confirmed
# deliberate pacing, not coincidence, via raw timestamps. 3h comfortably
# catches that cadence without widening so far that unrelated failures
# start getting lumped together.
findtime = 3h

[recidive]
enabled = true
# backend=auto (not the [DEFAULT] backend=systemd above): recidive reads
# fail2ban's OWN ban log, and fail2ban's logtarget is the file
# /var/log/fail2ban.log, not the journal (systemd only captures its
# generic start/stop lines) — under backend=systemd this jail silently
# watches an empty source and never bans a repeat offender. Found live
# 2026-09-30: a bot had been banned/unbanned 36 times over ~45h with
# recidive never once escalating it.
backend = auto
banaction = firewallcmd-ipset
bantime = 1w
# Widened from 1d (2026-10-30): a full-log sweep found repeat offenders
# (e.g. 213.209.159.133, banned by 4 jails at once, 5 separate visits)
# returning every ~1-1.5 days, with gaps (27h, 35h) consistently landing
# just outside the old 1d findtime - recidive's own escalation never
# triggered despite the clear repeat pattern. Same evasion-just-outside-
# the-window lesson as every other jail widened this session.
findtime = 3d
maxretry = 5
logpath = /var/log/fail2ban.log
EOF

elif [[ "$FW_BACKEND" == "ufw" ]]; then

    # --------------------------------------------------------
    # ufw path
    # --------------------------------------------------------

    if ! command -v ufw >/dev/null 2>&1; then
        log "Installing ufw..."
        apt-get update -qq
        apt-get install -y ufw
    else
        log "ufw already installed."
    fi

    log "Setting ufw default policies (deny incoming, allow outgoing)..."
    ufw default deny incoming
    ufw default allow outgoing

    # Known gap in grommunio-setup's own firewall-opening code — see the
    # matching comment in the firewalld branch above. Pre-opening 995/tcp
    # here is safe; grommunio-setup only ever adds its own ports later.
    ufw allow 995/tcp comment "pop3s (grommunio-setup itself never opens this)"

    # WHITELIST_IPS get FULL access (no port restriction) — not just SSH.
    # See the matching comment in the firewalld branch above for why.
    # Policy (2026-10-04): SSH is open to all public addresses. fail2ban's sshd
    # jail handles brute-force attempts. Whitelisted addresses also get full access.
    ufw allow "${SSH_PORT}/tcp" comment "ssh (open to public, see policy)"

    for ip in "${WHITELIST_IPS[@]}"; do
        if ufw status | grep -E "^${SSH_PORT}/tcp" | grep -qF "$ip"; then
            log "Removing superseded port-${SSH_PORT}-only rule for $ip (upgrading to full access)..."
            ufw delete allow from "$ip" to any port "$SSH_PORT" proto tcp || true
        fi

        if ufw status | grep -qF "$ip"; then
            log "Rule for $ip already present, skipping."
            continue
        fi
        log "Allowing $ip -> full access (all ports)"
        ufw allow from "$ip" comment "full-access-whitelist"
    done

    log "Enabling ufw..."
    ufw --force enable
    systemctl enable --now ufw >/dev/null 2>&1 || true

    log "Current ufw status:"
    ufw status verbose

    if ! command -v fail2ban-client >/dev/null 2>&1; then
        log "Installing fail2ban..."
        apt-get update -qq
        apt-get install -y fail2ban
    else
        log "fail2ban already installed."
    fi

    if [[ ! -f /etc/fail2ban/action.d/ufw.conf ]]; then
        die "fail2ban's ufw.conf action file is missing. Cannot set banaction=ufw safely."
    fi

    backup_file "$FAIL2BAN_OVERRIDE"

    log "Writing fail2ban override: $FAIL2BAN_OVERRIDE (banaction = ufw)"
    cat > "$FAIL2BAN_OVERRIDE" <<EOF
# Managed by server-setup.sh / 20-firewall-fail2ban.sh — do not edit
# Debian-shipped jail.conf/jail.local. This file is the override layer.
# Firewall backend: ufw.

[DEFAULT]
banaction = ufw
banaction_allports = ufw
backend = systemd
# Addresses fail2ban never bans: loopback plus the whitelist (detected SSH client and
# the saved or entered whitelist), the same list the firewall gives full access.
ignoreip = 127.0.0.1/8 ::1 ${SCANNER_IGNORE_IPS[*]} ${WHITELIST_IPS[*]}
bantime = 1h
findtime = 1h
maxretry = 5

[sshd]
enabled = true
port = ${SSH_PORT}
# Longer than the [DEFAULT] 1h (2026-10-30, by request) — see the matching
# comment in the firewalld branch above for why this is safe here.
bantime = 1d
# findtime widened too — see the matching comment in the firewalld branch
# above (deliberately-paced scanners found via a full-log sweep).
findtime = 3h

[recidive]
enabled = true
# backend=auto (not the [DEFAULT] backend=systemd above) — see the matching
# comment in the firewalld branch above for why: recidive reads fail2ban's
# own ban log, which is a file, not the journal.
backend = auto
banaction = ufw
bantime = 1w
# Widened from 1d (2026-10-30) — see the matching comment in the firewalld
# branch above for why.
findtime = 3d
maxretry = 5
logpath = /var/log/fail2ban.log
EOF

else
    die "Unknown firewall backend: $FW_BACKEND"
fi

chmod 644 "$FAIL2BAN_OVERRIDE"
finalize_backup "$FAIL2BAN_OVERRIDE"

log "Validating fail2ban configuration..."
fail2ban-client -t

log "Enabling and (re)starting fail2ban..."
systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban

sleep 1
log "fail2ban jail status:"
fail2ban-client status || true
fail2ban-client status sshd || true
fail2ban-client status recidive || true

# ============================================================
# Persist the decision for replay
# ============================================================

save_cfg "$CFG" "FW_BACKEND=$FW_BACKEND"
save_cfg_array_append "$CFG" WHITELIST_IPS "${WHITELIST_IPS[@]}"
log "Saved configuration for replay: $CFG"

echo
echo "============================================================"
echo " Done"
echo "============================================================"
echo
echo "Backend: $FW_BACKEND"
echo "SSH (port $SSH_PORT) is open to all public addresses; fail2ban's sshd jail handles brute-force attempts."
echo "Full access (all ports, not just SSH) is additionally granted to:"
for ip in "${WHITELIST_IPS[@]}"; do echo "  - $ip"; done
echo "fail2ban: sshd + recidive jails enabled via $FAIL2BAN_OVERRIDE"
echo
echo "IMPORTANT: keep this session open and verify a NEW ssh connection"
echo "succeeds from a whitelisted IP before closing this one."
echo
}
