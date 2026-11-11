#!/usr/bin/env bash
#
# 10-network-hostname.sh
#
# Debian 13 network discovery and systemd-networkd setup, as a function
# (step_network_hostname) for server-setup.sh. Behaviour is the same as the
# original standalone 1-network-hostname.sh, plus config persistence:
#
#   - On first run, prompts for hostname/domain and (if more than one public
#     address exists) which is primary, same as before.
#   - On success, saves those DECISIONS (not the raw detected network facts,
#     which are always re-detected fresh every run) to
#     /root/cfg-server/10-network-hostname.conf.
#   - On a later run (replay), if that file exists, the hostname/domain
#     prompt is skipped. The saved primary IP is only reused if it still
#     matches a currently-detected address on this machine (protects against
#     blindly replaying a stale address onto a genuinely different server);
#     otherwise it warns and falls back to the normal interactive selection.
#   - The two safety confirmations before an actual network change (install
#     the config, then restart systemd-networkd) are ALWAYS asked, replay or
#     not.
#
# CURRENTLY SUPPORTED:
#   Netplan -> systemd-networkd
#
# DETECTED BUT NOT AUTO-CONVERTED:
#   NetworkManager
#   ifupdown
#
# GENERATED FILES (for review, before anything is installed):
#   /root/10-<interface>.network
#   /root/hostname
#   /root/hosts

step_network_hostname()
{
local NETWORKD_FILE=""
local HOSTNAME_FILE="/root/hostname"
local HOSTS_FILE="/root/hosts"

local NETWORK_BACKEND="unknown"
local INTERFACE=""

local DHCP4="no"
local DHCP6="no"
local IPV6_RA="no"

local IPV4_GATEWAY=""
local IPV6_GATEWAY=""

local CURRENT_HOSTNAME=""
local CURRENT_FQDN=""
local CURRENT_DOMAIN=""

local NEW_HOSTNAME=""
local NEW_DOMAIN=""
local NEW_FQDN=""

local PRIMARY_IPV4=""
local PRIMARY_IPV6=""

local -a IPV4_ADDRESSES=()
local -a IPV6_ADDRESSES=()
local -a DNS_SERVERS=()

local CFG="$(cfg_file 10-network-hostname)"
local USING_SAVED_CFG=0
local SAVED_NEW_HOSTNAME="" SAVED_NEW_DOMAIN="" SAVED_NEW_FQDN=""
local SAVED_PRIMARY_IPV4="" SAVED_PRIMARY_IPV6=""

# ============================================================
# Required commands
# ============================================================

local command
for command in awk grep hostname ip resolvectl sed sort systemctl hostnamectl sysctl; do
    require_cmd "$command"
done

# ============================================================
# IPv4 public-address test
# ============================================================

is_ipv4_public()
{
    local ip="$1"
    local second_octet

    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 1
    fi

    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"

    for octet in "$o1" "$o2" "$o3" "$o4"; do
        if (( octet < 0 || octet > 255 )); then
            return 1
        fi
    done

    [[ "$ip" =~ ^127\. ]] && return 1
    [[ "$ip" =~ ^169\.254\. ]] && return 1
    [[ "$ip" =~ ^10\. ]] && return 1
    [[ "$ip" =~ ^192\.168\. ]] && return 1

    if [[ "$ip" =~ ^172\.([0-9]+)\. ]]; then
        second_octet="${BASH_REMATCH[1]}"
        if (( second_octet >= 16 && second_octet <= 31 )); then
            return 1
        fi
    fi

    # RFC6598 CGNAT: 100.64.0.0/10.
    if [[ "$ip" =~ ^100\.([0-9]+)\. ]]; then
        second_octet="${BASH_REMATCH[1]}"
        if (( second_octet >= 64 && second_octet <= 127 )); then
            return 1
        fi
    fi

    [[ "$ip" == "0.0.0.0" ]] && return 1
    [[ "$ip" =~ ^192\.0\.2\. ]] && return 1
    [[ "$ip" =~ ^198\.51\.100\. ]] && return 1
    [[ "$ip" =~ ^203\.0\.113\. ]] && return 1

    if (( o1 >= 224 && o1 <= 239 )); then
        return 1
    fi

    if (( o1 >= 240 )); then
        return 1
    fi

    return 0
}

# ============================================================
# IPv6 public-address test (global unicast = 2000::/3)
# ============================================================

is_ipv6_public()
{
    local ip="$1"
    [[ "$ip" =~ ^[23][0-9A-Fa-f:]*$ ]]
}

# ============================================================
# Detect network backend
# ============================================================

if compgen -G "/etc/netplan/*.yaml" >/dev/null 2>&1 ||
   compgen -G "/etc/netplan/*.yml" >/dev/null 2>&1; then
    NETWORK_BACKEND="netplan"
elif systemctl is-active --quiet systemd-networkd 2>/dev/null &&
     compgen -G "/etc/systemd/network/*.network" >/dev/null 2>&1; then
    # Already migrated by an earlier run of this step — not a fresh
    # netplan conversion, but a valid, supported state to replay/verify.
    NETWORK_BACKEND="systemd-networkd"
elif systemctl is-active --quiet NetworkManager 2>/dev/null ||
     systemctl is-enabled --quiet NetworkManager 2>/dev/null; then
    NETWORK_BACKEND="networkmanager"
elif [[ -f /etc/network/interfaces ]] ||
     systemctl is-active --quiet networking 2>/dev/null ||
     systemctl is-enabled --quiet networking 2>/dev/null; then
    NETWORK_BACKEND="ifupdown"
else
    NETWORK_BACKEND="unknown"
fi

if [[ "$NETWORK_BACKEND" != "netplan" && "$NETWORK_BACKEND" != "systemd-networkd" ]]; then
    echo
    echo "============================================================"
    echo " Network backend"
    echo "============================================================"
    echo
    echo "Detected backend: $NETWORK_BACKEND"
    echo
    echo "Automatic conversion is currently implemented only for Netplan"
    echo "(or a server already migrated to systemd-networkd by this step)."
    echo "NetworkManager and ifupdown are detected, but this step will"
    echo "not guess their configuration."
    echo
    return 1
fi

if [[ "$NETWORK_BACKEND" == "systemd-networkd" ]]; then
    log "This server is already on systemd-networkd (migrated by an earlier run of this step). Re-verifying/regenerating its configuration."
fi

# ============================================================
# Detect default routes / interface
# ============================================================

local DEFAULT_IPV4_ROUTE DEFAULT_IPV6_ROUTE
DEFAULT_IPV4_ROUTE="$(ip -4 route show default | head -n 1 || true)"
DEFAULT_IPV6_ROUTE="$(ip -6 route show default | head -n 1 || true)"

if [[ -n "$DEFAULT_IPV4_ROUTE" ]]; then
    INTERFACE="$(awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1);exit}}}' <<< "$DEFAULT_IPV4_ROUTE")"
fi
if [[ -z "$INTERFACE" && -n "$DEFAULT_IPV6_ROUTE" ]]; then
    INTERFACE="$(awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1);exit}}}' <<< "$DEFAULT_IPV6_ROUTE")"
fi

[[ -z "$INTERFACE" ]] && die "Could not determine the active network interface."
ip link show dev "$INTERFACE" >/dev/null 2>&1 || die "Interface '$INTERFACE' does not exist."

# ============================================================
# Detect DHCP / RA
# ============================================================

if ip -4 -o addr show dev "$INTERFACE" scope global | grep -q ' dynamic '; then
    DHCP4="yes"
fi
if ip -6 -o addr show dev "$INTERFACE" scope global | grep -q ' dynamic '; then
    DHCP6="yes"
fi

local file
for file in /etc/netplan/*.yaml /etc/netplan/*.yml; do
    [[ -f "$file" ]] || continue
    grep -Eq '^[[:space:]]*dhcp4:[[:space:]]*true([[:space:]]*#.*)?$' "$file" && DHCP4="yes"
    grep -Eq '^[[:space:]]*dhcp6:[[:space:]]*true([[:space:]]*#.*)?$' "$file" && DHCP6="yes"
done

if ip -6 route show dev "$INTERFACE" | grep -q ' proto ra '; then
    IPV6_RA="yes"
fi

# ============================================================
# Detect public addresses
# ============================================================

local address ip_without_prefix
while read -r address; do
    [[ -n "$address" ]] || continue
    ip_without_prefix="${address%/*}"
    is_ipv4_public "$ip_without_prefix" && IPV4_ADDRESSES+=("$address")
done < <(ip -4 -o addr show dev "$INTERFACE" scope global | awk '{print $4}')

[[ "${#IPV4_ADDRESSES[@]}" -gt 0 ]] && mapfile -t IPV4_ADDRESSES < <(printf '%s\n' "${IPV4_ADDRESSES[@]}" | sort -u)

while read -r address; do
    [[ -n "$address" ]] || continue
    ip_without_prefix="${address%/*}"
    is_ipv6_public "$ip_without_prefix" && IPV6_ADDRESSES+=("$address")
done < <(ip -6 -o addr show dev "$INTERFACE" scope global | awk '{print $4}')

[[ "${#IPV6_ADDRESSES[@]}" -gt 0 ]] && mapfile -t IPV6_ADDRESSES < <(printf '%s\n' "${IPV6_ADDRESSES[@]}" | sort -u)

# ============================================================
# Detect gateways
# ============================================================

if [[ -n "$DEFAULT_IPV4_ROUTE" ]]; then
    IPV4_GATEWAY="$(awk '{for(i=1;i<=NF;i++){if($i=="via"){print $(i+1);exit}}}' <<< "$DEFAULT_IPV4_ROUTE")"
fi
if [[ -n "$DEFAULT_IPV6_ROUTE" ]]; then
    IPV6_GATEWAY="$(awk '{for(i=1;i<=NF;i++){if($i=="via"){print $(i+1);exit}}}' <<< "$DEFAULT_IPV6_ROUTE")"
fi

if [[ "${#IPV4_ADDRESSES[@]}" -gt 0 && -z "$IPV4_GATEWAY" ]]; then
    die "Public IPv4 address detected, but no IPv4 default gateway was found."
fi
if [[ "${#IPV6_ADDRESSES[@]}" -gt 0 && -z "$IPV6_GATEWAY" ]]; then
    die "Public IPv6 address detected, but no IPv6 default gateway was found."
fi

# ============================================================
# Detect DNS servers with resolvectl (never the local stub)
# ============================================================

local DNS_LINE dns
DNS_LINE="$(resolvectl dns "$INTERFACE" 2>/dev/null | sed -n 's/^[^:]*:[[:space:]]*//p' | head -n 1)"

if [[ -n "$DNS_LINE" ]]; then
    local -a DNS_ARRAY
    read -r -a DNS_ARRAY <<< "$DNS_LINE"
    for dns in "${DNS_ARRAY[@]}"; do
        [[ -z "$dns" ]] && continue
        [[ "$dns" == "127.0.0.53" ]] && continue
        [[ "$dns" == "::1" ]] && continue
        DNS_SERVERS+=("$dns")
    done
fi

[[ "${#DNS_SERVERS[@]}" -gt 0 ]] && mapfile -t DNS_SERVERS < <(printf '%s\n' "${DNS_SERVERS[@]}" | sort -u)
[[ "${#DNS_SERVERS[@]}" -eq 0 ]] && die "No usable DNS servers detected with resolvectl on $INTERFACE."

# ============================================================
# Detect current hostname / FQDN / domain
# ============================================================

local CURRENT_CONFIGURED_HOSTNAME="" CURRENT_RUNTIME_HOSTNAME="" HOSTS_FQDN=""

if [[ -r /etc/hostname ]]; then
    CURRENT_CONFIGURED_HOSTNAME="$(sed -n '1p' /etc/hostname | tr -d '[:space:]')"
fi
CURRENT_RUNTIME_HOSTNAME="$(hostname 2>/dev/null || true)"
CURRENT_HOSTNAME="${CURRENT_CONFIGURED_HOSTNAME:-$CURRENT_RUNTIME_HOSTNAME}"

CURRENT_FQDN="$(hostname -f 2>/dev/null || true)"

if [[ -n "$CURRENT_FQDN" && "$CURRENT_FQDN" == *.* ]]; then
    CURRENT_HOSTNAME="${CURRENT_FQDN%%.*}"
    CURRENT_DOMAIN="${CURRENT_FQDN#*.}"
fi

if [[ -z "$CURRENT_DOMAIN" && -r /etc/hosts ]]; then
    HOSTS_FQDN="$(awk -v h="$CURRENT_HOSTNAME" '
        $0 !~ /^[[:space:]]*#/ {
            for (i = 2; i <= NF; i++) {
                if ($i == h || $i ~ ("^" h "\\.")) {
                    if ($i ~ /\./) { print $i; exit }
                }
            }
        }' /etc/hosts)"
    if [[ -n "$HOSTS_FQDN" ]]; then
        CURRENT_FQDN="$HOSTS_FQDN"
        CURRENT_DOMAIN="${CURRENT_FQDN#*.}"
    fi
fi

[[ -z "$CURRENT_HOSTNAME" ]] && CURRENT_HOSTNAME="server"

# ============================================================
# PTR (reverse DNS) check
#
# A mail server needs correct reverse DNS: many receiving servers reject
# or penalize mail from an IP with no PTR record, or one that does not
# match the sending FQDN. Checked here, before the hostname/FQDN prompt, so
# a working PTR can be offered as the suggested FQDN instead of whatever the
# OS installer wrote to /etc/hostname (often a random UUID on a freshly
# imaged VPS, as opposed to the FQDN the PTR was actually set up for).
# ============================================================

local PTR_IPV4="" PTR_IPV6="" PTR_SUGGESTED_FQDN=""
local ptr_check_ip ptr_line ptr_rest

if [[ "${#IPV4_ADDRESSES[@]}" -gt 0 ]]; then
    ptr_check_ip="${IPV4_ADDRESSES[0]%/*}"
    ptr_line="$(resolvectl query "$ptr_check_ip" 2>/dev/null | head -n 1)"
    if [[ "$ptr_line" == "${ptr_check_ip}:"* ]]; then
        # Strip the known literal "ip:" prefix with bash expansion, not a
        # colon-splitting regex: an IPv6 address has colons of its own, so
        # a regex like '^[^:]+:' would cut it off after the first segment.
        ptr_rest="${ptr_line#"${ptr_check_ip}":}"
        ptr_rest="$(sed -E 's/^[[:space:]]+//; s/[[:space:]]+--.*$//; s/[[:space:]]+$//; s/\.$//' <<< "$ptr_rest")"
        PTR_IPV4="$ptr_rest"
    fi
fi

if [[ "${#IPV6_ADDRESSES[@]}" -gt 0 ]]; then
    ptr_check_ip="${IPV6_ADDRESSES[0]%/*}"
    ptr_line="$(resolvectl query "$ptr_check_ip" 2>/dev/null | head -n 1)"
    if [[ "$ptr_line" == "${ptr_check_ip}:"* ]]; then
        ptr_rest="${ptr_line#"${ptr_check_ip}":}"
        ptr_rest="$(sed -E 's/^[[:space:]]+//; s/[[:space:]]+--.*$//; s/[[:space:]]+$//; s/\.$//' <<< "$ptr_rest")"
        PTR_IPV6="$ptr_rest"
    fi
fi

PTR_SUGGESTED_FQDN="${PTR_IPV4:-$PTR_IPV6}"

# ============================================================
# Forward-confirmed reverse DNS (FCrDNS) and MX check
#
# A PTR alone is not enough: many receiving servers also check that the
# PTR's forward A/AAAA record points back to this server's own address
# (forward-confirmed reverse DNS), and that the domain actually has an MX
# record (so this server is really set up to send/receive mail for it).
# ============================================================

local FCRDNS_IPV4="N/A" FCRDNS_IPV6="N/A"
local MX_DOMAIN="" MX_TARGET=""
local fwd_out mx_out mx_line

if [[ -n "$PTR_IPV4" ]]; then
    fwd_out="$(resolvectl query "$PTR_IPV4" 2>/dev/null)"
    if grep -qF "${IPV4_ADDRESSES[0]%/*}" <<< "$fwd_out"; then
        FCRDNS_IPV4="yes"
    else
        FCRDNS_IPV4="no"
    fi
fi

if [[ -n "$PTR_IPV6" ]]; then
    fwd_out="$(resolvectl query "$PTR_IPV6" 2>/dev/null)"
    if grep -qF "${IPV6_ADDRESSES[0]%/*}" <<< "$fwd_out"; then
        FCRDNS_IPV6="yes"
    else
        FCRDNS_IPV6="no"
    fi
fi

if [[ -n "$PTR_SUGGESTED_FQDN" && "$PTR_SUGGESTED_FQDN" == *.* ]]; then
    MX_DOMAIN="${PTR_SUGGESTED_FQDN#*.}"
    mx_out="$(resolvectl query --type=MX "$MX_DOMAIN" 2>/dev/null)"
    mx_line="$(head -n 1 <<< "$mx_out")"
    # "<domain> IN MX <priority> <target>" when an MX exists; a priority
    # with no target (e.g. "IN MX 0" alone) means no real MX (RFC 7505 null
    # MX, or simply none configured) - MX_TARGET stays empty either way.
    MX_TARGET="$(sed -nE 's/^[^ ]+ IN MX [0-9]+ ([^ ]+).*/\1/p' <<< "$mx_line")"
fi

# ============================================================
# Display current configuration
# ============================================================

local ipv4_list ipv6_list dns_list
ipv4_list="NONE"; [[ "${#IPV4_ADDRESSES[@]}" -gt 0 ]] && ipv4_list="$(IFS=', '; echo "${IPV4_ADDRESSES[*]}")"
ipv6_list="NONE"; [[ "${#IPV6_ADDRESSES[@]}" -gt 0 ]] && ipv6_list="$(IFS=', '; echo "${IPV6_ADDRESSES[*]}")"
dns_list="$(IFS=', '; echo "${DNS_SERVERS[*]}")"

echo
echo "============================================================"
echo " Current network configuration"
echo "============================================================"
echo
printf '%-20s %s\n' "Network backend:" "$NETWORK_BACKEND"
printf '%-20s %s\n' "Interface:" "$INTERFACE"
printf '%-20s %s\n' "DHCP:" "IPv4 $DHCP4, IPv6 $DHCP6"
printf '%-20s %s\n' "IPv6 RA:" "$IPV6_RA"
echo
printf '%-20s %s\n' "IPv4 address(es):" "$ipv4_list"
printf '%-20s %s\n' "IPv4 gateway:" "${IPV4_GATEWAY:-NONE}"
printf '%-20s %s\n' "IPv4 PTR:" "${PTR_IPV4:-NONE}"
printf '%-20s %s\n' "IPv4 FCrDNS:" "$FCRDNS_IPV4"
echo
printf '%-20s %s\n' "IPv6 address(es):" "$ipv6_list"
printf '%-20s %s\n' "IPv6 gateway:" "${IPV6_GATEWAY:-NONE}"
printf '%-20s %s\n' "IPv6 PTR:" "${PTR_IPV6:-NONE}"
printf '%-20s %s\n' "IPv6 FCrDNS:" "$FCRDNS_IPV6"
echo
printf '%-20s %s\n' "DNS:" "$dns_list"
printf '%-20s %s\n' "MX (${MX_DOMAIN:-domain unknown}):" "${MX_TARGET:-NONE}"
echo
printf '%-20s %s\n' "Hostname:" "${CURRENT_HOSTNAME:-NONE}"
printf '%-20s %s\n' "FQDN:" "${CURRENT_FQDN:-NONE}"
printf '%-20s %s\n' "Domain:" "${CURRENT_DOMAIN:-NONE}"
echo

# One combined warning, only when a public address genuinely has no PTR -
# not a per-field repeat, so the common (PTR all fine) case stays short.
local -a PTR_MISSING=()
[[ "${#IPV4_ADDRESSES[@]}" -gt 0 && -z "$PTR_IPV4" ]] && PTR_MISSING+=("IPv4 (${IPV4_ADDRESSES[0]%/*})")
[[ "${#IPV6_ADDRESSES[@]}" -gt 0 && -z "$PTR_IPV6" ]] && PTR_MISSING+=("IPv6 (${IPV6_ADDRESSES[0]%/*})")
if [[ "${#PTR_MISSING[@]}" -gt 0 ]]; then
    echo "WARNING: no PTR (reverse DNS) record for: ${PTR_MISSING[*]}"
    echo "Many receiving mail servers reject or penalize mail from an address"
    echo "with no reverse DNS. Set up a PTR record (usually via your hosting"
    echo "provider's control panel) before relying on this server to send mail."
    echo
fi

# Both PTRs present but pointing to different names: likely a DNS mistake
# (e.g. only one record was updated after a migration), and some receiving
# servers are stricter about IPv6 PTR/FCrDNS consistency than IPv4.
if [[ -n "$PTR_IPV4" && -n "$PTR_IPV6" && "$PTR_IPV4" != "$PTR_IPV6" ]]; then
    echo "WARNING: IPv4 PTR ($PTR_IPV4) and IPv6 PTR ($PTR_IPV6) do not match."
    echo "Check whether both are supposed to point to this server's FQDN."
    echo
fi

# Forward-confirmed reverse DNS: the PTR's own forward A/AAAA record must
# point back to this address, or the PTR alone is not worth much.
local -a FCRDNS_FAILED=()
[[ "$FCRDNS_IPV4" == "no" ]] && FCRDNS_FAILED+=("IPv4 ($PTR_IPV4 does not resolve back to ${IPV4_ADDRESSES[0]%/*})")
[[ "$FCRDNS_IPV6" == "no" ]] && FCRDNS_FAILED+=("IPv6 ($PTR_IPV6 does not resolve back to ${IPV6_ADDRESSES[0]%/*})")
if [[ "${#FCRDNS_FAILED[@]}" -gt 0 ]]; then
    echo "WARNING: forward-confirmed reverse DNS (FCrDNS) failed for: ${FCRDNS_FAILED[*]}"
    echo "The PTR name's own A/AAAA record does not point back to this server."
    echo "Some receiving mail servers treat this the same as having no PTR at all."
    echo
fi

if [[ -n "$MX_DOMAIN" && -z "$MX_TARGET" ]]; then
    echo "WARNING: no MX record found for $MX_DOMAIN."
    echo "Without an MX record, other mail servers do not know this domain"
    echo "receives mail here. Set one up if this server is meant to receive"
    echo "mail for $MX_DOMAIN."
    echo
fi

# ============================================================
# Load saved config, if any
# ============================================================

if [[ -f "$CFG" ]]; then
    # shellcheck disable=SC1090
    source "$CFG"
    SAVED_NEW_HOSTNAME="${NEW_HOSTNAME:-}"
    SAVED_NEW_DOMAIN="${NEW_DOMAIN:-}"
    SAVED_NEW_FQDN="${NEW_FQDN:-}"
    SAVED_PRIMARY_IPV4="${PRIMARY_IPV4:-}"
    SAVED_PRIMARY_IPV6="${PRIMARY_IPV6:-}"
    # Clear so we don't confuse "loaded" with "computed below" while deciding.
    NEW_HOSTNAME=""; NEW_DOMAIN=""; NEW_FQDN=""; PRIMARY_IPV4=""; PRIMARY_IPV6=""
    if [[ -n "$SAVED_NEW_HOSTNAME" ]]; then
        USING_SAVED_CFG=1
        log "Found saved configuration: $CFG"
    fi
fi

# ============================================================
# Hostname and domain: prompt, unless a saved config supplies them
# ============================================================

if [[ "$USING_SAVED_CFG" -eq 1 ]]; then
    NEW_HOSTNAME="$SAVED_NEW_HOSTNAME"
    NEW_DOMAIN="$SAVED_NEW_DOMAIN"
    NEW_FQDN="${SAVED_NEW_FQDN:-$NEW_HOSTNAME${NEW_DOMAIN:+.$NEW_DOMAIN}}"
    log "Using saved hostname/domain (delete $CFG to be asked again):"
    log "  Hostname : $NEW_HOSTNAME"
    log "  Domain   : ${NEW_DOMAIN:-<none>}"
    log "  FQDN     : $NEW_FQDN"
else
    echo "============================================================"
    echo " Hostname and domain"
    echo "============================================================"
    echo
    local PROMPT_DEFAULT_HOSTNAME="${PTR_SUGGESTED_FQDN:-$CURRENT_HOSTNAME}"
    if [[ -n "$PTR_SUGGESTED_FQDN" ]]; then
        log "Suggesting the FQDN found via PTR (reverse DNS): $PTR_SUGGESTED_FQDN"
    fi
    read -r -p "Hostname or FQDN [${PROMPT_DEFAULT_HOSTNAME}]: " NEW_HOSTNAME
    NEW_HOSTNAME="${NEW_HOSTNAME:-$PROMPT_DEFAULT_HOSTNAME}"

    if [[ "$NEW_HOSTNAME" == *.* ]]; then
        NEW_FQDN="$NEW_HOSTNAME"
        NEW_HOSTNAME="${NEW_FQDN%%.*}"
        [[ -z "$CURRENT_DOMAIN" ]] && CURRENT_DOMAIN="${NEW_FQDN#*.}"
    fi

    read -r -p "Domain name [${CURRENT_DOMAIN:-}]: " NEW_DOMAIN
    NEW_DOMAIN="${NEW_DOMAIN:-$CURRENT_DOMAIN}"

    if [[ ! "$NEW_HOSTNAME" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]]; then
        die "Invalid hostname: $NEW_HOSTNAME"
    fi
    if [[ -n "$NEW_DOMAIN" ]]; then
        if [[ ! "$NEW_DOMAIN" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]; then
            die "Invalid domain name: $NEW_DOMAIN"
        fi
    fi

    if [[ -n "$NEW_DOMAIN" ]]; then
        NEW_FQDN="${NEW_HOSTNAME}.${NEW_DOMAIN}"
    else
        NEW_FQDN="$NEW_HOSTNAME"
    fi

    echo
    echo "Hostname configuration:"
    echo
    echo "  Hostname : $NEW_HOSTNAME"
    echo "  Domain   : ${NEW_DOMAIN:-<none>}"
    echo "  FQDN     : $NEW_FQDN"
    echo

    local CONFIRM_HOST
    read -r -p "Is this correct? [y/N]: " CONFIRM_HOST
    if [[ ! "$CONFIRM_HOST" =~ ^[Yy]$ ]]; then
        echo; echo "Hostname/domain configuration rejected."; return 0
    fi
fi

# ============================================================
# Select primary IPv4/IPv6
#
# A saved choice is only reused if it still matches a currently-detected
# address on THIS machine (protects against replaying a stale address onto
# a genuinely different server); otherwise fall back to the normal
# interactive selection.
# ============================================================

local addr_only i CHOICE

if [[ -n "$SAVED_PRIMARY_IPV4" ]]; then
    for addr_only in "${IPV4_ADDRESSES[@]%/*}"; do
        [[ "$addr_only" == "$SAVED_PRIMARY_IPV4" ]] && PRIMARY_IPV4="$SAVED_PRIMARY_IPV4"
    done
    if [[ -z "$PRIMARY_IPV4" ]]; then
        log "WARNING: saved primary IPv4 ($SAVED_PRIMARY_IPV4) is not among this machine's current addresses; asking again."
    fi
fi

if [[ -z "$PRIMARY_IPV4" ]]; then
    if [[ "${#IPV4_ADDRESSES[@]}" -eq 1 ]]; then
        PRIMARY_IPV4="${IPV4_ADDRESSES[0]}"
    elif [[ "${#IPV4_ADDRESSES[@]}" -gt 1 ]]; then
        echo; echo "Multiple public IPv4 addresses detected:"; echo
        for i in "${!IPV4_ADDRESSES[@]}"; do echo "  $((i + 1))) ${IPV4_ADDRESSES[$i]}"; done
        echo
        while true; do
            read -r -p "Select primary IPv4 [1]: " CHOICE
            CHOICE="${CHOICE:-1}"
            if [[ "$CHOICE" =~ ^[0-9]+$ ]] && (( CHOICE >= 1 && CHOICE <= ${#IPV4_ADDRESSES[@]} )); then
                PRIMARY_IPV4="${IPV4_ADDRESSES[$((CHOICE - 1))]}"
                break
            fi
            echo "Invalid selection."
        done
    fi
fi

if [[ -n "$SAVED_PRIMARY_IPV6" ]]; then
    for addr_only in "${IPV6_ADDRESSES[@]%/*}"; do
        [[ "$addr_only" == "$SAVED_PRIMARY_IPV6" ]] && PRIMARY_IPV6="$SAVED_PRIMARY_IPV6"
    done
    if [[ -z "$PRIMARY_IPV6" ]]; then
        log "WARNING: saved primary IPv6 ($SAVED_PRIMARY_IPV6) is not among this machine's current addresses; asking again."
    fi
fi

if [[ -z "$PRIMARY_IPV6" ]]; then
    if [[ "${#IPV6_ADDRESSES[@]}" -eq 1 ]]; then
        PRIMARY_IPV6="${IPV6_ADDRESSES[0]}"
    elif [[ "${#IPV6_ADDRESSES[@]}" -gt 1 ]]; then
        echo; echo "Multiple public IPv6 addresses detected:"; echo
        for i in "${!IPV6_ADDRESSES[@]}"; do echo "  $((i + 1))) ${IPV6_ADDRESSES[$i]}"; done
        echo
        while true; do
            read -r -p "Select primary IPv6 [1]: " CHOICE
            CHOICE="${CHOICE:-1}"
            if [[ "$CHOICE" =~ ^[0-9]+$ ]] && (( CHOICE >= 1 && CHOICE <= ${#IPV6_ADDRESSES[@]} )); then
                PRIMARY_IPV6="${IPV6_ADDRESSES[$((CHOICE - 1))]}"
                break
            fi
            echo "Invalid selection."
        done
    fi
fi

PRIMARY_IPV4="${PRIMARY_IPV4%/*}"
PRIMARY_IPV6="${PRIMARY_IPV6%/*}"

# ============================================================
# Generate systemd-networkd configuration
#
# We intentionally do NOT reproduce arbitrary DHCP-generated routes; the
# gateway alone is enough once configured statically. For /32 (IPv4) and
# /128 (IPv6) addresses GatewayOnLink=yes is required, because the gateway
# is outside those host prefixes (typical of Hetzner/Strato-style VPS
# routing, e.g. 203.0.113.5/32 via 203.0.113.1).
# ============================================================

NETWORKD_FILE="/root/10-${INTERFACE}.network"

# Backs up a PRE-EXISTING review file from an earlier run of this step
# (replay), not /etc - the /etc backup happens separately below, right
# before each install.
backup_file "$NETWORKD_FILE"
{
    echo "# ============================================================"
    echo "# Generated by server-setup.sh / 10-network-hostname.sh"
    echo "# Review before installing into /etc/systemd/network/"
    echo "# ============================================================"
    echo
    echo "[Match]"
    echo "Name=$INTERFACE"
    echo
    echo "[Network]"
    for address in "${IPV4_ADDRESSES[@]}"; do echo "Address=$address"; done
    for address in "${IPV6_ADDRESSES[@]}"; do echo "Address=$address"; done
    echo "IPv6AcceptRA=no"
    for dns in "${DNS_SERVERS[@]}"; do echo "DNS=$dns"; done
    [[ -n "$NEW_DOMAIN" ]] && echo "Domains=$NEW_DOMAIN"
    if [[ -n "$IPV4_GATEWAY" ]]; then
        echo; echo "[Route]"
        echo "Destination=0.0.0.0/0"
        echo "Gateway=$IPV4_GATEWAY"
        echo "GatewayOnLink=yes"
    fi
    if [[ -n "$IPV6_GATEWAY" ]]; then
        echo; echo "[Route]"
        echo "Destination=::/0"
        echo "Gateway=$IPV6_GATEWAY"
        echo "GatewayOnLink=yes"
    fi
} > "$NETWORKD_FILE"

backup_file "$HOSTNAME_FILE"
printf '%s\n' "$NEW_HOSTNAME" > "$HOSTNAME_FILE"

backup_file "$HOSTS_FILE"
{
    echo "127.0.0.1       localhost"
    echo "::1             localhost ip6-localhost ip6-loopback"
    echo "ff02::1         ip6-allnodes"
    echo "ff02::2         ip6-allrouters"
    echo
    # Deliberately no "127.0.1.1 <hostname>": the hostname is tied to its
    # real public address(es), so hostname -f / Postfix's myhostname resolve
    # correctly without gromox's oxdisco_exonym workaround.
    [[ -n "$PRIMARY_IPV4" ]] && printf '%-15s  %s %s\n' "$PRIMARY_IPV4" "$NEW_FQDN" "$NEW_HOSTNAME"
    [[ -n "$PRIMARY_IPV6" ]] && printf '%-15s  %s %s\n' "$PRIMARY_IPV6" "$NEW_FQDN" "$NEW_HOSTNAME"
} > "$HOSTS_FILE"

chmod 600 "$NETWORKD_FILE" "$HOSTNAME_FILE" "$HOSTS_FILE"
finalize_backup "$NETWORKD_FILE"
finalize_backup "$HOSTNAME_FILE"
finalize_backup "$HOSTS_FILE"

[[ -s "$NETWORKD_FILE" ]] || die "Generated networkd file is empty."
[[ -s "$HOSTNAME_FILE" ]] || die "Generated hostname file is empty."
[[ -s "$HOSTS_FILE" ]] || die "Generated hosts file is empty."
grep -q '^\[Match\]$' "$NETWORKD_FILE" || die "Generated networkd file has no [Match] section."
grep -q '^Name=' "$NETWORKD_FILE" || die "Generated networkd file has no interface match."
grep -q '^IPv6AcceptRA=no$' "$NETWORKD_FILE" || die "Generated networkd file does not disable IPv6 RA."

echo
echo "============================================================"
echo " Generated configuration"
echo "============================================================"
echo
echo "----- $NETWORKD_FILE -----"; cat "$NETWORKD_FILE"
echo; echo "----- $HOSTNAME_FILE -----"; cat "$HOSTNAME_FILE"
echo; echo "----- $HOSTS_FILE -----"; cat "$HOSTS_FILE"
echo

# ============================================================
# APPLY — always confirmed explicitly, saved config or not.
# ============================================================

echo
echo "============================================================"
echo " Install systemd-networkd configuration"
echo "============================================================"
echo
echo "The following files have been generated:"
echo; echo "  $NETWORKD_FILE"; echo "  $HOSTNAME_FILE"; echo "  $HOSTS_FILE"; echo
echo "They contain:"
echo
echo "  Interface : $INTERFACE"
echo "  IPv4      : ${PRIMARY_IPV4:-none}"
echo "  IPv4 GW   : ${IPV4_GATEWAY:-none}"
echo "  IPv6      : ${PRIMARY_IPV6:-none}"
echo "  IPv6 GW   : ${IPV6_GATEWAY:-none}"
echo "  Hostname  : $NEW_HOSTNAME"
echo "  FQDN      : $NEW_FQDN"
echo
echo "WARNING:"
echo
echo "This will change the active network configuration."
echo "If you are connected through SSH, this may disconnect you."
echo
echo "Make sure you have console / KVM / out-of-band access before continuing."
echo

local APPLY_CONFIG
read -r -p "Install and activate systemd-networkd now? [y/N]: " APPLY_CONFIG
if [[ ! "$APPLY_CONFIG" =~ ^[Yy]$ ]]; then
    echo; echo "Nothing was changed."; echo
    echo "Review the generated files manually:"
    echo; echo "  $NETWORKD_FILE"; echo "  $HOSTNAME_FILE"; echo "  $HOSTS_FILE"; echo
    return 0
fi

local NETMIGR_BACKUP_ROOT="/root/network-migration-backup"
local NETMIGR_BACKUP_DIR="${NETMIGR_BACKUP_ROOT}/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$NETMIGR_BACKUP_DIR"

echo; echo "Creating backup:"; echo "  $NETMIGR_BACKUP_DIR"; echo

[[ -e /etc/hostname ]] && cp -a /etc/hostname "$NETMIGR_BACKUP_DIR/hostname"
[[ -e /etc/hosts ]] && cp -a /etc/hosts "$NETMIGR_BACKUP_DIR/hosts"
[[ -e /etc/resolv.conf || -L /etc/resolv.conf ]] && cp -a /etc/resolv.conf "$NETMIGR_BACKUP_DIR/resolv.conf"

if [[ -d /etc/netplan ]]; then
    mkdir -p "$NETMIGR_BACKUP_DIR/netplan"
    cp -a /etc/netplan/. "$NETMIGR_BACKUP_DIR/netplan/" 2>/dev/null || true
fi
if [[ -d /etc/systemd/network ]]; then
    mkdir -p "$NETMIGR_BACKUP_DIR/systemd-network"
    cp -a /etc/systemd/network/. "$NETMIGR_BACKUP_DIR/systemd-network/" 2>/dev/null || true
fi

cat > "$NETMIGR_BACKUP_DIR/README" <<EOF
Network migration backup
========================

Date:
$(date)

Interface:
$INTERFACE

Old backend:
$NETWORK_BACKEND

New backend:
systemd-networkd

Hostname:
$NEW_HOSTNAME

FQDN:
$NEW_FQDN

IPv4:
${PRIMARY_IPV4:-none}

IPv4 gateway:
${IPV4_GATEWAY:-none}

IPv6:
${PRIMARY_IPV6:-none}

IPv6 gateway:
${IPV6_GATEWAY:-none}

Backup directory:
$NETMIGR_BACKUP_DIR

Original Netplan configuration:
$NETMIGR_BACKUP_DIR/netplan/

Original hostname:
/etc/hostname

Original hosts:
/etc/hosts

Original resolv.conf:
/etc/resolv.conf

Original systemd-networkd configuration:
$NETMIGR_BACKUP_DIR/systemd-network/
EOF

echo "Backup complete."; echo

mkdir -p /etc/systemd/network
backup_file "/etc/systemd/network/10-${INTERFACE}.network"
install -o root -g root -m 0644 "$NETWORKD_FILE" "/etc/systemd/network/10-${INTERFACE}.network"
finalize_backup "/etc/systemd/network/10-${INTERFACE}.network"
echo "Installed:"; echo "  /etc/systemd/network/10-${INTERFACE}.network"; echo

backup_file /etc/hostname
install -o root -g root -m 0644 "$HOSTNAME_FILE" /etc/hostname
finalize_backup /etc/hostname
echo "Installed:"; echo "  /etc/hostname"; echo

backup_file /etc/hosts
install -o root -g root -m 0644 "$HOSTS_FILE" /etc/hosts
finalize_backup /etc/hosts
echo "Installed:"; echo "  /etc/hosts"; echo

hostnamectl set-hostname "$NEW_FQDN"
echo "Runtime hostname set to:"; hostname; echo

local SYSCTL_FILE="/etc/sysctl.d/99-network-no-ipv6-ra.conf"
backup_file "$SYSCTL_FILE"
cat > "$SYSCTL_FILE" <<EOF
# Disable IPv6 Router Advertisements on this server.
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF
finalize_backup "$SYSCTL_FILE"
sysctl -p "$SYSCTL_FILE" >/dev/null
echo "IPv6 Router Advertisements disabled."; echo

echo "Configuring systemd-resolved..."
systemctl enable systemd-resolved >/dev/null 2>&1 || true
systemctl is-active --quiet systemd-resolved || systemctl start systemd-resolved

if [[ -e /etc/resolv.conf || -L /etc/resolv.conf ]]; then
    if [[ "$(readlink -f /etc/resolv.conf 2>/dev/null || true)" != "/run/systemd/resolve/stub-resolv.conf" ]]; then
        rm -f /etc/resolv.conf
        ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    fi
else
    ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
fi
echo "/etc/resolv.conf configured for systemd-resolved."; echo

if [[ -d /etc/netplan ]]; then
    local NETPLAN_DISABLED="$NETMIGR_BACKUP_DIR/netplan-disabled"
    mkdir -p "$NETPLAN_DISABLED"
    shopt -s nullglob
    local -a NETPLAN_FILES=(/etc/netplan/*.yaml /etc/netplan/*.yml)
    if [[ "${#NETPLAN_FILES[@]}" -gt 0 ]]; then
        for file in "${NETPLAN_FILES[@]}"; do
            mv "$file" "$NETPLAN_DISABLED/"
            echo "Disabled Netplan configuration:"; echo "  $file"
        done
    fi
    shopt -u nullglob
fi
echo

echo "Enabling systemd-networkd..."
systemctl enable systemd-networkd
systemctl daemon-reload

echo
echo "============================================================"
echo " Network activation"
echo "============================================================"
echo
echo "The network service will now be restarted."
echo "Your SSH connection may disconnect."
echo

local RESTART_NETWORK
read -r -p "Restart systemd-networkd now? [y/N]: " RESTART_NETWORK
if [[ ! "$RESTART_NETWORK" =~ ^[Yy]$ ]]; then
    echo; echo "Configuration is installed but networkd was NOT restarted."
    echo; echo "You can activate it later with:"
    echo; echo "  systemctl restart systemd-networkd"; echo
    return 0
fi

systemctl restart systemd-networkd
echo; echo "Waiting for network..."; sleep 3
systemctl restart systemd-resolved
sleep 2

echo
echo "============================================================"
echo " Verification"
echo "============================================================"
echo

local VERIFY_FAILED=0

if ip link show dev "$INTERFACE" >/dev/null 2>&1; then
    echo "[ OK ] Interface $INTERFACE exists."
else
    echo "[FAIL] Interface $INTERFACE does not exist."; VERIFY_FAILED=1
fi

if [[ -n "$PRIMARY_IPV4" ]]; then
    if ip -4 addr show dev "$INTERFACE" | grep -q "$PRIMARY_IPV4"; then
        echo "[ OK ] IPv4 address $PRIMARY_IPV4"
    else
        echo "[FAIL] IPv4 address $PRIMARY_IPV4 not present."; VERIFY_FAILED=1
    fi
fi

if [[ -n "$IPV4_GATEWAY" ]]; then
    if ip -4 route show default | grep -q "via $IPV4_GATEWAY"; then
        echo "[ OK ] IPv4 gateway $IPV4_GATEWAY"
    else
        echo "[FAIL] IPv4 gateway $IPV4_GATEWAY not active."; VERIFY_FAILED=1
    fi
fi

if [[ -n "$PRIMARY_IPV6" ]]; then
    if ip -6 addr show dev "$INTERFACE" | grep -q "$PRIMARY_IPV6"; then
        echo "[ OK ] IPv6 address $PRIMARY_IPV6"
    else
        echo "[FAIL] IPv6 address $PRIMARY_IPV6 not present."; VERIFY_FAILED=1
    fi
fi

if [[ -n "$IPV6_GATEWAY" ]]; then
    if ip -6 route show default | grep -q "via $IPV6_GATEWAY"; then
        echo "[ OK ] IPv6 gateway $IPV6_GATEWAY"
    else
        echo "[FAIL] IPv6 gateway $IPV6_GATEWAY not active."; VERIFY_FAILED=1
    fi
fi

if ip -6 route show dev "$INTERFACE" | grep -q ' proto ra '; then
    echo "[FAIL] IPv6 Router Advertisement route still exists."; VERIFY_FAILED=1
else
    echo "[ OK ] No IPv6 RA route detected."
fi

echo; echo "DNS configuration:"
resolvectl dns "$INTERFACE" || true
for dns in "${DNS_SERVERS[@]}"; do
    if resolvectl dns "$INTERFACE" 2>/dev/null | grep -Fq "$dns"; then
        echo "[ OK ] DNS $dns"
    else
        echo "[WARN] DNS $dns not currently reported by resolvectl."
    fi
done

echo; echo "Hostname:"; hostname
echo; echo "FQDN:"; hostname -f || true

if [[ "$(hostname)" == "$NEW_FQDN" || "$(hostname)" == "$NEW_HOSTNAME" ]]; then
    echo "[ OK ] Hostname configured."
else
    echo "[WARN] Runtime hostname differs from requested hostname."
fi

echo; echo "Services:"
if systemctl is-active --quiet systemd-networkd; then
    echo "[ OK ] systemd-networkd is active."
else
    echo "[FAIL] systemd-networkd is NOT active."; VERIFY_FAILED=1
fi
if systemctl is-active --quiet systemd-resolved; then
    echo "[ OK ] systemd-resolved is active."
else
    echo "[FAIL] systemd-resolved is NOT active."; VERIFY_FAILED=1
fi

echo
echo "============================================================"
if (( VERIFY_FAILED == 0 )); then
    echo " Network migration completed successfully"
    echo "============================================================"
    echo
    echo "systemd-networkd is now managing:"
    echo; echo "  $INTERFACE"; echo
    echo "IPv4:"; echo "  ${PRIMARY_IPV4:-none}"; echo "  Gateway: ${IPV4_GATEWAY:-none}"; echo
    echo "IPv6:"; echo "  ${PRIMARY_IPV6:-none}"; echo "  Gateway: ${IPV6_GATEWAY:-none}"; echo
    echo "FQDN:"; echo "  $NEW_FQDN"; echo
    echo "DNS:"; printf '  %s\n' "${DNS_SERVERS[@]}"; echo
    echo "Backup:"; echo "  $NETMIGR_BACKUP_DIR"; echo

    # Only persist the config on a verified-good run.
    save_cfg "$CFG" \
        "NEW_HOSTNAME=$NEW_HOSTNAME" \
        "NEW_DOMAIN=$NEW_DOMAIN" \
        "NEW_FQDN=$NEW_FQDN" \
        "PRIMARY_IPV4=$PRIMARY_IPV4" \
        "PRIMARY_IPV6=$PRIMARY_IPV6"
    log "Saved configuration for replay: $CFG"
else
    echo " Network migration completed with WARNINGS/ERRORS"
    echo "============================================================"
    echo
    echo "Do NOT delete the backup."
    echo; echo "Backup:"; echo "  $NETMIGR_BACKUP_DIR"; echo
    echo "Configuration was NOT saved to $CFG because of the warnings/errors above."
    return 1
fi
}
