#!/usr/bin/env bash
#
# f2b-subnet-detect.sh
#
# Given one IPv4 address, print the real, officially registered network
# block (CIDR) it belongs to - looked up live via whois, not guessed with
# a fixed mask. Tries, in order, the "route:", "CIDR:", "inetnum:" (range
# or CIDR), "IPv4 Address" (range) and "NetRange" (range) fields, since
# different registries (RIPE, ARIN, APNIC, ...) answer differently - the
# same priority order already proven on another server's
# ufw-cidr-ssh-auth.conf. Falls back to the bare /32 of
# the input IP if none of those parse, so a caller never gets empty
# output for a resolvable IP.
#
# Used by fail2ban's firewallcmd-ipset-cidr.conf action to widen a ban
# from one IP to its provider's whole announced block - see
# 36-fail2ban-mail-jails.sh's postfix-smtp-auth-subnet jail, added to
# catch distributed low-and-slow brute force (many different IPs in the
# same block, each individually staying under any single jail's
# maxretry) that a plain per-IP ban can never catch.
#
# Usage: f2b-subnet-detect.sh <ip>
#        f2b-subnet-detect.sh <file with one IP per line>

require_cmd()
{
    command -v "$1" >/dev/null 2>&1 || { echo "f2b-subnet-detect.sh: $1 not found - apt-get install $2" >&2; exit 1; }
}
require_cmd whois whois
require_cmd ipcalc ipcalc

debug=${F2B_SUBNET_DETECT_DEBUG:-0}
checkCIDR="^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$"
checkIP="^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"

debugEcho()
{
    [[ "$debug" == 1 ]] && echo "$*" 1>&2
    return 0
}

findCIDR()
{
    local cidrData="$1"
    if [[ -z "$cidrData" ]]; then
        echo ""
        return
    fi
    if [[ ! "$cidrData" =~ $checkCIDR ]]; then
        cidrData="$(sed -E 's/^([0-9]{1,3}\.[0-9]{1,3})(\/([0-9]|[1-2][0-9]|3[0-2]))/\1.0.0\2/' <<< "$1")"
        if [[ ! "$cidrData" =~ $checkCIDR ]]; then
            cidrData="$(sed -E 's/^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(\/([0-9]|[1-2][0-9]|3[0-2]))/\1.0\2/' <<< "$1")"
            [[ "$cidrData" =~ $checkCIDR ]] || cidrData=""
        fi
    fi
    echo "$cidrData"
}

findRange()
{
    local rangeData="$*" ip1 ip2 localSubnet=""
    ip1="$(awk '{print $1}' <<< "$rangeData")"
    ip2="$(awk '{print $3}' <<< "$rangeData")"
    if [[ "$ip1" =~ $checkIP && "$ip2" =~ $checkIP ]]; then
        localSubnet="$(ipcalc "$rangeData" | grep -m1 -v deaggregate | awk '{print $1}')"
        [[ "$localSubnet" =~ $checkCIDR ]] || localSubnet=""
    fi
    echo "$localSubnet"
}

getSubnet()
{
    local ip="$1" whoisResult subnet netrange
    whoisResult="$(whois "$ip" 2>/dev/null)"

    subnet="$(grep -m1 '^route:' <<< "$whoisResult" | awk '{print $2}')"

    if [[ -z "$subnet" ]]; then
        subnet="$(grep -m1 'CIDR' <<< "$whoisResult" | awk '{print $2}')"
        subnet="$(findCIDR "$subnet")"
    fi

    if [[ -z "$subnet" ]]; then
        netrange="$(grep -m1 '^inetnum:' <<< "$whoisResult" | awk '{print $2 " - " $4}')"
        if [[ -n "${netrange// - /}" ]]; then
            subnet="$(findRange "$netrange")"
            if [[ -z "$subnet" ]]; then
                subnet="$(findCIDR "$(awk '{print $1}' <<< "$netrange")")"
            fi
        fi
    fi

    if [[ -z "$subnet" ]]; then
        netrange="$(grep -m1 'IPv4 Address' <<< "$whoisResult" | awk '{print $4 " - " $6}')"
        [[ -n "${netrange// - /}" ]] && subnet="$(findRange "$netrange")"
    fi

    if [[ -z "$subnet" ]]; then
        netrange="$(grep -m1 'NetRange' <<< "$whoisResult" | awk '{print $2 " - " $4}')"
        subnet="$(findRange "$netrange")"
        [[ -z "$subnet" ]] && subnet="$(findCIDR "$(awk '{print $1}' <<< "$netrange")")"
    fi

    [[ -n "$subnet" ]] || subnet="${ip}/32"
    echo "$subnet"
}

if [[ -z "${1:-}" ]]; then
    echo "Usage: f2b-subnet-detect.sh <ip>|<file>" >&2
    exit 1
fi

if [[ -f "$1" ]]; then
    while read -r line; do
        [[ -n "$line" ]] || continue
        getSubnet "$line"
    done < "$1"
elif [[ "$1" =~ $checkIP ]]; then
    getSubnet "$1"
else
    echo "INVALID" >&2
    exit 1
fi
