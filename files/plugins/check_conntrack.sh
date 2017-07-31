#!/bin/sh
# This file is managed by juju.  Do not make local changes.

# Copyright (C) 2013, 2016 Canonical Ltd.
# Author: Haw Loeung <haw.loeung@canonical.com>
#         Paul Gear <paul.gear@canonical.com>

# Alert when current conntrack entries exceeds certain percentage of max. to
# detect when we're about to fill it up and start dropping packets.

set -eu

STATE_OK=0
STATE_WARNING=1
STATE_CRITICAL=2
STATE_UNKNOWN=3

if ! lsmod | grep -q conntrack; then
    echo "OK: no conntrack modules present"
    exit $STATE_OK
fi

if ! [ -e /proc/sys/net/netfilter/nf_conntrack_max ]; then
    echo "OK: conntrack not available"
    exit $STATE_OK
fi

max=$(sysctl net.netfilter.nf_conntrack_max 2>/dev/null | awk '{ print $3 }')
if [ -z "$max" ]; then
    echo "UNKNOWN: unable to retrieve value of net.netfilter.nf_conntrack_max"
    exit $STATE_UNKNOWN
fi
current=$(sysctl net.netfilter.nf_conntrack_count 2>/dev/null | awk '{ print $3 }')
if [ -z "$current" ]; then
    echo "UNKNOWN: unable to retrieve value of net.netfilter.nf_conntrack_count"
    exit $STATE_UNKNOWN
fi

# default thresholds
crit=90
warn=80

# parse command line
set +e
OPTIONS=$(getopt w:c: "$@")
if [ $? -ne 0 ]; then
    echo "Usage: $0 [-w warningpercent] [-c criticalpercent]" >&2
    echo "       Check nf_conntrack_count against nf_conntrack_max" >&2
    exit $STATE_UNKNOWN
fi
set -e

set -- $OPTIONS
while true; do
    case "$1" in
	-w) warn=$2; shift 2 ;;
	-c) crit=$2; shift 2 ;;
	--) shift;   break ;;
	*)  break ;;
    esac
done

percent=$((current * 100 / max))
stats="| current=$current max=$max percent=$percent;$warn;$crit"

threshold=$((max * crit / 100))
if [ $current -gt $threshold ]; then
    echo "CRITICAL: conntrack table nearly full. $stats"
    exit $STATE_CRITICAL
fi

threshold=$((max * warn / 100))
if [ $current -gt $threshold ]; then
    echo "WARNING: conntrack table filling. $stats"
    exit $STATE_WARNING
fi

echo "OK: conntrack table normal $stats"
exit $STATE_OK
