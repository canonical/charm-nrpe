#!/usr/bin/env python3
# -*- coding: us-ascii -*-

# Copyright (C) 2019 Canonical
# All rights reserved

import argparse
import os

from nagios_plugin3 import (
    CriticalError,
    WarnError,
    UnknownError,
    try_check,
)


def check_arp_cache(warn, crit):
    """Checks the usage of arp cache against gc_thresh.

    Alerts when the number of arp entries exceeds a threshold of gc_thresh3.
    See https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt for
    full details.

    :param warn: integer, % level of hard limit at which to raise Warning
    :param crit: integer, % level of hard limit at which to raise Critical
    """

    ARP_TABLE_ENTRIES = '/proc/net/arp'
    GC_THRESH_LOCATION = '/proc/sys/net/ipv4/neigh/default/gc_thresh3'

    if not os.path.exists(ARP_TABLE_ENTRIES):
        raise UnknownError("No arp table found!")
    if not os.path.exists(GC_THRESH_LOCATION):
        raise UnknownError("sysctl entry net.ipv4.neigh.default.gc_thresh3 not found!")

    with open(GC_THRESH_LOCATION) as fd:
        gc_thresh3 = int(fd.read())

    with open(ARP_TABLE_ENTRIES) as fd:
        arp_cache = fd.read().count('\n') - 1  # remove header
    extra_info = "arp cache entries: {}".format(arp_cache)

    warn_threshold = gc_thresh3 * warn / 100
    crit_threshold = gc_thresh3 * crit / 100

    if arp_cache >= crit_threshold:
        message = "CRITICAL: arp cache is more than {} of limit, {}".format(crit, extra_info)
        raise CriticalError(message)
    if arp_cache >= warn_threshold:
        message = "WARNING: arp cache is more than {} of limit, {}".format(warn, extra_info)
        raise WarnError(message)

    print('OK: arp cache is healthy: {}'.format(extra_info))


def parse_args():
    parser = argparse.ArgumentParser(description='Check bond status')
    parser.add_argument('--warn', '-w', type=int,
                        help='% of gc_thresh3 to exceed for warning',
                        default=60)
    parser.add_argument('--crit', '-c', type=int,
                        help='% of gc_thresh3 to exceed for critical',
                        default=80)
    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    try_check(check_arp_cache, args.warn, args.crit)


if __name__ == '__main__':
    main()
