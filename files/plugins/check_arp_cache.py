#!/usr/bin/env python3
"""Check arp cache usage and alert."""
# -*- coding: us-ascii -*-

# Copyright (C) 2019 Canonical
# All rights reserved

import argparse
import os

from nagios_plugin3 import (
    CriticalError,
    UnknownError,
    WarnError,
    try_check,
)


def check_arp_cache(warn, crit):
    """Check the usage of arp cache against gc_thresh.

    Alerts when the number of arp entries exceeds a threshold of gc_thresh3.
    See https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt for
    full details.

    :param warn: integer, % level of hard limit at which to raise Warning
    :param crit: integer, % level of hard limit at which to raise Critical
    """
    arp_table_entries = "/proc/net/arp"
    gc_thresh_location = "/proc/sys/net/ipv4/neigh/default/gc_thresh3"

    if not os.path.exists(arp_table_entries):
        raise UnknownError("No arp table found!")
    if not os.path.exists(gc_thresh_location):
        raise UnknownError("sysctl entry net.ipv4.neigh.default.gc_thresh3 not found!")

    with open(gc_thresh_location) as fd:
        gc_thresh3 = int(fd.read())

    with open(arp_table_entries) as fd:
        arp_cache = fd.read().count("\n") - 1  # remove header
    extra_info = "arp cache entries: {}".format(arp_cache)

    warn_threshold = gc_thresh3 * warn / 100
    crit_threshold = gc_thresh3 * crit / 100

    if arp_cache >= crit_threshold:
        message = "CRITICAL: arp cache is more than {} of limit, {}".format(
            crit, extra_info
        )
        raise CriticalError(message)
    if arp_cache >= warn_threshold:
        message = "WARNING: arp cache is more than {} of limit, {}".format(
            warn, extra_info
        )
        raise WarnError(message)

    print("OK: arp cache is healthy: {}".format(extra_info))


def parse_args():
    """Parse command-line options."""
    parser = argparse.ArgumentParser(description="Check bond status")
    parser.add_argument(
        "--warn",
        "-w",
        type=int,
        help="% of gc_thresh3 to exceed for warning",
        default=60,
    )
    parser.add_argument(
        "--crit",
        "-c",
        type=int,
        help="% of gc_thresh3 to exceed for critical",
        default=80,
    )
    args = parser.parse_args()
    return args


def main():
    """Parse args and check the arp cache."""
    args = parse_args()
    try_check(check_arp_cache, args.warn, args.crit)


if __name__ == "__main__":
    main()
