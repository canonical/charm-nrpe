#!/usr/bin/env python3
"""Check cpu governor scaling and alert."""
# -*- coding: us-ascii -*-

# Copyright (C) 2021 Canonical
# All rights reserved
# Author: Diko Parvanov <diko.parvanov@canonical.com>
#
# ./check_cpu_governor.py


import argparse
import os
import re
import subprocess

from nagios_plugin3 import (
    CriticalError,
    try_check,
)


def check_governors(governor):
    """Check /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor."""
    cpu_path = os.listdir("/sys/devices/system/cpu")
    regex = re.compile("(cpu[0-9][0-9]*)")
    numcpus = sum(1 for x in cpu_path if regex.match(x))
    error = False
    error_cpus = ""
    for cpu in range(0, numcpus):
        path = f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor"
        cmd = f"cat {path}"
        out = subprocess.check_output(cmd.split())

        if governor in out.decode():
            continue
        else:
            error = True
            error_cpus += f"CPU{cpu} "

    if error:
        error_cpus = ",".join(error_cpus.split())
        raise CriticalError(f"CRITICAL: {error_cpus} not set to {governor}")

    print(f"OK: All CPUs set to {governor}.")


def parse_args():
    """Parse command-line options."""
    parser = argparse.ArgumentParser(description="Check CPU governor")
    parser.add_argument(
        "--governor",
        "-g",
        type=str,
        help="% governor to check each CPU",
        default="performance",
    )
    args = parser.parse_args()
    return args


def main():
    """Check the cpu governors."""
    args = parse_args()
    try_check(check_governors, args.governor)


if __name__ == "__main__":
    main()
