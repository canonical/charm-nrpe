#!/usr/bin/env python3
"""Check CPU governor scaling and alert."""

import argparse
import os
import re

from nagios_plugin3 import CriticalError, try_check


def wanted_governor(governor):
    """Check /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor."""
    cpu_path = os.listdir("/sys/devices/system/cpu")
    regex = re.compile("(cpu[0-9][0-9]*)")
    numcpus = sum(1 for x in cpu_path if regex.match(x))
    error_cpus = set()
    for cpu in range(0, numcpus):
        path = f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor"
        with open(path) as f:
            out = f.readline().strip()

        if governor in out:
            continue
        else:
            error_cpus.add(f"CPU{cpu}")

    if error_cpus:
        error_cpus = ",".join(error_cpus)
        raise CriticalError(f"CRITICAL: {error_cpus} not set to {governor}")

    print(f"OK: All CPUs set to {governor}.")


def parse_args():
    """Parse command-line options."""
    parser = argparse.ArgumentParser(description="Check CPU governor")
    parser.add_argument(
        "--governor",
        "-g",
        type=str,
        help="The requested governor to check for each CPU",
        default="performance",
    )
    args = parser.parse_args()
    return args


def main():
    """Check the CPU governors."""
    args = parse_args()
    try_check(wanted_governor, args.governor)


if __name__ == "__main__":
    main()
