#!/usr/bin/env python3
"""Check readonly filesystems and alert."""
# -*- coding: us-ascii -*-

# Copyright (C) 2020 Canonical
# All rights reserved
#

import argparse

from nagios_plugin3 import CriticalError, UnknownError, try_check

EXCLUDE = {"/snap/", "/sys/fs/cgroup"}
EXCLUDE_FS = {"nsfs", "ramfs", "tmpfs"}


def check_ro_filesystem(excludes=""):
    """Loop /proc/mounts looking for readonly mounts.

    :param excludes: list of mount points to exclude from checks
    """
    # read /proc/mounts, add each line to a list
    try:
        with open("/proc/mounts") as fd:
            mounts = [mount.strip() for mount in fd.readlines()]
    except Exception as e:
        raise UnknownError("UNKNOWN: unable to read mounts with {}".format(e))

    exclude_mounts = EXCLUDE
    ro_filesystems = []
    # if excludes != "" and excludes is not None:
    if excludes:
        try:
            exclude_mounts = EXCLUDE.union(set(excludes.split(",")))
        except Exception as e:
            msg = "UNKNOWN: unable to read list of mounts to exclude {}".format(e)
            raise UnknownError(msg)
    for mount in mounts:
        _, mount_point, fs, mount_options, *others = mount.split()
        # if current fs matches EXCLUDE_FS then next, else check it's not readonly
        if fs in EXCLUDE_FS:
            continue
        if not any(mount_point.startswith(exclusion.strip()) for exclusion in exclude_mounts):
            mount_options = mount_options.split(",")
            if "ro" in mount_options:
                ro_filesystems.append(mount_point)
    if len(ro_filesystems) > 0:
        msg = "CRITICAL: filesystem(s) {} readonly".format(",".join(ro_filesystems))
        raise CriticalError(msg)

    print("OK: no readonly filesystems found")


def parse_args():
    """Parse command-line options."""
    parser = argparse.ArgumentParser(description="Check for readonly filesystems")
    parser.add_argument(
        "--exclude",
        "-e",
        type=str,
        help="""Comma separated list of mount points to exclude from
                checks for readonly filesystem.
                Can be just a substring of the whole mount point.""",
        default="",
    )
    args = parser.parse_args()
    return args


def main():
    """Parse args and check the readonly filesystem."""
    args = parse_args()
    try_check(check_ro_filesystem, args.exclude)


if __name__ == "__main__":
    main()
