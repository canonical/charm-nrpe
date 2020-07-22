#!/usr/bin/python
"""Read file and return nagios status based on its content."""
# --------------------------------------------------------
# This file is managed by Juju
# --------------------------------------------------------

#
# Copyright 2014 Canonical Ltd.
#
# Author: Jacek Nykis <jacek.nykis@canonical.com>
#

import re
import nagios_plugin


def parse_args():
    """Parse command-line options."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Read file and return nagios status based on its content",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-f", "--status-file", required=True, help="Status file path")
    parser.add_argument(
        "-c",
        "--critical-text",
        default="CRITICAL",
        help="String indicating critical status",
    )
    parser.add_argument(
        "-w",
        "--warning-text",
        default="WARNING",
        help="String indicating warning status",
    )
    parser.add_argument(
        "-o", "--ok-text", default="OK", help="String indicating OK status"
    )
    parser.add_argument(
        "-u",
        "--unknown-text",
        default="UNKNOWN",
        help="String indicating unknown status",
    )
    return parser.parse_args()


def check_status(args):
    """Return nagios status."""
    nagios_plugin.check_file_freshness(args.status_file, 43200)

    with open(args.status_file, "r") as f:
        content = [line.strip() for line in f.readlines()]

    for line in content:
        if re.search(args.critical_text, line):
            raise nagios_plugin.CriticalError(line)
        elif re.search(args.warning_text, line):
            raise nagios_plugin.WarnError(line)
        elif re.search(args.unknown_text, line):
            raise nagios_plugin.UnknownError(line)
        else:
            print line  # noqa: E999


if __name__ == "__main__":
    args = parse_args()
    nagios_plugin.try_check(check_status, args)
