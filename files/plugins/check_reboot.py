#!/usr/bin/env python3
"""Check reboot via uptime.

This script will:

- get current reboot time via `uptime --since`
- compare with given known reboot time
- if newer reboot detected, raise nagios alert

To acknowledge/resolve the alert:

    juju run-action --wait nrpe/0 ack-reboot

"""

import argparse
import subprocess
import sys
from datetime import datetime

# `uptime --since` output, e.g.: 2022-02-12 08:07:02
UPTIME_FORMAT = "%Y-%m-%d %H:%M:%S"
UPTIME_FORMAT_HUMAN = "yyyy-mm-dd HH:MM:SS"

NAGIOS_STATUS_OK = 0
NAGIOS_STATUS_WARNING = 1
NAGIOS_STATUS_CRITICAL = 2
NAGIOS_STATUS_UNKNOWN = 3

NAGIOS_STATUS = {
    NAGIOS_STATUS_OK: "OK",
    NAGIOS_STATUS_WARNING: "WARNING",
    NAGIOS_STATUS_CRITICAL: "CRITICAL",
    NAGIOS_STATUS_UNKNOWN: "UNKNOWN",
}


def nagios_exit(status, message):
    """Exit with message in the nagios way.

    What this short function does:

    - exit with valid nagios status code
    - print message to stdout as required by nagios
    - prefix status name to message to help human readability

    """
    assert status in NAGIOS_STATUS, "Invalid Nagios status code"
    # prefix status name to message
    output = "{}: {}".format(NAGIOS_STATUS[status], message)
    print(output)
    sys.exit(status)


def get_cmd_output(cmd):
    """Get shell command output in unicode string."""
    return subprocess.check_output(cmd).decode("utf-8").strip()


def convert_time(str_time):
    """Convert str time to datetime object."""
    try:
        return datetime.strptime(str_time, UPTIME_FORMAT)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "time must be in format {}, "
            "same as output from `uptime --since`.".format(UPTIME_FORMAT_HUMAN)
        ) from exc


def main():
    """Check reboot."""
    parser = argparse.ArgumentParser(
        description="Check reboot time via uptime",
    )

    parser.add_argument(
        "known_reboot_time",
        type=convert_time,
        help="in format {}, same as output from `uptime --since`".format(
            UPTIME_FORMAT_HUMAN
        ),
    )

    args = parser.parse_args()

    current_reboot_time_str = get_cmd_output(["uptime", "--since"])
    current_reboot_time = convert_time(current_reboot_time_str)
    delta = current_reboot_time - args.known_reboot_time
    # `uptime --since` output maybe flapping because ntp is changing sytem time
    # here we allow 5s gap to avoid fake alert
    if delta.total_seconds() > 5.0:
        nagios_exit(
            NAGIOS_STATUS_CRITICAL, "unknown reboot at {}".format(current_reboot_time)
        )
    else:
        nagios_exit(
            NAGIOS_STATUS_OK, "system is up since {}".format(current_reboot_time)
        )


if __name__ == "__main__":
    main()
