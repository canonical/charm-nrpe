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


def main():
    """Check reboot."""
    parser = argparse.ArgumentParser(
        description="Check reboot time via uptime",
    )

    parser.add_argument(
        "known_reboot_time",
        help="in yyyy-mm-dd HH:MM:SS format, normally output from `uptime --since`",
    )

    args = parser.parse_args()

    current_reboot_time = get_cmd_output(["uptime", "--since"])
    if current_reboot_time > args.known_reboot_time:
        nagios_exit(
            NAGIOS_STATUS_CRITICAL, "unknown reboot at {}".format(current_reboot_time)
        )
    else:
        nagios_exit(
            NAGIOS_STATUS_OK, "system is up since {}".format(current_reboot_time)
        )


if __name__ == "__main__":
    main()
