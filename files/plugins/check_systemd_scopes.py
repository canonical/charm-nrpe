#!/usr/bin/env python3
"""Review systemd state scopes and return a nagios status based on their count."""

# Copyright (C) 2022 Canonical Ltd.
# All rights reserved
# Author: John P Lettman <john.lettman@canonical.com>

import re
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser, ArgumentTypeError
from subprocess import CalledProcessError, PIPE, check_output

from nagios_plugin3 import CriticalError, UnknownError, WarnError, try_check

DEFAULT_WARN_ERROR = 25
DEFAULT_CRIT_ERROR = 50

DEFAULT_WARN_ABANDONED = 25
DEFAULT_CRIT_ABANDONED = 50

RE_SCOPES = re.compile("[\\w\\d\\-_]+\\.scope", re.I | re.M)
BIN_SYSTEMCTL = "/bin/systemctl"


def count_systemd_scopes(output):
    """Count the number of `.scope` units in provided output text."""
    return len(RE_SCOPES.findall(output))


def get_systemd_scopes_state(state):
    """Get output for systemd scopes in specified state."""
    # While it is possible to use `grep` within the `check_output` call,
    # there arises an issue when `grep` counts 0. It will return an error code.
    # Therefore, this check uses a pre-compiled regular expression to count.
    cmd = [
        "/bin/sh",
        "-c",
        "{} list-units --type=scope --state={} --no-pager".format(BIN_SYSTEMCTL, state),
    ]
    return check_output(cmd, stderr=PIPE).decode("UTF-8")


def count_systemd_scopes_state(state):
    """Count number of `.scope` units in specified state."""
    try:
        scopes = get_systemd_scopes_state(state)
        return count_systemd_scopes(scopes)
    except CalledProcessError as e:
        err = e.stderr.decode("UTF-8")
        raise UnknownError(
            "UNKNOWN: Unable to check systemd abandoned state scopes: {}".format(err)
        )
    except ValueError:
        # ideally, this should never occur
        raise UnknownError(
            "UNKNOWN: Counting systemd abandoned state scopes returns non-integer"
        )


def check_systemd_scopes(args):
    """Check number of systemd scopes in error and abandoned states."""
    # Check scopes in 'error' state
    error_count = count_systemd_scopes_state("error")
    if error_count >= args.crit_error:
        raise CriticalError(
            "CRITICAL: System has {} systemd scopes in error state".format(error_count)
        )
    elif error_count >= args.warn_error:
        raise WarnError(
            "WARNING: System has {} systemd scopes in error state".format(error_count)
        )

    # Check scopes in 'abandoned' state
    abandoned_count = count_systemd_scopes_state("abandoned")
    if error_count >= args.crit_abandoned:
        raise CriticalError(
            "CRITICAL: System has {} systemd scopes in abandoned state".format(
                error_count
            )
        )
    elif error_count >= args.warn_abandoned:
        raise WarnError(
            "WARNING: System has {} systemd scopes in abandoned state".format(
                error_count
            )
        )

    # With no nagios errors raised, we are in an "OK" state
    # Print the counts from each state as informational, may help in monitoring
    print(
        "OK: {}; {} in error state, {} in abandoned state".format(
            args.ok_message, error_count, abandoned_count
        )
    )


def positive_int(value):
    """Ensure the provided value is a positive integer greater than 0."""
    try:
        value = int(value)
    except ValueError:
        raise Exception("{} is not an integer".format(value))

    if value <= 0:
        raise ArgumentTypeError("{} is not a positive integer".format(value))
    return value


def parse_args(args=None):
    """Parse command-line options."""
    parser = ArgumentParser(
        description=__doc__, formatter_class=ArgumentDefaultsHelpFormatter
    )

    # Thresholds for the scopes in 'error' state
    parser.add_argument(
        "-e",
        "--warn-error",
        type=positive_int,
        default=DEFAULT_WARN_ERROR,
        metavar="WARN_THRESH",
        help="At the specified threshold number of error state scopes, "
        "raise a nagios WARN state",
    )
    parser.add_argument(
        "-E",
        "--crit-error",
        type=positive_int,
        default=DEFAULT_CRIT_ERROR,
        metavar="CRIT_THRESH",
        help="At the specified threshold number of error state scopes, "
        "raise a nagios CRIT state",
    )

    # Thresholds for the scopes in 'abandoned' state
    parser.add_argument(
        "-a",
        "--warn-abandoned",
        type=positive_int,
        default=DEFAULT_WARN_ABANDONED,
        metavar="WARN_THRESH",
        help="At the specified threshold number of abandoned state scopes, "
        "raise a nagios WARN state",
    )
    parser.add_argument(
        "-A",
        "--crit-abandoned",
        type=positive_int,
        default=DEFAULT_CRIT_ABANDONED,
        metavar="CRIT_THRESH",
        help="At the specified threshold number of abandoned state scopes, "
        "raise a nagios CRIT state",
    )

    # Customization of the nagios "OK" message
    parser.add_argument(
        "-o",
        "--ok-message",
        default="Nominal",
        metavar="MSG",
        help="Message indicating an OK status",
    )

    return parser.parse_args(args)


if __name__ == "__main__":
    args = parse_args()
    try_check(check_systemd_scopes, args)
