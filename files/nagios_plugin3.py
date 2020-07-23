#!/usr/bin/env python3
"""Nagios plugin for python3."""

# Copyright (C) 2005, 2006, 2007, 2012, 2017  James Troup <james.troup@canonical.com>

import os
import stat
import sys
import time
import traceback


###############################################################################


class CriticalError(Exception):
    """This indicates a critical error."""

    pass


class WarnError(Exception):
    """This indicates a warning condition."""

    pass


class UnknownError(Exception):
    """This indicates a unknown error was encountered."""

    pass


def try_check(function, *args, **kwargs):
    """Perform a check with error/warn/unknown handling."""
    try:
        function(*args, **kwargs)
    except UnknownError as msg:
        print(msg)
        sys.exit(3)
    except CriticalError as msg:
        print(msg)
        sys.exit(2)
    except WarnError as msg:
        print(msg)
        sys.exit(1)
    except:  # noqa: E722
        print("{} raised unknown exception '{}'".format(function, sys.exc_info()[0]))
        print("=" * 60)
        traceback.print_exc(file=sys.stdout)
        print("=" * 60)
        sys.exit(3)


###############################################################################


def check_file_freshness(filename, newer_than=600):
    """Check a file.

    It check that file exists, is readable and is newer than <n> seconds (where
    <n> defaults to 600).
    """
    # First check the file exists and is readable
    if not os.path.exists(filename):
        raise CriticalError("%s: does not exist." % (filename))
    if os.access(filename, os.R_OK) == 0:
        raise CriticalError("%s: is not readable." % (filename))

    # Then ensure the file is up-to-date enough
    mtime = os.stat(filename)[stat.ST_MTIME]
    last_modified = time.time() - mtime
    if last_modified > newer_than:
        raise CriticalError(
            "%s: was last modified on %s and is too old (> %s "
            "seconds)." % (filename, time.ctime(mtime), newer_than)
        )
    if last_modified < 0:
        raise CriticalError(
            "%s: was last modified on %s which is in the "
            "future." % (filename, time.ctime(mtime))
        )


###############################################################################
