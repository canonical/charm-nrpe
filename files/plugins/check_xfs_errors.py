#!/usr/bin/env python3
"""Check for xfs errors and alert."""
#
# Copyright 2017 Canonical Ltd
#
# Author: Jill Rouleau <jill.rouleau@canonical.com>
#
# Check for xfs errors and alert
#
import re
import subprocess
import sys
from datetime import datetime, timedelta


# error messages commonly seen in dmesg on xfs errors
raw_xfs_errors = [
    "XFS_WANT_CORRUPTED_",
    "xfs_error_report",
    "corruption detected at xfs_",
    "Unmount and run xfs_repair",
]

xfs_regex = [re.compile(i) for i in raw_xfs_errors]

# nagios can't read from kern.log, so we look at dmesg - this does present
# a known limitation if a node is rebooted or dmesg is otherwise cleared.
log_lines = [line for line in subprocess.getoutput(["dmesg -T"]).split("\n")]

err_results = [line for line in log_lines for rgx in xfs_regex if re.search(rgx, line)]

# Look for errors within the last N minutes, specified in the check definition
check_delta = int(sys.argv[1])

# dmesg -T formatted timestamps are inside [], so we need to add them
datetime_delta = datetime.now() - timedelta(minutes=check_delta)

recent_logs = [
    i for i in err_results if datetime.strptime(i[1:25], "%c") >= datetime_delta
]

if recent_logs:
    print("CRITICAL: Recent XFS errors in kern.log." + "\n" + "{}".format(recent_logs))
    sys.exit(2)
else:
    print("OK")
    sys.exit(0)
