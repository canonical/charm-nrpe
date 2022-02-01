#!/usr/bin/python3
# Copyright (C) 2022 Canonical
# All rights reserved
"""Run cis-audit if latest results are outdated."""

import argparse
import glob
import grp
import os
import random
import re
import subprocess
import sys
import time


AUDIT_FOLDER = "/usr/share/ubuntu-scap-security-guides"
AUDIT_RESULT_GLOB = AUDIT_FOLDER + "/cis-*-results.xml"
CLOUD_INIT_LOG = "/var/log/cloud-init-output.log"
DEFAULT_PROFILE = "level1_server"
PROFILES = [
    "level1_server",
    "level2_server",
    "level1_workstation",
    "level2_workstation",
]
MAX_SLEEP = 600


def _get_cis_hardening_profile(profile):
    """Try to read the cis profile from cloud init log or default to level1_server."""
    if profile in PROFILES:
        return profile

    if not os.path.exists(CLOUD_INIT_LOG) or not os.access(CLOUD_INIT_LOG, os.R_OK):
        print(
            "{} not existing/accessible, default to profile '{}'".format(
                CLOUD_INIT_LOG, DEFAULT_PROFILE
            )
        )
        return DEFAULT_PROFILE
    pattern = re.compile(r"Applying Level-(1|2) scored (server|workstation)")
    for _, line in enumerate(open(CLOUD_INIT_LOG)):
        for match in re.finditer(pattern, line):
            level, machine_type = match.groups()
            return "level{}_{}".format(level, machine_type)
    return DEFAULT_PROFILE


def _get_cis_result_age():
    """Get the age of the newest audit results file."""
    audit_files = glob.glob(AUDIT_RESULT_GLOB)
    if not audit_files:
        return False
    if len(audit_files) >= 1:
        audit_file = sorted(audit_files, key=os.path.getmtime).pop()
        return (time.time() - os.path.getmtime(audit_file)) / 3600


def run_audit(profile):
    """Execute the cis-audit as subprocess and allow nagios group to read result."""
    cmd_run_audit = ["/usr/sbin/cis-audit", profile]
    sleep_time = random.randint(0, MAX_SLEEP)
    print("Sleeping for {}s to randomize the cis-audit start time".format(sleep_time))
    time.sleep(sleep_time)
    try:
        print("Run cis-audit: {}".format(cmd_run_audit), flush=True)
        subprocess.run(
            cmd_run_audit, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        print("Done cis-audit, change group of result file to nagios", flush=True)
        for file in glob.glob(AUDIT_RESULT_GLOB):
            os.chown(file, 0, grp.getgrnam("nagios").gr_gid)
    except subprocess.CalledProcessError as e:
        sys.exit(
            "Failed running command '{}' Return Code {}: {}".format(
                cmd_run_audit, e.returncode, e.output
            )
        )


def parse_args(args):
    """Parse command-line options."""
    parser = argparse.ArgumentParser(
        prog=__file__,
        description="Run cis-audit if report is outdated",
    )
    parser.add_argument(
        "--max-age",
        "-a",
        type=int,
        help="maximum age (h) of audit result file before alerting (default 170)",
        default=170,
    )
    profile_options = PROFILES + [""]
    parser.add_argument(
        "--cis-profile",
        "-p",
        choices=profile_options,
        default="",
        type=str,
        help="cis-audit level parameter (verifies if audit report matches)",
    )
    return parser.parse_args(args)


def main():
    """Run cis-audit if audit results are outdated."""
    args = parse_args(sys.argv[1:])

    # folder does not exist - usg-cisbenchmark likely not installed
    if not os.path.exists(AUDIT_FOLDER):
        raise FileNotFoundError(
            "Folder {} does not exist, is usg-cisbenchmark installed?".format(
                AUDIT_FOLDER
            )
        )

    # audit result file does not exist or is outdated
    audit_file_age_hours = _get_cis_result_age()
    if audit_file_age_hours is False or audit_file_age_hours > args.max_age:
        profile = _get_cis_hardening_profile(args.cis_profile)
        run_audit(profile)


if __name__ == "__main__":
    main()
