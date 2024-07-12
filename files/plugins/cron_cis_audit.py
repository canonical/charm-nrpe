#!/usr/bin/python3
"""Run cis-audit if latest results are outdated."""

import argparse
import glob
import grp
import os
import random
import re
import stat
import subprocess
import sys
import time
from pathlib import Path


def _get_major_version():
    """Get major version from /etc/os-release."""
    with open(os.path.join(os.sep, "etc", "os-release")) as fin:
        for line in fin:
            if "VERSION_ID" in line:
                value = line.strip().split("=", 1)[1]
                return int(float(value.strip('"')))
    raise OSError("No VERSION_ID in /etc/os-release")


# cis audit changed from bionic ot focal.
PROFILES_COMPATIBILITY = {
    "level1_server": "cis_level1_server",
    "level2_server": "cis_level2_server",
    "level1_workstation": "cis_level1_workstation",
    "level2_workstation": "cis_level2_workstation",
}

DISTRO_VERSION = _get_major_version()
if DISTRO_VERSION < 20:
    AUDIT_FOLDER = "/usr/share/ubuntu-scap-security-guides"
    AUDIT_RESULT_GLOB = AUDIT_FOLDER + "/cis-*-results.xml"
    AUDIT_BIN = ["/usr/sbin/cis-audit"]
else:
    AUDIT_FOLDER = "/var/lib/usg/"
    AUDIT_RESULT_GLOB = AUDIT_FOLDER + "/usg-results-*.*.xml"
    AUDIT_BIN = ["/usr/sbin/usg", "audit"]


CLOUD_INIT_LOG = "/var/log/cloud-init-output.log"

MAX_SLEEP = 600
PID_FILENAME = "/tmp/cron_cis_audit.pid"
TAILORING_CIS_FILE = Path("/etc/usg/default-tailoring.xml")


def _get_cis_hardening_profile(profile):
    """Try to read the cis profile from cloud init log or defaults to the first option.

    If the "default" tailoring file exists in /etc/usg/default-tailoring.xml,
    no profile is passed.
    """
    if TAILORING_CIS_FILE.exists():
        return None

    profiles = _get_profile_by_ubuntu_series()
    default_profile = profiles[0]

    if profile in profiles:
        return profile

    if not os.path.exists(CLOUD_INIT_LOG) or not os.access(CLOUD_INIT_LOG, os.R_OK):
        print(
            "{} not existing/accessible, default to profile '{}'".format(
                CLOUD_INIT_LOG, default_profile
            )
        )
        return default_profile

    pattern = re.compile(r"Applying Level-(1|2) scored (server|workstation)")
    for _, line in enumerate(open(CLOUD_INIT_LOG)):
        for match in re.finditer(pattern, line):
            level, machine_type = match.groups()
            return "level{}_{}".format(level, machine_type)

    return default_profile


def _get_profile_by_ubuntu_series():
    """Get the valid profile options depending on the Ubuntu series."""
    if _get_major_version() < 20:
        return list(PROFILES_COMPATIBILITY.keys())
    return list(PROFILES_COMPATIBILITY.values())


def _get_cis_result_age():
    """Get the age of the newest audit results file."""
    audit_files = glob.glob(AUDIT_RESULT_GLOB)
    if not audit_files:
        return False
    if len(audit_files) >= 1:
        audit_file = sorted(audit_files, key=os.path.getmtime).pop()
        return (time.time() - os.path.getmtime(audit_file)) / 3600


def _set_permissions():
    print("Done cis-audit, change group of result file to nagios", flush=True)
    os.chmod(AUDIT_FOLDER, stat.S_IRWXU | stat.S_IXGRP | stat.S_IRGRP)
    os.chown(AUDIT_FOLDER, 0, grp.getgrnam("nagios").gr_gid)
    for file in glob.glob(AUDIT_RESULT_GLOB):
        os.chown(file, 0, grp.getgrnam("nagios").gr_gid)
        os.chmod(file, stat.S_IWUSR | stat.S_IRUSR | stat.S_IRGRP)


def run_audit(profile):
    """Execute the cis-audit as subprocess and allow nagios group to read result."""
    cmd_run_audit = AUDIT_BIN + [profile] if profile else AUDIT_BIN
    sleep_time = random.randint(0, MAX_SLEEP)
    print("Sleeping for {}s to randomize the cis-audit start time".format(sleep_time))
    time.sleep(sleep_time)
    try:
        print("Run cis-audit: {}".format(cmd_run_audit), flush=True)
        subprocess.run(
            cmd_run_audit, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        _set_permissions()
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
        help="maximum age (h) of result file before running the audit (default 168)",
        default=168,
    )
    parser.add_argument(
        "--cis-profile",
        "-p",
        choices=[
            "",
            "level1_server",
            "level2_server",
            "level1_workstation",
            "level2_workstation",
        ],
        default="",
        type=str,
        help="cis-audit level parameter (verifies if audit report matches)",
    )
    parser.add_argument(
        "--tailoring",
        "-t",
        action="store_true",
        default=False,
        help="Whether is using the default tailoring file or not."
    )

    args = parser.parse_args(args)

    if args.tailoring and args.cis_profile:
        parser.error("You cannot provide both a tailoring file and a profile!")

    return args


def main():
    """Run cis-audit if audit results are outdated."""
    args = parse_args(sys.argv[1:])

    # folder does not exist - usg-cisbenchmark likely not installed
    if not os.path.exists(AUDIT_FOLDER) and DISTRO_VERSION < 20:
        raise FileNotFoundError(
            "Folder {} does not exist, is usg-cisbenchmark installed?".format(
                AUDIT_FOLDER
            )
        )

    # Ensure a single instance via a simple pidfile
    pid = str(os.getpid())

    if os.path.isfile(PID_FILENAME):
        sys.exit("{} already exists, exiting".format(PID_FILENAME))

    with open(PID_FILENAME, "w") as f:
        f.write(pid)

    try:
        # audit result file does not exist or is outdated
        audit_file_age_hours = _get_cis_result_age()
        if audit_file_age_hours is False or audit_file_age_hours > args.max_age:
            profile = _get_cis_hardening_profile(args.cis_profile)
            run_audit(profile)
    finally:
        os.unlink(PID_FILENAME)


if __name__ == "__main__":
    main()
