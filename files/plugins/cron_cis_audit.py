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


def _get_major_version():
    """Get major version from /etc/os-release."""
    with open(os.path.join(os.sep, 'etc', 'os-release')) as fin:
        for line in fin:
            if "VERSION_ID" in line:
                value = line.strip().split("=", 1)[1]
                return int(float(value.strip('"')))
    raise OSError("No VERSION_ID in /etc/os-release")


# cis audit changed from bionic ot focal.
PROFILES = [
    "level1_server",
    "level2_server",
    "level1_workstation",
    "level2_workstation",
]
DISTRO_VERSION = _get_major_version()
if DISTRO_VERSION < 20:
    AUDIT_FOLDER = "/usr/share/ubuntu-scap-security-guides"
    AUDIT_RESULT_GLOB = AUDIT_FOLDER + "/cis-*-results.xml"
    AUDIT_BIN = ["/usr/sbin/cis-audit"]
else:
    AUDIT_FOLDER = "/var/lib/usg/"
    AUDIT_RESULT_GLOB = AUDIT_FOLDER + "/usg-results-*.*.xml"
    PROFILES = ["cis_" + p for p in PROFILES]
    AUDIT_BIN = ["/usr/sbin/usg", "audit"]


CLOUD_INIT_LOG = "/var/log/cloud-init-output.log"
DEFAULT_PROFILE = PROFILES[0]

MAX_SLEEP = 600
PID_FILENAME = "/tmp/cron_cis_audit.pid"


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


def _set_permissions():
    print("Done cis-audit, change group of result file to nagios", flush=True)
    os.chmod(AUDIT_FOLDER, stat.S_IRWXU | stat.S_IXGRP | stat.S_IRGRP)
    os.chown(AUDIT_FOLDER, 0, grp.getgrnam("nagios").gr_gid)
    for file in glob.glob(AUDIT_RESULT_GLOB):
        os.chown(file, 0, grp.getgrnam("nagios").gr_gid)
        os.chmod(file, stat.S_IWUSR | stat.S_IRUSR | stat.S_IRGRP)


def run_audit(profile):
    """Execute the cis-audit as subprocess and allow nagios group to read result."""
    cmd_run_audit = AUDIT_BIN + [profile]
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
