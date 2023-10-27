#!/usr/bin/env python3
"""
Check CIS audit score and verify the age of the last report.

This check relies on a cron job that runs 'cis-audit' periodically.
'cis-audit' is part of the 'usg-cisbenchmark' package that is available to
Ubuntu Advantage customers.

Example: check_cis_audit.py -p level2_server -a 170 -w 85 -c 80
"""


import argparse
import glob
import os
import sys
import time
import xml.etree.ElementTree as ElementTree


from nagios_plugin3 import (
    CriticalError,
    WarnError,
    try_check,
)


# cis-audit changed between bionic and focal
if os.path.isfile("/usr/sbin/cis-audit"):
    AUDIT_FOLDER = "/usr/share/ubuntu-scap-security-guides"
    AUDIT_RESULT_GLOB = AUDIT_FOLDER + "/cis-*-results.xml"
    PROFILE_MAP = {
        "level1_server": "cis_profile_Level_1_Server",
        "level2_server": "cis_profile_Level_2_Server",
        "level1_workstation": "cis_profile_Level_1_Workstation",
        "level2_workstation": "cis_profile_Level_2_Workstation",
    }
else:
    AUDIT_FOLDER = "/var/lib/usg"
    AUDIT_RESULT_GLOB = AUDIT_FOLDER + "/usg-results-*.*.xml"
    PROFILE_MAP = {
      "level1_server": "cis_level1_server",
      "level2_server": "cis_level2_server",
      "level1_workstation": "cis_level1_workstation",
      "level2_workstation": "cis_level2_workstation",
    }


def get_audit_result_filepath():
    """Get the path of the newest audit results file."""
    audit_files = glob.glob(AUDIT_RESULT_GLOB)
    if not audit_files:
        msg = (
            "CRITICAL: Could not find audit results file '{}', "
            "make sure package usg-cisbenchmark is installed and cis-audit "
            "cron job is running"
        ).format(AUDIT_RESULT_GLOB)
        raise CriticalError(msg)
    # get newest results file if there are multiple (e.g. after upgrade)
    return sorted(audit_files, key=os.path.getmtime).pop()


def check_file_max_age(max_age, results_filepath):
    """Verify the age of the file against the max_age parameter."""
    age_hours = (time.time() - os.path.getmtime(results_filepath)) / 3600
    if age_hours > max_age:
        msg = (
            "CRITICAL: The audit result file age {:.2f}h is older than threshold {}h "
            "for '{}', make sure the cis-audit cronjob is working"
        ).format(age_hours, max_age, results_filepath)
        raise CriticalError(msg)


def parse_profile_idref(profile_idref):
    """Parse the profile idref and return cis-audit level."""
    for profile in PROFILE_MAP:
        if profile_idref.endswith(PROFILE_MAP[profile]):
            return profile

    msg = "CRITICAL: could not determine profile from idref '{}'"
    raise CriticalError(msg.format(profile_idref))


def get_audit_score_and_profile(results_filepath):
    """Extract audit score and profile level from results xml file."""
    try:
        root = ElementTree.parse(results_filepath).getroot()
        namespace = root.tag.split("Benchmark")[0]
        score = root.find(namespace + "TestResult/" + namespace + "score").text
        profile_xml = root.find(namespace + "TestResult/" + namespace + "profile")
        profile = parse_profile_idref(profile_xml.attrib["idref"])
    except ElementTree.ParseError as parse_error:
        msg = "CRITICAL: Could not parse audit results file '{}': '{}'"
        raise CriticalError(msg.format(results_filepath, parse_error))
    except PermissionError as permission_error:
        msg = "CRITICAL: Could not read audit results file '{}': {}"
        raise CriticalError(msg.format(results_filepath, permission_error))
    return float(score), profile


def check_cis_audit(target_profile, max_age, warning, critical):
    """Check if recent audit report exists and score and level are as specified."""
    results_filepath = get_audit_result_filepath()
    check_file_max_age(max_age, results_filepath)
    score, profile = get_audit_score_and_profile(results_filepath)

    msg = "{}: cis-audit score is {:.2f} of 100; threshold -c {} -w {} ({}; {})"
    if score < critical:
        raise CriticalError(
            msg.format("CRITICAL", score, critical, warning, profile, results_filepath)
        )
    if score < warning:
        raise WarnError(
            msg.format("WARNING", score, critical, warning, profile, results_filepath)
        )

    if target_profile != "" and target_profile != profile:
        msg = (
            "CRITICAL: requested audit profile '{}' does not match "
            "report profile '{}' from '{}'"
        ).format(target_profile, profile, results_filepath)
        raise CriticalError(msg)

    print("OK: cis-audit score is {:.2f} of 100 (profile: {})".format(score, profile))


def parse_args(args):
    """Parse command-line options."""
    parser = argparse.ArgumentParser(
        prog=__file__,
        description="Check CIS audit score",
    )
    parser.add_argument(
        "--max-age",
        "-a",
        type=int,
        help="maximum age (h) of audit result file before alerting (default 170)",
        default=172,
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
        help="cis-audit level parameter (verifies if audit report matches)",
        default="",
    )
    parser.add_argument(
        "--warn",
        "-w",
        type=int,
        help="a score below this number results in status WARNING (default: -1)",
        default=-1,
    )
    parser.add_argument(
        "--crit",
        "-c",
        type=int,
        help="a score below this number results in status CRITICAL (default: -1)",
        default=-1,
    )
    args = parser.parse_args(args)
    return args


def main():
    """Parse args and check the audit report."""
    args = parse_args(sys.argv[1:])
    try_check(check_cis_audit, args.cis_profile, args.max_age, args.warn, args.crit)


if __name__ == "__main__":
    main()
