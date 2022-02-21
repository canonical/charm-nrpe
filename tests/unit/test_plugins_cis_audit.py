"""Unit tests for files/plugins/(cron_cis_audit.py|check_cis_audit.py) module."""

import argparse
import os
import tempfile
from io import StringIO
from time import sleep
from unittest import TestCase, mock

from files.plugins import check_cis_audit, cron_cis_audit

from nagios_plugin3 import CriticalError, WarnError

DUMMY_LOGLINES = """
Processing triggers for man-db (2.8.3-2ubuntu0.1) ...
Processing triggers for libc-bin (2.27-3ubuntu1.4) ...
***Applying Level-2 scored server remediation for failures on a fresh Ubuntu 18.04 install***
"""  # noqa: E501

DUMMY_AUDIT_RESULT = """<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" id="xccdf_com.ubuntu.bionic.cis_benchmark_CIS" resolved="1" xml:lang="en" style="SCAP_1.2">
  <TestResult id="xccdf_org.open-scap_testresult_xccdf_com.ubuntu.bionic.cis_profile_Level_1_Server" start-time="2022-01-13T10:40:20" end-time="2022-01-13T10:40:45" version="2.0.1" test-system="cpe:/a:redhat:openscap:1.2.15">
    <profile idref="xccdf_com.ubuntu.bionic.cis_profile_Level_1_Server"/>
    <score system="urn:xccdf:scoring:default" maximum="100.000000">89.444443</score>
  </TestResult>
</Benchmark>
"""  # noqa: E501


class TestCronCisAudit(TestCase):
    """Test the cis-audit cron job functions."""

    cloud_init_logfile = os.path.join(tempfile.gettempdir(), "cloud-init-output.log")

    @classmethod
    def setUpClass(cls):
        """Create dummy log file."""
        with open(cls.cloud_init_logfile, "w") as f:
            f.write(DUMMY_LOGLINES)

    @classmethod
    def tearDownClass(cls):
        """Delete dummy log file."""
        if os.path.exists(cls.cloud_init_logfile):
            os.remove(cls.cloud_init_logfile)

    def test_get_cis_hardening_profile_default(self):
        """Test hardening profile passing defaults."""
        # default profile should be return if profile passed is invalid
        profile = cron_cis_audit._get_cis_hardening_profile("")
        self.assertEqual(
            profile,
            cron_cis_audit.DEFAULT_PROFILE,
            "Default profile should have been returned",
        )
        # parameter should be returned if parameter contains a valid profile
        expected_profile = cron_cis_audit.PROFILES[3]
        profile = cron_cis_audit._get_cis_hardening_profile(expected_profile)
        self.assertEqual(
            profile,
            expected_profile,
            "The profile in the parameter should have been returned",
        )

    @mock.patch("files.plugins.cron_cis_audit.CLOUD_INIT_LOG", cloud_init_logfile)
    def test_get_cis_hardening_profile_cloudinit(self):
        """Test the detection of the hardening profile from cloudinit.log."""
        expected_profile = "level2_server"
        profile = cron_cis_audit._get_cis_hardening_profile("")
        self.assertEqual(
            profile,
            expected_profile,
            "Profile from Dummy file should be 'level2_server'",
        )

    def test_get_cis_result_age(self):
        """Test file age function."""
        # file does not exist, returns false
        self.assertFalse(cron_cis_audit._get_cis_result_age())

        # file was created when test initiated, should return 0
        with mock.patch(
            "files.plugins.cron_cis_audit.AUDIT_RESULT_GLOB", self.cloud_init_logfile
        ):
            age_in_hours = cron_cis_audit._get_cis_result_age()
            self.assertLess(
                age_in_hours,
                0.1,
                "File age should be small because the file was just created",
            )

    @mock.patch("sys.stderr", new_callable=StringIO)
    def test_parse_args(self, mock_stderr):
        """Test the default parsing behavior of the argument parser."""
        # test empty parameters
        args = cron_cis_audit.parse_args([])
        self.assertEqual(args, argparse.Namespace(cis_profile="", max_age=170))

        # test setting parameters
        args = cron_cis_audit.parse_args(["-a 1", "-p=level2_workstation"])
        self.assertEqual(
            args, argparse.Namespace(cis_profile="level2_workstation", max_age=1)
        )

        # test setting invalid parameter
        with self.assertRaises(SystemExit):
            cron_cis_audit.parse_args(["-p=invalid-parameter-test"])
        self.assertRegex(
            mock_stderr.getvalue(), r"invalid choice: 'invalid-parameter-test'"
        )

    @mock.patch("sys.argv", [])
    def test_main_raise_exception(self):
        """Test if main() raises FileNotFoundError if AUDIT_FOLDER does not exist."""
        with self.assertRaises(FileNotFoundError):
            cron_cis_audit.main()

    @mock.patch("files.plugins.cron_cis_audit.MAX_SLEEP", 1)
    @mock.patch("files.plugins.cron_cis_audit.AUDIT_FOLDER", "/tmp")
    @mock.patch("sys.argv", [])
    def test_main_run_audit(self):
        """Test if main() calles cis-audit is called with correct arguments."""
        with mock.patch("subprocess.run") as mock_subprocess_run:
            process_mock = mock.Mock()
            attrs = {"communicate.return_value": ("output", "error")}
            process_mock.configure_mock(**attrs)
            mock_subprocess_run.return_value = process_mock
            cron_cis_audit.main()
            self.assertTrue(mock_subprocess_run.called)
            self.assertEqual(
                str(mock_subprocess_run.call_args),
                "call(['/usr/sbin/cis-audit', 'level1_server'], stdout=-3, stderr=-3)",
            )


class TestCheckCisAudit(TestCase):
    """Test the cis-audit cron job functions."""

    audit_result_folder = os.path.join(tempfile.gettempdir(), "test-audit-result")
    audit_results_glob = audit_result_folder + "/cis-*-results.xml"
    testfile1 = os.path.join(audit_result_folder, "cis-testfile1-results.xml")
    testfile2 = os.path.join(audit_result_folder, "cis-testfile2-results.xml")

    @classmethod
    def setUpClass(cls):
        """Create dummy audit folder and files."""
        if not os.path.exists(cls.audit_result_folder):
            os.mkdir(cls.audit_result_folder)
            with open(cls.testfile1, mode="a"):
                pass  # create empty file
            sleep(0.1)
            with open(cls.testfile2, mode="w") as f:
                f.write(DUMMY_AUDIT_RESULT)

    @classmethod
    def tearDownClass(cls):
        """Delete dummy log file."""
        if os.path.exists(cls.audit_result_folder):
            for file in os.listdir(cls.audit_result_folder):
                os.remove(os.path.join(cls.audit_result_folder, file))
            os.rmdir(cls.audit_result_folder)

    def test_get_audit_result_filepath_not_found(self):
        """Test that the audit results file can be found."""
        with self.assertRaises(CriticalError):
            check_cis_audit.get_audit_result_filepath()

    @mock.patch("files.plugins.check_cis_audit.AUDIT_RESULT_GLOB", audit_results_glob)
    def test_get_audit_result_filepath_found(self):
        """Test that the newest audit file is returned."""
        audit_result_filepath = check_cis_audit.get_audit_result_filepath()
        expected = os.path.join(self.audit_result_folder, "cis-testfile2-results.xml")
        self.assertEqual(audit_result_filepath, expected)

    def test_check_file_max_age(self):
        """Test that an exception is raised if the file is too old."""
        with self.assertRaises(CriticalError):
            check_cis_audit.check_file_max_age(0, self.testfile1)

    def test_parse_profile_idref(self):
        """Test that profile parsing works correctly."""
        with self.assertRaises(CriticalError):
            check_cis_audit.parse_profile_idref("unknown_profile")

        profile_id = "xccdf_com.ubuntu.bionic.cis_profile_Level_2_Workstation"
        self.assertEqual(
            "level2_workstation", check_cis_audit.parse_profile_idref(profile_id)
        )

    def test_get_audit_score_and_profile(self):
        """Test the parsing of the audit results file."""
        # empty file raises CriticalError
        with self.assertRaises(CriticalError):
            check_cis_audit.get_audit_score_and_profile(self.testfile1)

        # score and profile correctly read from xml
        score, profile = check_cis_audit.get_audit_score_and_profile(self.testfile2)
        self.assertEqual(score, 89.444443)
        self.assertEqual(profile, "level1_server")

    @mock.patch("sys.argv", [])
    def test_parse_args(self):
        """Test the argument parsing."""
        # test default arguments
        arguments = check_cis_audit.parse_args([])
        self.assertEqual(
            arguments,
            argparse.Namespace(
                cis_profile="",
                crit=-1,
                max_age=170,
                warn=-1,
            ),
        )

        # test setting arguments
        arguments = check_cis_audit.parse_args(
            ["-a", "1", "-c", "99", "-w", "90", "-p", "level2_server"]
        )
        self.assertEqual(
            arguments,
            argparse.Namespace(
                cis_profile="level2_server",
                crit=99,
                max_age=1,
                warn=90,
            ),
        )

    @mock.patch("files.plugins.check_cis_audit.AUDIT_RESULT_GLOB", audit_results_glob)
    def test_check_cis_audit(self):
        """Test the check function with different parameters."""
        # all ok
        check_cis_audit.check_cis_audit("", 1, 80, 85)

        # too old
        with self.assertRaises(CriticalError) as error:
            check_cis_audit.check_cis_audit("", 0, 80, 85)
        self.assertRegex(
            str(error.exception),
            "CRITICAL: The audit result file age 0.00h is older than threshold.*",
        )

        # score below warning
        with self.assertRaises(WarnError) as error:
            check_cis_audit.check_cis_audit("", 1, 90, 80)
        self.assertRegex(
            str(error.exception),
            "WARNING: cis-audit score is 89.44 of 100; threshold -c 80 -w 90",
        )

        # score below critical
        with self.assertRaises(CriticalError) as error:
            check_cis_audit.check_cis_audit("", 1, 95, 90)
        self.assertRegex(
            str(error.exception),
            "CRITICAL: cis-audit score is 89.44 of 100; threshold -c 90 -w 95",
        )

        # profile does not match
        with self.assertRaises(CriticalError) as error:
            check_cis_audit.check_cis_audit("level2_workstation", 1, 85, 80)
        self.assertRegex(
            str(error.exception),
            "CRITICAL: requested audit profile 'level2_workstation' does not match",
        )

    @mock.patch("files.plugins.check_cis_audit.AUDIT_RESULT_GLOB", audit_results_glob)
    def test_main(self):
        """Test the main function."""
        namespace = argparse.Namespace(cis_profile="", max_age=1, crit=80, warn=70)
        with mock.patch("argparse.ArgumentParser.parse_args", return_value=namespace):
            check_cis_audit.main()
