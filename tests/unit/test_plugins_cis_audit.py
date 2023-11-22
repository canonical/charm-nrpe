"""Unit tests for files/plugins/(cron_cis_audit.py|check_cis_audit.py) module."""

import argparse
import grp
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

FOCAL_DUMMY_AUDIT_RESULT = """
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" id="xccdf_org.ssgproject.content_benchmark_UBUNTU_22-04" resolved="1" xml:lang="en-US" style="SCAP_1.2">
  <TestResult id="xccdf_org.open-scap_testresult_xccdf_org.ssgproject.content_profile_cis_level1_server" start-time="2023-11-17T10:10:03" end-time="2023-11-17T10:11:26" version="0.1.67" test-system="cpe:/a:redhat:openscap:1.2.17">
    <benchmark href="/usr/share/ubuntu-scap-security-guides/current/benchmarks/ssg-ubuntu2204-xccdf.xml" id="xccdf_org.ssgproject.content_benchmark_UBUNTU_22-04"/>
    <profile idref="xccdf_org.ssgproject.content_profile_cis_level1_server"/>
    <score system="urn:xccdf:scoring:default" maximum="100.000000">66.160233</score>
  </TestResult>
</Benchmark>
"""  # noqa: E501


class TestCronCisAudit(TestCase):
    """Test the cis-audit cron job functions."""

    cloud_init_logfile = os.path.join(tempfile.gettempdir(), "cloud-init-output.log")
    bionic_profiles = [
        "level1_server",
        "level2_server",
        "level1_workstation",
        "level2_workstation",
    ]
    bionic_audit_folder = "/usr/share/ubuntu-scap-security-guides"
    bionic_audit_result_glob = bionic_audit_folder + "/cis-*-results.xml"
    bionic_audit_bin = ["/usr/sbin/cis-audit"]

    focal_audit_folder = "/var/lib/usg/"
    focal_audit_result_glob = focal_audit_folder + "/usg-results-*.*.xml"
    focal_profiles = ["cis_" + p for p in bionic_profiles]
    focal_audit_bin = ["/usr/sbin/usg", "audit"]

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

    @mock.patch.multiple(
        "files.plugins.cron_cis_audit",
        DEFAULT_PROFILE=bionic_profiles[0],
        PROFILES=bionic_profiles,
    )
    @mock.patch("sys.stderr", new_callable=StringIO)
    def test_parse_args(self, mock_stderr):
        """Test the default parsing behavior of the argument parser."""
        # test empty parameters
        args = cron_cis_audit.parse_args([])
        self.assertEqual(args, argparse.Namespace(cis_profile="", max_age=168))

        # test setting parameters
        args = cron_cis_audit.parse_args(["-a 1", f"-p={self.bionic_profiles[3]}"])
        self.assertEqual(
            args, argparse.Namespace(cis_profile=self.bionic_profiles[3], max_age=1)
        )

        # test setting invalid parameter
        with self.assertRaises(SystemExit):
            cron_cis_audit.parse_args(["-p=invalid-parameter-test"])
        self.assertRegex(
            mock_stderr.getvalue(), r"invalid choice: 'invalid-parameter-test'"
        )

    @mock.patch("sys.argv", [])
    @mock.patch("files.plugins.cron_cis_audit.MAX_SLEEP", 1)
    def test_main_raise_exception(self):
        """Test if main() raises FileNotFoundError if AUDIT_FOLDER does not exist."""
        with self.assertRaises(FileNotFoundError):
            cron_cis_audit.main()

    @mock.patch("files.plugins.cron_cis_audit.AUDIT_FOLDER", focal_audit_folder)
    @mock.patch("files.plugins.cron_cis_audit.glob.glob", return_value=["testfile"])
    @mock.patch("os.chmod")
    @mock.patch("os.chown")
    @mock.patch("grp.getgrnam")
    def test_set_permissions(self, mock_grp, mock_chown, mock_chmod, mock_glob):
        """Test if _set_permissions changes the permissions as expected."""
        mock_grp.return_value = grp.struct_group(
            ("mockgroup", "mockpasswd", "1000", "mockuser")
        )
        cron_cis_audit._set_permissions()
        mock_chown.assert_has_calls(
            [
                mock.call(self.focal_audit_folder, 0, "1000"),
                mock.call("testfile", 0, "1000"),
            ]
        )

    @mock.patch("files.plugins.cron_cis_audit.MAX_SLEEP", 1)
    @mock.patch.multiple(
        "files.plugins.cron_cis_audit",
        AUDIT_FOLDER=bionic_audit_folder,
        AUDIT_BIN=bionic_audit_bin,
        DISTRO_VERSION=18,
        DEFAULT_PROFILE=bionic_profiles[0],
    )
    @mock.patch("files.plugins.cron_cis_audit._set_permissions", lambda: True)
    @mock.patch("sys.argv", [])
    @mock.patch("os.path.exists", lambda x: True)
    def test_main_run_audit_bionic(self):
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
                f"call(['{self.bionic_audit_bin[0]}', "
                f"'{self.bionic_profiles[0]}'], stdout=-3, stderr=-3)",
            )

    @mock.patch("files.plugins.cron_cis_audit.MAX_SLEEP", 1)
    @mock.patch.multiple(
        "files.plugins.cron_cis_audit",
        AUDIT_FOLDER=focal_audit_folder,
        AUDIT_BIN=focal_audit_bin,
        DISTRO_VERSION=18,
        DEFAULT_PROFILE=focal_profiles[0],
    )
    @mock.patch("files.plugins.cron_cis_audit._set_permissions", lambda: True)
    @mock.patch("sys.argv", [])
    @mock.patch("os.path.exists", lambda x: True)
    def test_main_run_audit_focal(self):
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
                f"call(['{self.focal_audit_bin[0]}', "
                f"'{self.focal_audit_bin[1]}', "
                f"'{self.focal_profiles[0]}'], stdout=-3, stderr=-3)",
            )


class TestCheckCisAudit(TestCase):
    """Test the cis-audit cron job functions."""

    audit_result_folder = os.path.join(tempfile.gettempdir(), "test-audit-result")

    bionic_profile_map = {
        "level1_server": "cis_profile_Level_1_Server",
        "level2_server": "cis_profile_Level_2_Server",
        "level1_workstation": "cis_profile_Level_1_Workstation",
        "level2_workstation": "cis_profile_Level_2_Workstation",
    }
    # bionic_audit_folder = "/usr/share/ubuntu-scap-security-guides"
    bionic_audit_result_glob = audit_result_folder + "/cis-*-results.xml"

    # focal_audit_folder = "/var/lib/usg/"
    focal_audit_result_glob = audit_result_folder + "/usg-results-*.*.xml"
    focal_profile_map = {
        "level1_server": "cis_level1_server",
        "level2_server": "cis_level2_server",
        "level1_workstation": "cis_level1_workstation",
        "level2_workstation": "cis_level2_workstation",
    }

    bionic_testfile1 = os.path.join(audit_result_folder, "cis-testfile1-results.xml")
    bionic_testfile2 = os.path.join(audit_result_folder, "cis-testfile2-results.xml")

    focal_testfile1 = os.path.join(audit_result_folder, "usg-results-testfile1.123.xml")
    focal_testfile2 = os.path.join(audit_result_folder, "usg-results-testfile2.123.xml")

    @classmethod
    def setUpClass(cls):
        """Create dummy audit folder and files."""
        if not os.path.exists(cls.audit_result_folder):
            os.mkdir(cls.audit_result_folder)
            with open(cls.bionic_testfile1, mode="a"):
                pass  # create empty file
            sleep(0.1)
            with open(cls.bionic_testfile2, mode="w") as f:
                f.write(DUMMY_AUDIT_RESULT)
            sleep(0.1)
            with open(cls.focal_testfile1, mode="a"):
                pass  # create empty file
            sleep(0.1)
            with open(cls.focal_testfile2, mode="w") as f:
                f.write(FOCAL_DUMMY_AUDIT_RESULT)

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

    def test_get_audit_result_filepath_found(self):
        """Test that the newest audit file is returned."""
        with mock.patch(
            "files.plugins.check_cis_audit.AUDIT_RESULT_GLOB",
            self.bionic_audit_result_glob,
        ):
            audit_result_filepath = check_cis_audit.get_audit_result_filepath()
            expected = os.path.join(
                self.audit_result_folder, "cis-testfile2-results.xml"
            )
            self.assertEqual(audit_result_filepath, expected)
        # check focal
        with mock.patch(
            "files.plugins.check_cis_audit.AUDIT_RESULT_GLOB",
            self.focal_audit_result_glob,
        ):
            audit_result_filepath = check_cis_audit.get_audit_result_filepath()
            expected = os.path.join(
                self.audit_result_folder, "usg-results-testfile2.123.xml"
            )
            self.assertEqual(audit_result_filepath, expected)

    def test_check_file_max_age(self):
        """Test that an exception is raised if the file is too old."""
        with self.assertRaises(CriticalError):
            check_cis_audit.check_file_max_age(0, self.bionic_testfile1)

    @mock.patch("files.plugins.check_cis_audit.PROFILE_MAP", bionic_profile_map)
    def test_parse_profile_idref(self):
        """Test that profile parsing works correctly."""
        with self.assertRaises(CriticalError):
            check_cis_audit.parse_profile_idref("unknown_profile")

        profile_id = "xccdf_com.ubuntu.bionic.cis_profile_Level_2_Workstation"
        self.assertEqual(
            "level2_workstation", check_cis_audit.parse_profile_idref(profile_id)
        )

    @mock.patch("files.plugins.check_cis_audit.PROFILE_MAP", bionic_profile_map)
    def test_get_audit_score_and_profile_bionic(self):
        """Test the parsing of the audit results file."""
        # empty file raises CriticalError
        with self.assertRaises(CriticalError):
            check_cis_audit.get_audit_score_and_profile(self.bionic_testfile1)

        # score and profile correctly read from xml
        score, profile = check_cis_audit.get_audit_score_and_profile(
            self.bionic_testfile2
        )
        self.assertEqual(score, 89.444443)
        self.assertEqual(profile, "level1_server")

    @mock.patch("files.plugins.check_cis_audit.PROFILE_MAP", focal_profile_map)
    def test_get_audit_score_and_profile_focal(self):
        """Test the parsing of the audit results file."""
        # empty file raises CriticalError
        with self.assertRaises(CriticalError):
            check_cis_audit.get_audit_score_and_profile(self.focal_testfile1)

        # score and profile correctly read from xml
        score, profile = check_cis_audit.get_audit_score_and_profile(
            self.focal_testfile2
        )
        self.assertEqual(score, 66.160233)
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
                max_age=172,
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

    @mock.patch.multiple(
        "files.plugins.check_cis_audit",
        AUDIT_RESULT_GLOB=bionic_audit_result_glob,
        PROFILE_MAP=bionic_profile_map,
    )
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

    @mock.patch.multiple(
        "files.plugins.check_cis_audit",
        AUDIT_RESULT_GLOB=bionic_audit_result_glob,
        PROFILE_MAP=bionic_profile_map,
    )
    def test_main(self):
        """Test the main function."""
        namespace = argparse.Namespace(cis_profile="", max_age=1, crit=80, warn=70)
        with mock.patch("argparse.ArgumentParser.parse_args", return_value=namespace):
            check_cis_audit.main()
