#!/usr/bin/env python3
"""Test the files/plugins/check_systemd_scopes.py plugin."""

# Copyright (C) 2022 Canonical Ltd.
# All rights reserved
# Author: John P Lettman <john.lettman@canonical.com>

from argparse import ArgumentTypeError, Namespace
from io import StringIO
from subprocess import CalledProcessError
from unittest import TestCase, mock

from nagios_plugin3 import CriticalError, UnknownError, WarnError

from plugins import check_systemd_scopes


SAMPLE_SCOPES_OUTPUT_X4 = """
  UNIT             LOAD   ACTIVE SUB     DESCRIPTION               
  init.scope       loaded active running System and Service Manager
  session-3.scope  loaded active running Session 3 of user jlettman
  session-5.scope  loaded active running Session 5 of user jlettman
  session-c1.scope loaded active running Session c1 of user gdm    

LOAD   = Reflects whether the unit definition was properly loaded.
ACTIVE = The high-level unit activation state, i.e. generalization of SUB.
SUB    = The low-level unit activation state, values depend on unit type.

4 loaded units listed. Pass --all to see loaded but inactive units, too.
To show all installed unit files use 'systemctl list-unit-files'.
"""  # noqa W291

SAMPLE_SCOPES_OUTPUT_X0 = """
  UNIT LOAD ACTIVE SUB DESCRIPTION
0 loaded units listed.
"""  # noqa W291


def mock_check_output_x4(_):
    """Mock check_output, return fake systemctl list-units with 4 scopes."""
    return SAMPLE_SCOPES_OUTPUT_X4.encode("UTF-8")


class TestCheckSystemdScopes(TestCase):
    """Test the check_systemd_scopes package contents."""

    def test_count_systemd_scopes(self):
        """Test count_systemd_scopes with sample inputs."""
        # test counting output with 4 scopes listed
        count = check_systemd_scopes.count_systemd_scopes(SAMPLE_SCOPES_OUTPUT_X4)
        self.assertEqual(count, 4)

        # test counting output with 0 scopes listed
        count = check_systemd_scopes.count_systemd_scopes(SAMPLE_SCOPES_OUTPUT_X0)
        self.assertEqual(count, 0)

    @mock.patch("plugins.check_systemd_scopes.BIN_SYSTEMCTL", "/bin/doesnt-exist")
    def test_get_systemd_scopes_state_nosystemctl(self):
        """Test get_systemd_scopes_state on systems without systemctl."""
        with self.assertRaises(CalledProcessError):
            check_systemd_scopes.get_systemd_scopes_state("test")

    @mock.patch(
        "plugins.check_systemd_scopes.get_systemd_scopes_state",
        lambda _: SAMPLE_SCOPES_OUTPUT_X4,
    )
    def test_count_systemd_scopes_state(self):
        """Test count_systemd_scopes_state with overridden X4 output."""
        count = check_systemd_scopes.count_systemd_scopes_state("test")
        self.assertEqual(count, 4)

    @mock.patch("plugins.check_systemd_scopes.BIN_SYSTEMCTL", "/bin/doesnt-exist")
    def test_count_systemd_scopes_state_nosystemctl(self):
        """Test count_systemd_scopes_state on systems without systemctl."""
        with self.assertRaises(UnknownError):
            check_systemd_scopes.count_systemd_scopes_state("test")

    @mock.patch("sys.stdout", new_callable=StringIO)
    @mock.patch("subprocess.check_output", mock_check_output_x4)
    def assert_check_stdout(self, args, expected_output, mock_stdout):
        """Capture and assertEqual on prints within check_systemd_scopes."""
        check_systemd_scopes.check_systemd_scopes(args)
        self.assertEqual(mock_stdout.getvalue(), expected_output)

    @mock.patch(
        "plugins.check_systemd_scopes.get_systemd_scopes_state",
        lambda _: SAMPLE_SCOPES_OUTPUT_X4,
    )
    def test_check_systemd_scopes(self):
        """Test check_systemd_scopes with various thresholds."""
        # test with standard arguments and mocked x4 scopes
        args = check_systemd_scopes.parse_args(
            ["-e", "1000", "-E", "2000", "-a", "1000", "-A", "2000", "-o", "Nominal"]
        )

        self.assert_check_stdout(args, "OK: Nominal; 4 in error state, 4 in abandoned state\n")

        # test arguments to invoke WARN on error state x4 scopes
        args = check_systemd_scopes.parse_args(
            ["-e", "3", "-E", "2000", "-a", "1000", "-A", "2000", "-o", "Nominal"]
        )

        with self.assertRaises(WarnError) as error:
            check_systemd_scopes.check_systemd_scopes(args)

        self.assertEqual(
            str(error.exception), "WARNING: System has 4 systemd scopes in error state"
        )

        # test arguments to invoke CRIT on error state x4 scopes
        args = check_systemd_scopes.parse_args(
            ["-e", "4", "-E", "3", "-a", "1000", "-A", "2000", "-o", "Nominal"]
        )

        with self.assertRaises(CriticalError) as error:
            check_systemd_scopes.check_systemd_scopes(args)

        self.assertEqual(
            str(error.exception), "CRITICAL: System has 4 systemd scopes in error state"
        )

        # test arguments to invoke WARN on abandoned state x4 scopes
        args = check_systemd_scopes.parse_args(
            ["-e", "1000", "-E", "2000", "-a", "3", "-A", "2000", "-o", "Nominal"]
        )

        with self.assertRaises(WarnError) as error:
            check_systemd_scopes.check_systemd_scopes(args)

        self.assertEqual(
            str(error.exception),
            "WARNING: System has 4 systemd scopes in abandoned state",
        )

        # test arguments to invoke CRIT on abandoned state x4 scopes
        args = check_systemd_scopes.parse_args(
            ["-e", "1000", "-E", "2000", "-a", "4", "-A", "3", "-o", "Nominal"]
        )

        with self.assertRaises(CriticalError) as error:
            check_systemd_scopes.check_systemd_scopes(args)

        self.assertEqual(
            str(error.exception),
            "CRITICAL: System has 4 systemd scopes in abandoned state",
        )

    def test_positive_int(self):
        """Test postive_int with various user inputs."""
        # test with a negative number, expect raise of ArgumentTypeError
        with self.assertRaises(ArgumentTypeError) as error:
            check_systemd_scopes.positive_int("-10")

        self.assertEqual(str(error.exception), "-10 is not a positive integer")

        # test with 0, expect raise of ArgumentTypeError
        with self.assertRaises(ArgumentTypeError) as error:
            check_systemd_scopes.positive_int("0")

        self.assertEqual(str(error.exception), "0 is not a positive integer")

        # test with positive non-zero number, expect int(val) return
        val = check_systemd_scopes.positive_int("10")
        self.assertEqual(val, 10)

    @mock.patch("sys.argv", ["prog.py"])
    def test_parse_args(self):
        """Test parse_args with various user inputs."""
        # test with default arguments, expect DEFAULT_{WARN,CRIT}_{ERROR,ABANDONED}
        args = check_systemd_scopes.parse_args()
        self.assertEqual(
            args,
            Namespace(
                warn_error=check_systemd_scopes.DEFAULT_WARN_ERROR,
                crit_error=check_systemd_scopes.DEFAULT_CRIT_ERROR,
                warn_abandoned=check_systemd_scopes.DEFAULT_WARN_ABANDONED,
                crit_abandoned=check_systemd_scopes.DEFAULT_CRIT_ABANDONED,
                ok_message="Nominal",
            ),
        )

        # test with supplied arguments, expect appropriate translation
        args = check_systemd_scopes.parse_args(
            [
                "-e",
                "345",
                "-E",
                "678",
                "-a",
                "543",
                "-A",
                "876",
                "-o",
                "Everything is fabulous",
            ]
        )
        self.assertEqual(
            args,
            Namespace(
                warn_error=345,
                crit_error=678,
                warn_abandoned=543,
                crit_abandoned=876,
                ok_message="Everything is fabulous",
            ),
        )
