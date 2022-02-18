"""Unit tests for scripts in files/plugins."""
import subprocess
import unittest
from datetime import datetime, timedelta
from os.path import abspath, dirname, join

DIR_REPO_ROOT = dirname(dirname(dirname(abspath(__file__))))
DIR_PLUGINS = join(DIR_REPO_ROOT, "files", "plugins")
UPTIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def get_cmd_output(cmd):
    """Get shell command output in unicode string without checking retcode."""
    proc = subprocess.run(
        cmd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return proc.stdout.decode("utf8").strip()


def get_script_path(filename="check_reboot.py"):
    """Get script full path under files/plugins dir."""
    return join(DIR_PLUGINS, filename)


class TestCheckRebootScript(unittest.TestCase):
    """Test plugin scripts in files/plugins."""

    check_reboot = get_script_path(filename="check_reboot.py")

    def test_old_reboot_time(self):
        """Test old known reboot time will trigger CRITICAL alert."""
        # check a old reboot time, should raise critical
        out = get_cmd_output([self.check_reboot, "2000-01-01 00:00:00"])
        self.assertTrue(out.startswith("CRITICAL"))

    def test_current_reboot_time(self):
        """Test current reboot time will not trigger alert."""
        # check current reboot time, should be ok
        uptime = get_cmd_output(["uptime", "--since"])
        out = get_cmd_output([self.check_reboot, uptime])
        self.assertTrue(out.startswith("OK"))

    def test_future_reboot_time(self):
        """Test future reboot time will not trigger alert."""
        # check future time, should also be ok
        out = get_cmd_output([self.check_reboot, "2100-01-01 00:00:00"])
        self.assertTrue(out.startswith("OK"))

    def test_small_reboot_time_gap_is_allowed(self):
        """Test no fake alert when uptime --since output is flapping a bit.

        `uptime --since` output may be flapping because ntp could keep changing
        system time. We allow 5s gap.
        """
        current_uptime_str = get_cmd_output(["uptime", "--since"])
        current_uptime = datetime.strptime(current_uptime_str, UPTIME_FORMAT)

        # we allow 5s gap, this should not trigger
        known_reboot_time = current_uptime - timedelta(seconds=5)
        known_reboot_time_str = known_reboot_time.strftime(UPTIME_FORMAT)
        out = get_cmd_output([self.check_reboot, known_reboot_time_str])
        self.assertTrue(out.startswith("OK"))

    def test_bigger_reboot_time_gap_is_not_allowed(self):
        """Test fake alert should be triggered when uptime gap is 6s."""
        current_uptime_str = get_cmd_output(["uptime", "--since"])
        current_uptime = datetime.strptime(current_uptime_str, UPTIME_FORMAT)

        # we only allow 5s gap, 6s should trigger the alert
        known_reboot_time = current_uptime - timedelta(seconds=6)
        known_reboot_time_str = known_reboot_time.strftime(UPTIME_FORMAT)
        out = get_cmd_output([self.check_reboot, known_reboot_time_str])
        self.assertTrue(out.startswith("CRITICAL"))
