"""Zaza functional tests."""

import logging
import pprint
import unittest

import tenacity

import yaml
import zaza.model as model  # noqa I201

RETRY = tenacity.retry(
    wait=tenacity.wait_fixed(5),
    stop=tenacity.stop_after_attempt(5),
)


class TestBase(unittest.TestCase):
    """Base Class for charm functional tests."""

    @classmethod
    def setUpClass(cls):
        """Run setup for tests."""
        cls.model_name = model.get_juju_model()
        cls.application_name = "nrpe"
        cls.lead_unit_name = model.get_lead_unit_name(
            cls.application_name, model_name=cls.model_name
        )
        cls.units = model.get_units(cls.application_name, model_name=cls.model_name)
        cls.nrpe_ip = model.get_app_ips(cls.application_name)[0]


class TestNrpe(TestBase):
    """Class for charm functional tests."""

    @RETRY
    def test_01_nrpe_check(self):
        """Verify nrpe check exists."""
        logging.debug(
            "Verify the nrpe checks are created and have the required content..."
        )

        nrpe_checks = {
            "check_conntrack.cfg": "command[check_conntrack]="
            "/usr/local/lib/nagios/plugins/check_conntrack.sh",
            "check_space_root.cfg": "command[check_space_root]="
            "/usr/lib/nagios/plugins/check_disk",
            "check_load.cfg": "command[check_load]=/usr/lib/nagios/plugins/check_load",
            "check_mem.cfg": "command[check_mem]="
            "/usr/local/lib/nagios/plugins/check_mem.pl",
            "check_rabbitmq.cfg": "command[check_rabbitmq]="
            "/usr/local/lib/nagios/plugins/check_rabbitmq.py",
            "check_swap_activity.cfg": "command[check_swap_activity]="
            "/usr/local/lib/nagios/plugins/check_swap_activity",
        }

        for nrpe_check in nrpe_checks:
            logging.info("Checking content of '{}' nrpe check".format(nrpe_check))
            cmd = "cat /etc/nagios/nrpe.d/" + nrpe_check
            result = model.run_on_unit(self.lead_unit_name, cmd)
            code = result.get("Code")

            if code != "0":
                logging.warning(
                    "Unable to find nrpe check {} at /etc/nagios/nrpe.d/".format(
                        nrpe_check
                    )
                )

                raise model.CommandRunFailed(cmd, result)
            content = result.get("Stdout")
            self.assertTrue(nrpe_checks[nrpe_check] in content)

    @RETRY
    def test_02_enable_swap(self):
        """Check swap checks are applied."""
        swap = "-w 40% -c 25%"
        model.set_application_config(self.application_name, {"swap": swap})
        model.block_until_all_units_idle()
        cmd = "cat /etc/nagios/nrpe.d/check_swap.cfg"
        result = model.run_on_unit(self.lead_unit_name, cmd)
        code = result.get("Code")

        if code != "0":
            logging.warning(
                "Unable to find nrpe check check_swap.cfg at /etc/nagios/nrpe.d/"
            )
            raise model.CommandRunFailed(cmd, result)
        content = result.get("Stdout")
        self.assertTrue(swap in content)

    @RETRY
    def test_02_remove_check(self):
        """Verify swap check is removed."""
        model.set_application_config(self.application_name, {"swap": ""})
        model.block_until_all_units_idle()
        cmd = "cat /etc/nagios/nrpe.d/check_swap.cfg"
        result = model.run_on_unit(self.lead_unit_name, cmd)
        self.assertTrue(result.get("Code") != 0)

    @RETRY
    def test_03_user_monitor(self):
        """Verify user monitors are applied."""
        user_monitors = {
            "version": "0.3",
            "monitors": {
                "local": {
                    "procrunning": {
                        "rsync": {
                            "max": 1,
                            "executable": "rsync",
                            "name": "RSYNc Running",
                            "min": 1,
                        },
                        "jujud": {
                            "max": 1,
                            "executable": "jujud",
                            "name": "Juju Running",
                            "min": 1,
                        },
                    }
                },
                "remote": {
                    "tcp": {
                        "ssh": {
                            "warning": 2,
                            "critical": 10,
                            "name": "SSH Running",
                            "timeout": 12,
                            "port": 22,
                            "string": "SSH.*",
                            "expect": None,
                        }
                    }
                },
            },
        }
        model.set_application_config(
            self.application_name, {"monitors": yaml.dump(user_monitors)}
        )
        model.block_until_all_units_idle()

        local_nrpe_checks = {
            "check_proc_jujud_user.cfg": "command[check_proc_jujud_user]="
            "/usr/lib/nagios/plugins/"
            "check_procs -w 1 -c 1 -C jujud",
            "check_proc_rsync_user.cfg": "command[check_proc_rsync_user]="
            "/usr/lib/nagios/plugins/"
            "check_procs -w 1 -c 1 -C rsync",
        }

        for nrpe_check in local_nrpe_checks:
            logging.info("Checking content of '{}' nrpe check".format(nrpe_check))
            cmd = "cat /etc/nagios/nrpe.d/" + nrpe_check
            result = model.run_on_unit(self.lead_unit_name, cmd)
            code = result.get("Code")

            if code != "0":
                logging.warning(
                    "Unable to find nrpe check {} at /etc/nagios/nrpe.d/".format(
                        nrpe_check
                    )
                )
                raise model.CommandRunFailed(cmd, result)
            content = result.get("Stdout")
            self.assertTrue(local_nrpe_checks[nrpe_check] in content)

        remote_nrpe_checks = {
            "check_tcp_H_HOSTADDRESS__E_p22_s_SSH____eNone_w2_c10_t12_t10.cfg": "/usr/"
            "lib/nagios/plugins/check_tcp -H $HOSTADDRESS$ "
            "-E -p 22 -s 'SSH.*' -e None -w 2 -c 10 -t 12 -t 10"
        }

        for nrpe_check in remote_nrpe_checks:
            logging.info(
                "Checking content of '{}' nrpe command in nagios unit".format(
                    nrpe_check
                )
            )
            cmd = "cat /etc/nagios3/conf.d/commands/" + nrpe_check
            nagios_lead_unit_name = model.get_lead_unit_name(
                "nagios", model_name=self.model_name
            )
            result = model.run_on_unit(nagios_lead_unit_name, cmd)
            code = result.get("Code")

            if code != "0":
                logging.warning(
                    "Unable to find nrpe command {} at "
                    "/etc/nagios3/conf.d/commands/ in nagios unit".format(nrpe_check)
                )
                raise model.CommandRunFailed(cmd, result)
            content = result.get("Stdout")
            self.assertTrue(remote_nrpe_checks[nrpe_check] in content)

    @RETRY
    def test_04_check_nagios_ip_is_allowed(self):
        """Verify nagios ip is allowed in nrpe.cfg."""
        nagios_ip = model.get_app_ips("nagios")[0]
        line = "allowed_hosts=127.0.0.1,{}/32".format(nagios_ip)
        cmd = "cat /etc/nagios/nrpe.cfg"
        result = model.run_on_unit(self.lead_unit_name, cmd)
        code = result.get("Code")

        if code != "0":
            logging.warning("Unable to find nrpe config file at /etc/nagios/nrpe.cfg")
            raise model.CommandRunFailed(cmd, result)
        content = result.get("Stdout")
        self.assertTrue(line in content)

    @RETRY
    def test_05_netlinks(self):
        """Check netlinks checks are applied."""
        netlinks = "- ens3 mtu:9000 speed:10000"
        model.set_application_config(self.application_name, {"netlinks": netlinks})
        model.block_until_all_units_idle()
        cmd = "cat /etc/nagios/nrpe.d/check_netlinks_ens3.cfg"
        line = (
            "command[check_netlinks_ens3]=/usr/local/lib/nagios/plugins/"
            "check_netlinks.py -i ens3 -m 9000 -s 1000"
        )
        result = model.run_on_unit(self.lead_unit_name, cmd)
        code = result.get("Code")

        if code != "0":
            logging.warning(
                "Unable to find nrpe check at "
                "/etc/nagios/nrpe.d/check_netlinks_ens3.cfg"
            )
            raise model.CommandRunFailed(cmd, result)
        content = result.get("Stdout")
        self.assertTrue(line in content)

    @RETRY
    def test_06_container_checks(self):
        """Check that certain checks are enabled on hosts but disabled on containers."""
        # Enable appropriate config to enable various checks for testing whether they
        # get created on containers versus hosts.
        model.set_application_config(
            self.application_name,
            {
                "disk_root": "-u GB -w 25% -c 20% -K 5%",
                "zombies": "-w 3 -c 6 -s Z",
                "procs": "-k -w 250 -c 300",
                "load": "auto",
                "conntrack": "-w 80 -c 90",
                "users": "-w 20 -c 25",
                "swap": "-w 40% -c 25%",
                "swap_activity": "-i 5 -w 10240 -c 40960",
                "mem": "-C -h -u -w 85 -c 90",
                "lacp_bonds": "lo",  # Enable a bogus lacp check on the loopback iface
                "netlinks": "- ens3 mtu:9000 speed:10000",
                "xfs_errors": "5",
            },
        )
        model.block_until_all_units_idle()

        host_checks = self._get_unit_check_files("rabbitmq-server/0")
        container_checks = self._get_unit_check_files("container/0")
        expected_shared_checks = set(
            [
                "check_conntrack.cfg",  # this should be host-only
                "check_total_procs.cfg",
                "check_users.cfg",
                "check_zombie_procs.cfg",  # This also feels host-only
            ]
        )
        expected_host_only_checks = set(
            [
                "check_arp_cache.cfg",
                "check_space_root.cfg",
                "check_lacp_lo.cfg",
                "check_load.cfg",
                "check_mem.cfg",
                "check_netlinks_ens3.cfg",
                "check_ro_filesystem.cfg",
                "check_swap.cfg",
                "check_swap_activity.cfg",
                "check_xfs_errors.cfg",
            ]
        )
        self.assertTrue(
            expected_shared_checks.issubset(host_checks),
            self._get_set_comparison(expected_shared_checks, host_checks),
        )
        self.assertTrue(
            expected_shared_checks.issubset(container_checks),
            self._get_set_comparison(expected_shared_checks, container_checks),
        )
        self.assertTrue(
            expected_host_only_checks.issubset(host_checks),
            self._get_set_comparison(expected_host_only_checks, host_checks),
        )
        self.assertTrue(
            expected_host_only_checks.isdisjoint(container_checks),
            self._get_set_comparison(expected_host_only_checks, container_checks),
        )

    @RETRY
    def test_07_cronjob_checks(self):
        """Check that cron job is installed and check enabled."""
        model.set_application_config(
            self.application_name,
            {
                "cis_audit_enabled": "True",
            },
        )
        model.block_until_all_units_idle()
        host_checks = self._get_unit_check_files("rabbitmq-server/0")
        expected_shared_checks = set(["check_cis_audit.cfg"])
        self.assertTrue(
            expected_shared_checks.issubset(host_checks),
            self._get_set_comparison(expected_shared_checks, host_checks),
        )

        cronjobs = self._get_cronjob_files("rabbitmq-server/0")
        expected_cronjobs = set(["cis-audit"])
        self.assertTrue(
            expected_cronjobs.issubset(cronjobs),
            self._get_set_comparison(expected_cronjobs, cronjobs),
        )

    @RETRY
    def test_08_plugins_copied(self):
        """Check that NRPE plugins are copied."""
        plugin_dir = "/usr/local/lib/nagios/plugins"
        plugin_files = [
            "check_arp_cache.py",
            "check_cis_audit.py",
            "check_exit_status.pl",
            "check_netlinks.py",
            "check_status_file.py",
            "check_upstart_job",
            "check_netns.sh",
            "check_swap_activity",
            "check_xfs_errors.py",
            "check_conntrack.sh",
            "check_lacp_bond.py",
            "check_reboot.py",
            "check_systemd.py",
            "cron_cis_audit.py",
            "check_cpu_governor.py",
            "check_mem.pl",
            "check_ro_filesystem.py",
            "check_systemd_scopes.py",
            "nagios_plugin3.py",
        ]
        for filename in plugin_files:
            logging.info("Checking that {} was copied into place.".format(filename))
            cmd = "ls {}/{}".format(plugin_dir, filename)
            # run this on the lead unit only
            result = model.run_on_unit(self.lead_unit_name, cmd)
            code = result.get("Code")
            self.assertEqual(code, "0")

    def _get_unit_check_files(self, unit):
        cmdline = "ls /etc/nagios/nrpe.d/"
        result = model.run_on_unit(unit, cmdline)
        self.assertEqual(result["Code"], "0")

        return set(result["Stdout"].splitlines())

    def _get_set_comparison(self, expected_checks, actual_checks):
        return pprint.pformat(
            {
                "Expected:": expected_checks,
                "Actual:": actual_checks,
            }
        )

    def _get_cronjob_files(self, unit):
        cmdline = "ls /etc/cron.d/"
        result = model.run_on_unit(unit, cmdline)
        self.assertEqual(result["Code"], "0")
        return set(result["Stdout"].splitlines())


class TestNrpeActions(TestBase):
    """Class for charm actions."""

    @RETRY
    def test_01_ack_reboot(self):
        """Test the ack-reboot action."""
        uptime = (
            model.run_on_leader(self.application_name, "uptime --since")
            .get("Stdout")
            .strip()
        )
        action = model.run_action_on_leader(self.application_name, "ack-reboot")
        message = action.data["results"].get("message")
        self.assertIsNotNone(message)
        self.assertEqual(message, "known reboot time updated to {}".format(uptime))
