"""Zaza functional tests."""
import logging
import pprint
import unittest

import yaml

import zaza.model as model


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

    def test_01_nrpe_check(self):
        """Verify nrpe check exists."""
        logging.debug(
            "Verify the nrpe checks are created and have the required content..."
        )

        nrpe_checks = {
            "check_conntrack.cfg":
                "command[check_conntrack]=/usr/local/lib/nagios/plugins/"
                "check_conntrack.sh",
            "check_disk_root.cfg":
                "command[check_disk_root]=/usr/lib/nagios/plugins/check_disk",
            "check_load.cfg": "command[check_load]=/usr/lib/nagios/plugins/check_load",
            "check_mem.cfg":
                "command[check_mem]=/usr/local/lib/nagios/plugins/check_mem.pl",
            "check_rabbitmq.cfg":
                "command[check_rabbitmq]="
                "/usr/local/lib/nagios/plugins/check_rabbitmq.py",
            "check_swap_activity.cfg":
                "command[check_swap_activity]="
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

    def test_02_remove_check(self):
        """Verify swap check is removed."""
        model.set_application_config(self.application_name, {"swap": ""})
        model.block_until_all_units_idle()
        cmd = "cat /etc/nagios/nrpe.d/check_swap.cfg"
        result = model.run_on_unit(self.lead_unit_name, cmd)
        self.assertTrue(result.get("Code") != 0)

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
            "check_proc_jujud_user.cfg":
                "command[check_proc_jujud_user]=/usr/lib/nagios/plugins/"
                "check_procs -w 1 -c 1 -C jujud",
            "check_proc_rsync_user.cfg":
                "command[check_proc_rsync_user]=/usr/lib/nagios/plugins/"
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
            "check_tcp_H_HOSTADDRESS__E_p22_s_SSH____eNone_w2_c10_t12_t10.cfg":
                "/usr/lib/nagios/plugins/check_tcp -H $HOSTADDRESS$ "
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

    def test_06_container_checks(self):
        """Check that certain checks are enabled on hosts but disabled on containers."""
        # Enable appropriate config to enable various checks for testing whether they
        # get created on containers versus hosts.
        model.set_application_config(self.application_name, {
            "disk_root": "-u GB -w 25% -c 20% -K 5%",
            "zombies": "-w 3 -c 6 -s Z",
            "procs": "-k -w 250 -c 300",
            "load": "auto",
            "conntrack": "-w 80 -c 90",
            "users": "-w 20 -c 25",
            "swap": "-w 40% -c 25%",
            "swap_activity": "-i 5 -w 10240 -c 40960",
            "mem": "-C -h -u -w 85 -c 90",
            "lacp_bonds": "lo",  # Enable a bogus lacp check on the loopback interface
            "netlinks": "- ens3 mtu:9000 speed:10000",  # Copied from test_05_netlinks
            "xfs_errors": "5",
        })
        model.block_until_all_units_idle()

        host_checks = self._get_unit_check_files("rabbitmq-server/0")
        container_checks = self._get_unit_check_files("container/0")
        expected_shared_checks = set([
            "check_conntrack.cfg",  # I think this should be host-only, but am not sure.
            "check_total_procs.cfg",
            "check_users.cfg",
            "check_zombie_procs.cfg",  # This also feels host-only to me; thoughts?
        ])
        expected_host_only_checks = set([
            "check_arp_cache.cfg",
            "check_disk_root.cfg",
            "check_lacp_lo.cfg",
            "check_load.cfg",
            "check_mem.cfg",
            "check_netlinks_ens3.cfg",
            "check_ro_filesystem.cfg",
            "check_swap.cfg",
            "check_swap_activity.cfg",
            "check_xfs_errors.cfg",
        ])
        self.assertTrue(expected_shared_checks.issubset(host_checks),
                        pprint.pformat({
                            'Expected:': expected_shared_checks,
                            'Actual:': host_checks,
                        }))
        self.assertTrue(expected_shared_checks.issubset(container_checks),
                        pprint.pformat({
                            'Expected:': expected_shared_checks,
                            'Actual:': container_checks,
                        }))
        self.assertTrue(expected_host_only_checks.issubset(host_checks),
                        pprint.pformat({
                            'Expected:': expected_host_only_checks,
                            'Actual:': host_checks,
                        }))
        self.assertTrue(expected_host_only_checks.isdisjoint(container_checks),
                        pprint.pformat({
                            'Expected:': expected_host_only_checks,
                            'Actual:': container_checks,
                        }))

    def _get_unit_check_files(self, unit):
        cmdline = "ls /etc/nagios/nrpe.d/"
        result = model.run_on_unit(unit, cmdline)
        self.assertEqual(result["Code"], "0")
        return set(result["Stdout"].splitlines())
