"""Zaza functional tests."""
import logging
import unittest

import yaml

import zaza.model as model
from zaza.utilities import juju as juju_utils


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

        check_mysql_content = (
            "command[check_mysql]=/usr/local/lib/nagios/plugins/check_systemd.py mysql"
        )
        machine = list(juju_utils.get_machines_for_application("mysql"))[0]
        machine_series = juju_utils.get_machine_series(machine)

        if machine_series == "trusty":
            check_mysql_content = (
                "command[check_mysql]=/usr/lib/nagios/plugins/check_mysql -u nagios"
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
            "check_mysql.cfg": check_mysql_content,
            "check_mysql_proc.cfg": "command[check_mysql_proc]=/usr/lib/nagios/plugins/"
            "check_procs -c 1:1 -C mysqld",
            "check_swap_activity.cfg":
                "command[check_swap_activity]="
                "/usr/local/lib/nagios/plugins/check_swap_activity",
            "check_swap.cfg": "command[check_swap]=/usr/lib/nagios/plugins/check_swap",
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
        netlinks = "- eth0 mtu:9000 speed:10000"
        model.set_application_config(self.application_name, {"netlinks": netlinks})
        model.block_until_all_units_idle()
        cmd = "cat /etc/nagios/nrpe.d/check_netlinks_eth0.cfg"
        line = (
            "command[check_netlinks_eth0]=/usr/local/lib/nagios/plugins/"
            "check_netlinks.py -i eth0 -m 9000 -s 1000"
        )
        result = model.run_on_unit(self.lead_unit_name, cmd)
        code = result.get("Code")
        if code != "0":
            logging.warning(
                "Unable to find nrpe check at "
                "/etc/nagios/nrpe.d/check_netlinks_eth0.cfg"
            )
            raise model.CommandRunFailed(cmd, result)
        content = result.get("Stdout")
        self.assertTrue(line in content)
