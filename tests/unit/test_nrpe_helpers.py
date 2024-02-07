"""Unit tests for hooks/nrpe_helpers.py module."""

import os
import unittest
from unittest import mock

import netifaces

import nrpe_helpers
from nrpe_helpers import match_cidr_to_ifaces

import yaml


class TestMatchCidrToIfaces(unittest.TestCase):
    """Test match_cidr_to_ifaces helper function."""

    mock_iface_ip_data = {
        "lo": "127.0.0.1",
        "eno1": "10.0.0.0",
        "eno2": "10.1.0.0",
        "fan-252": "252.0.0.1",
    }

    def test_single_dev_match(self):
        """Test single interface match."""
        self._run_mocked_test("10.0.0.0/16", ["eno1"])

    def test_multi_dev_match(self):
        """Test multiple interface match."""
        self._run_mocked_test("10.0.0.0/8", ["eno1", "eno2"])

    def test_no_dev_match(self):
        """Test no interface match."""
        self._run_mocked_test("192.168.0.0/16", [])

    def test_cidr_with_host_bits_set(self):
        """Test invalid CIDR input (e.g. "eno1")."""
        with self.assertRaises(Exception):
            match_cidr_to_ifaces("10.1.2.3/8")  # Should be 10.0.0.0/8

    def test_iface_passed_in_as_cidr(self):
        """Test invalid CIDR input (e.g. "eno1")."""
        with self.assertRaises(Exception):
            match_cidr_to_ifaces("eno1")

    @mock.patch("netifaces.ifaddresses")
    @mock.patch("netifaces.interfaces")
    def _run_mocked_test(self, cidr, matches, ifaces_mock, addrs_mock):
        iface_ip_tuples = list(self.mock_iface_ip_data.items())
        ifaces_mock.return_value = [t[0] for t in iface_ip_tuples]
        addrs_mock.side_effect = [
            {netifaces.AF_INET: [{"addr": t[1]}]} for t in iface_ip_tuples
        ]
        self.assertEqual(match_cidr_to_ifaces(cidr), matches)


class TestIngressAddress(unittest.TestCase):
    """Test functions to provide a suitable ingress address."""

    @mock.patch("nrpe_helpers.hookenv.config")
    @mock.patch("nrpe_helpers.hookenv.network_get")
    def test_get_bind_address(self, mock_network_get, mock_config):
        """Prove we get a local IP address for interface binding."""
        mock_config.return_value = "private"
        mock_network_get.return_value = {
            "bind-addresses": [
                {
                    "mac-address": "06:f1:3a:74:ad:fe",
                    "interface-name": "ens5",
                    "addresses": [
                        {
                            "hostname": "",
                            "address": "172.31.29.247",
                            "cidr": "172.31.16.0/20",
                        }
                    ],
                    "macaddress": "06:f1:3a:74:ad:fe",
                    "interfacename": "ens5",
                }
            ],
            "egress-subnets": ["3.8.134.119/32"],
            "ingress-addresses": ["3.8.134.119"],
        }
        self.assertEqual(
            nrpe_helpers.get_ingress_address("mockbinding"), "172.31.29.247"
        )

    @mock.patch("nrpe_helpers.hookenv.config")
    @mock.patch("nrpe_helpers.hookenv.network_get")
    def test_get_private_address(self, mock_network_get, mock_config):
        """Prove we get a local IP address for Nagios relation."""
        mock_config.return_value = "private"
        mock_network_get.return_value = {
            "bind-addresses": [
                {
                    "mac-address": "06:f1:3a:74:ad:fe",
                    "interface-name": "ens5",
                    "addresses": [
                        {
                            "hostname": "",
                            "address": "172.31.29.247",
                            "cidr": "172.31.16.0/20",
                        }
                    ],
                    "macaddress": "06:f1:3a:74:ad:fe",
                    "interfacename": "ens5",
                }
            ],
            "egress-subnets": ["3.8.134.119/32"],
            "ingress-addresses": ["3.8.134.119"],
        }
        self.assertEqual(
            nrpe_helpers.get_ingress_address("mockbinding", external=True),
            "172.31.29.247",
        )

    @mock.patch("nrpe_helpers.hookenv.config")
    @mock.patch("nrpe_helpers.hookenv.unit_get")
    def test_get_public_address(self, mock_unit_get, mock_config):
        """Prove we get a public IP address for Nagios relation."""
        mock_config.return_value = "public"
        mock_unit_get.return_value = "1.2.3.4"
        self.assertEqual(
            nrpe_helpers.get_ingress_address("mockbinding", external=True), "1.2.3.4"
        )


class TestCheckReboot(unittest.TestCase):
    """Test check_reboot related code."""

    def test_set_and_get_known_reboot_time(self):
        """Test set/get known reboot time."""
        t0 = nrpe_helpers.get_cmd_output(["uptime", "--since"])
        t1 = nrpe_helpers.set_known_reboot_time()
        t2 = nrpe_helpers.get_known_reboot_time()
        self.assertEqual(t0, t1)
        self.assertEqual(t0, t2)

    def test_unset_known_reboot_time(self):
        """Test unset known reboot time will clear the data."""
        t0 = nrpe_helpers.set_known_reboot_time()
        self.assertIsNotNone(t0)
        t2 = nrpe_helpers.unset_known_reboot_time()
        self.assertIsNone(t2)

    def test_get_check_reboot_context_add(self):
        """Test get_check_reboot_context will render time correctly."""
        t0 = nrpe_helpers.get_cmd_output(["uptime", "--since"])
        context = nrpe_helpers.get_check_reboot_context(known_reboot_time=t0)
        self.assertEquals(context["cmd_params"], '"{}"'.format(t0))

    def test_get_check_reboot_context_remove(self):
        """Test get_check_reboot_context will render None correctly."""
        context = nrpe_helpers.get_check_reboot_context(known_reboot_time=None)
        self.assertFalse(context["cmd_params"])


class TestDiskSpaceCheck(unittest.TestCase):
    """Test space_check related code."""

    def test_valid_partition(self):
        """Test a valid partition."""
        device_root = {
            "name": "nvme0n1p4",
            "maj:min": "259:4",
            "rm": False,
            "size": "100G",
            "ro": False,
            "type": "part",
            "mountpoint": "/",
        }
        result = nrpe_helpers.is_valid_partition(device_root)
        self.assertEqual(result, True)

    def test_invalid_partition(self):
        """Test an invalid partitions."""
        invalid_partitions = {"loop", "tmpfs", "devtmpfs", "squashfs"}
        for partition in invalid_partitions:
            device = {
                "name": "loop0",
                "maj:min": "7:0",
                "rm": False,
                "size": "15M",
                "ro": True,
                "type": partition,
                "mountpoint": "/snap/something",
            }
            result = nrpe_helpers.is_valid_partition(device)
            self.assertEqual(result, False)

    lsblk_output = b"""{
        "blockdevices": [
            {
                "name": "loop2",
                "maj:min": "7:2",
                "rm": false,
                "size": "113,7M",
                "ro": true,
                "type": "loop",
                "mountpoint": "/snap/charm/602"
            },
            {
                "name": "nvme0n1",
                "maj:min": "259:0",
                "rm": false,
                "size": "477G",
                "ro": false,
                "type": "disk",
                "mountpoint": null,
                "children": [
                    {
                        "name": "nvme0n1p1",
                        "maj:min": "259:1",
                        "rm": false,
                        "size": "260M",
                        "ro": false,
                        "type": "part",
                        "mountpoint": "/boot/efi"
                    },
                    {
                        "name": "nvme0n1p2",
                        "maj:min": "259:4",
                        "rm": false,
                        "size": "100G",
                        "ro": false,
                        "type": "part",
                        "mountpoint": "/"
                    },
                    {
                        "name": "nvme0n1p3",
                        "maj:min": "259:5",
                        "rm": false,
                        "size": "4G",
                        "ro": false,
                        "type": "part",
                        "mountpoint": "[SWAP]"
                    },
                    {
                        "name": "nvme0n1p4",
                        "maj:min": "259:6",
                        "rm": false,
                        "size": "1000M",
                        "ro": false,
                        "type": "part",
                        "mountpoint": "/srv/instances"
                    },
                    {
                        "name": "nvme0n1p5",
                        "maj:min": "259:6",
                        "rm": false,
                        "size": "500G",
                        "ro": false,
                        "type": "part",
                        "mountpoints": [
                            null
                        ],
                        "children": [
                            {
                                "name": "vg0-var--log--audit",
                                "maj:min": "253:1",
                                "rm": "0",
                                "size": "51.2G",
                                "ro": "0",
                                "type": "lvm",
                                "mountpoint": "/var/log/audit"
                            },
                            {
                                "name": "vg0-var--log",
                                "maj:min": "253:3",
                                "rm": "0",
                                "size": "93.1G",
                                "ro": "0",
                                "type": "lvm",
                                "mountpoint": "/var/log"
                            }
                        ]
                    }
                ]
            },
            {
                "name":"vdb",
                "maj:min":"252:16",
                "rm":false,
                "size":"1G",
                "ro":false,
                "type":"disk",
                "mountpoints": [
                    "/var/lib/kubelet/pods/../k..s.io~csi/pvc../mount"
                ]
            }
        ]
    }"""

    @mock.patch("subprocess.check_output", return_value=lsblk_output)
    def test_get_partitions_to_check(self, lock_lsblk_output):
        """Test the list of partitions to check."""
        partitions = nrpe_helpers.get_partitions_to_check()
        # mp here denotes the 'mountpoint' for microk8s
        mp = "/var/snap/microk8s/common/var/lib/kubelet/pods/../k..s.io~csi/pvc../mount"
        params = [
            ("/snap/charm/602", False),
            ("/boot/efi", False),
            ("/", True),
            ("SWAP", False),
            ("/srv/instances", True),
            ("/var/log/audit", True),
            ("/var/log", True),
            ("/var/lib/kubelet/pods/../k..s.io~csi/pvc../mount", False),
            (mp, False),
        ]
        for partition, expected in params:
            with self.subTest(
                msg="Validate partition filtering", p1=partition, p2=expected
            ):
                if expected:
                    self.assertIn(partition, partitions)
                else:
                    self.assertNotIn(partition, partitions)


def load_default_config():
    """Load the default config values from the charm config.yaml.

    Returns a dict of {config:default}
    """
    with open(os.path.join(os.getcwd(), "config.yaml"), "r") as f:
        config_raw = yaml.safe_load(f)
    return {key: value["default"] for key, value in config_raw["options"].items()}


class TestSubordinateCheckDefinitions(unittest.TestCase):
    """Test SubordinateCheckDefinitions() related code."""

    def glob_valid_cpufreq_path(self, arg):
        """Return a valid list of cpufreq sysfs paths.

        This function is meant to be used as a side_effect when
        mocking glob.glob(), to provide a more controlled unit
        testing environment.
        """
        ret = []
        if arg == "/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor":
            ret = ["/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"]
        return ret

    @mock.patch("nrpe_helpers.glob.glob")
    @mock.patch("nrpe_helpers.hookenv._metadata_unit")
    @mock.patch("nrpe_helpers.hookenv.principal_unit")
    @mock.patch("nrpe_helpers.hookenv.config")
    def test_cpu_governor_default_enabled_for_principle_charms(
        self, mock_config, mock_principal_unit, mock__metadata_unit, mock_glob
    ):
        """Test cpu_governor check is enabled by default for principle charms.

        A cpu scaling governor value of 'performance' is expected
        by default for the charms nova-compute, kubernetes-worker,
        rabbitmq-server, percona-cluster even if the charm config
        is unset
        """
        config = load_default_config()
        mock_config.side_effect = lambda key: config[key]
        mock_glob.side_effect = self.glob_valid_cpufreq_path

        principal_charms = [
            "nova-compute",
            "rabbitmq-server",
            "kubernetes-worker",
            "percona-cluster",
        ]
        for charm in principal_charms:
            mock_principal_unit.return_value = charm + "/0"
            mock__metadata_unit.return_value = {"name": charm}

            check = {
                "description": "Check CPU governor scaler (sub)",
                "cmd_name": "check_cpu_governor",
                "cmd_exec": "/usr/local/lib/nagios/plugins/check_cpu_governor.py",
                "cmd_params": "--governor performance",
                "matching_files": [],
            }
            checks = nrpe_helpers.SubordinateCheckDefinitions()["checks"]
            self.assertIn(check, checks)

            mock_principal_unit.reset_mock(return_value=True)
            mock__metadata_unit.reset_mock(return_value=True)

    @mock.patch("nrpe_helpers.glob.glob")
    @mock.patch("nrpe_helpers.hookenv._metadata_unit")
    @mock.patch("nrpe_helpers.hookenv.principal_unit")
    @mock.patch("nrpe_helpers.hookenv.config")
    def test_cpu_governor_disabled_default_for_non_principle_charms(
        self, mock_config, mock_principal_unit, mock__metadata_unit, mock_glob
    ):
        """Test cpu_governor check is disabled by default for non principle charms.

        A cpu scaling governor value check should be disabled by default
        by most charms.
        """
        config = load_default_config()
        mock_config.side_effect = lambda key: config[key]
        mock_glob.side_effect = self.glob_valid_cpufreq_path
        mock_principal_unit.return_value = "mongodb/0"
        mock__metadata_unit.return_value = {"name": "mongodb"}

        checks = nrpe_helpers.SubordinateCheckDefinitions()["checks"]
        check_in_list = False
        for check in checks:
            if check["cmd_name"].startswith("check_cpu_governor"):
                check_in_list = True
                break
        self.assertFalse(check_in_list)

    @mock.patch("nrpe_helpers.glob.glob")
    @mock.patch("nrpe_helpers.hookenv._metadata_unit")
    @mock.patch("nrpe_helpers.hookenv.principal_unit")
    @mock.patch("nrpe_helpers.hookenv.config")
    def test_cpu_governor_config_overrides_default(
        self, mock_config, mock_principal_unit, mock__metadata_unit, mock_glob
    ):
        """Test cpu_governor default value overriden by config.

        The value coming from the configuration should take precedence
        in case it is set for principle charms.
        """
        config = load_default_config()
        config["cpu_governor"] = "ondemand"
        mock_config.side_effect = lambda key: config[key]
        mock_glob.side_effect = self.glob_valid_cpufreq_path
        mock_principal_unit.return_value = "nova-compute/0"
        mock__metadata_unit.return_value = {"name": "nova-compute"}

        check = {
            "description": "Check CPU governor scaler (sub)",
            "cmd_name": "check_cpu_governor",
            "cmd_exec": "/usr/local/lib/nagios/plugins/check_cpu_governor.py",
            "cmd_params": "--governor ondemand",
            "matching_files": [],
        }
        checks = nrpe_helpers.SubordinateCheckDefinitions()["checks"]
        self.assertIn(check, checks)

    @mock.patch("nrpe_helpers.glob.glob")
    @mock.patch("nrpe_helpers.hookenv._metadata_unit")
    @mock.patch("nrpe_helpers.hookenv.principal_unit")
    @mock.patch("nrpe_helpers.hookenv.config")
    def test_cpu_governor_check_disabled_in_vm(
        self, mock_config, mock_principal_unit, mock__metadata_unit, mock_glob
    ):
        """Test cpu_governor check is disabled for virtual environments.

        When running in VM, this check should be disabled even if it is
        set through the config.
        """
        config = load_default_config()
        config["cpu_governor"] = "performance"
        mock_config.side_effect = lambda key: config[key]
        mock_glob.side_effect = lambda arg: []  # cpufreq paths no exist in VM
        mock_principal_unit.return_value = "nova-compute/0"
        mock__metadata_unit.return_value = {"name": "nova-compute"}

        check_in_list = False
        checks = nrpe_helpers.SubordinateCheckDefinitions()["checks"]
        for check in checks:
            if check["cmd_name"].startswith("check_cpu_governor"):
                check_in_list = True
                break
        self.assertFalse(check_in_list)

    @mock.patch("nrpe_helpers.glob.glob")
    @mock.patch("nrpe_helpers.hookenv._metadata_unit")
    @mock.patch("nrpe_helpers.hookenv.principal_unit")
    @mock.patch("nrpe_helpers.hookenv.config")
    def test_disable_all_built_in_checks(
        self, mock_config, mock_principal_unit, mock__metadata_unit, mock_glob
    ):
        """Test disabling all built-in checks when cos integration is detected."""
        config = load_default_config()
        config["disable_system_checks"] = True
        mock_config.side_effect = lambda key: config[key]
        mock_glob.side_effect = lambda arg: []  # cpufreq paths no exist in VM
        mock_principal_unit.return_value = "nova-compute/0"
        mock__metadata_unit.return_value = {"name": "nova-compute"}

        checks = nrpe_helpers.SubordinateCheckDefinitions()["checks"]
        for check in checks:
            self.assertEqual(check["cmd_params"], "")

    @mock.patch("nrpe_helpers.is_container")
    @mock.patch("nrpe_helpers.glob.glob")
    @mock.patch("nrpe_helpers.hookenv._metadata_unit")
    @mock.patch("nrpe_helpers.hookenv.principal_unit")
    @mock.patch("nrpe_helpers.hookenv.config")
    def test_sub_postfix(
        self,
        mock_config,
        mock_principal_unit,
        mock__metadata_unit,
        mock_glob,
        mock_is_container,
    ):
        """Test that sub_postfix is added to all checks."""
        postfix = "unittest"
        config = load_default_config()
        config["sub_postfix"] = postfix
        mock_config.side_effect = lambda key: config[key]
        mock_principal_unit.return_value = "nova-compute/0"
        mock__metadata_unit.return_value = {"name": "nova-compute"}
        mock_glob.side_effect = self.glob_valid_cpufreq_path
        mock_is_container.return_value = False

        check_definitions = nrpe_helpers.SubordinateCheckDefinitions()
        cmd_postfix = "###" + postfix
        for check in check_definitions["checks"]:
            with self.subTest(check):
                self.assertTrue(
                    check["cmd_name"].endswith(cmd_postfix),
                    f"{check['cmd_name']} does not end with {cmd_postfix}",
                )

    @mock.patch("nrpe_helpers.get_partitions_to_check")
    @mock.patch("nrpe_helpers.is_container")
    @mock.patch("nrpe_helpers.glob.glob")
    @mock.patch("nrpe_helpers.hookenv._metadata_unit")
    @mock.patch("nrpe_helpers.hookenv.principal_unit")
    @mock.patch("nrpe_helpers.hookenv.config")
    def test_sub_postfix_not_in_check_names(
        self,
        mock_config,
        mock_principal_unit,
        mock__metadata_unit,
        mock_glob,
        mock_is_container,
        mock_partitions,
    ):
        """Test that sub_postfix is not faced in normal check names."""
        config = load_default_config()
        mock_config.side_effect = lambda key: config[key]
        mock_principal_unit.return_value = "nova-compute/0"
        mock__metadata_unit.return_value = {"name": "nova-compute"}
        mock_glob.side_effect = self.glob_valid_cpufreq_path
        mock_is_container.return_value = False
        mock_partitions.return_value = {"/", "/var", "/var/log"}

        check_definitions = nrpe_helpers.SubordinateCheckDefinitions()
        for check in check_definitions["checks"]:
            with self.subTest(check):
                self.assertNotIn(check["cmd_name"], "###")

    @mock.patch("nrpe_helpers.is_container")
    @mock.patch("nrpe_helpers.hookenv._metadata_unit")
    @mock.patch("nrpe_helpers.hookenv.principal_unit")
    @mock.patch("nrpe_helpers.get_partitions_to_check")
    @mock.patch("nrpe_helpers.hookenv.config")
    def test_check_space_basics_functions(
        self,
        mock_config,
        mock_partitions,
        mock_principal_unit,
        mock__metadata_unit,
        mock_is_container,
    ):
        """Test generation of check_space commands."""
        config = load_default_config()
        mock_config.side_effect = lambda key: config[key]
        mock_principal_unit.return_value = "nova-compute/0"
        mock__metadata_unit.return_value = {"name": "nova-compute"}
        # without the line below test will fail in CI
        mock_is_container.return_value = False

        mock_partitions.return_value = {"/", "/var", "/var/log"}
        checks = nrpe_helpers.SubordinateCheckDefinitions()["checks"]
        cmd_names = {check["cmd_name"] for check in checks}
        for expected in {"check_space_root", "check_space_var", "check_space_var_log"}:
            with self.subTest():
                self.assertIn(expected, cmd_names)
