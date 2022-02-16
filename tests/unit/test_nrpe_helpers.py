"""Unit tests for hooks/nrpe_helpers.py module."""
import unittest
from unittest import mock

import netifaces

import nrpe_helpers
from nrpe_helpers import match_cidr_to_ifaces


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
