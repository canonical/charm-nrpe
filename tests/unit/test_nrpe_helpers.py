"""Unit tests for hooks/nrpe_helpers.py module."""
import unittest
from unittest import mock

import netifaces

from nrpe_helpers import match_cidr_to_ifaces


class TestMatchCidrToIfaces(unittest.TestCase):
    """Test match_cidr_to_ifaces helper function."""

    mock_iface_ip_data = {
        'lo': '127.0.0.1',
        'eno1': '10.0.0.0',
        'eno2': '10.1.0.0',
        'fan-252': '252.0.0.1',
    }

    def test_single_dev_match(self):
        """Test single interface match."""
        self._run_mocked_test('10.0.0.0/16', ['eno1'])

    def test_multi_dev_match(self):
        """Test multiple interface match."""
        self._run_mocked_test('10.0.0.0/8', ['eno1', 'eno2'])

    def test_no_dev_match(self):
        """Test no interface match."""
        self._run_mocked_test('192.168.0.0/16', [])

    def test_cidr_with_host_bits_set(self):
        """Test invalid CIDR input (e.g. "eno1")."""
        with self.assertRaises(Exception):
            match_cidr_to_ifaces('10.1.2.3/8')  # Should be 10.0.0.0/8

    def test_iface_passed_in_as_cidr(self):
        """Test invalid CIDR input (e.g. "eno1")."""
        with self.assertRaises(Exception):
            match_cidr_to_ifaces('eno1')

    @mock.patch('netifaces.ifaddresses')
    @mock.patch('netifaces.interfaces')
    def _run_mocked_test(self, cidr, matches, ifaces_mock, addrs_mock):
        iface_ip_tuples = list(self.mock_iface_ip_data.items())
        ifaces_mock.return_value = [t[0] for t in iface_ip_tuples]
        addrs_mock.side_effect = [{netifaces.AF_INET: [{'addr': t[1]}]} for t in
                                  iface_ip_tuples]
        self.assertEqual(match_cidr_to_ifaces(cidr), matches)
