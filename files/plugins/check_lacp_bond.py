#!/usr/bin/env python3
# -*- coding: us-ascii -*-

# Copyright (C) 2017 Canonical
# All rights reserved
# Author: Alvaro Uria <alvaro.uria@canonical.com>

import argparse
import glob
import os
import sys

from nagios_plugin3 import (
    CriticalError,
    WarnError,
    UnknownError,
    try_check,
)


def check_lacp_bond(iface):
    """Checks LACP bonds are correctly configured (AD Aggregator IDs match)
    """
    BOND_AGGR_TEMPLATE = '/sys/class/net/{0}/bonding/ad_aggregator'
    BOND_SLAVES_TEMPLATE = '/sys/class/net/{0}/bonding/slaves'
    BOND_MODE_TEMPLATE = '/sys/class/net/{0}/bonding/mode'
    SLAVE_TEMPLATE = '/sys/class/net/{0}/bonding_slave/ad_aggregator_id'

    bond_aggr = BOND_AGGR_TEMPLATE.format(iface)
    bond_slaves = BOND_SLAVES_TEMPLATE.format(iface)

    if os.path.exists(bond_aggr):
        with open(BOND_MODE_TEMPLATE.format(iface)) as fd:
            bond_mode = fd.readline()

        if '802.3ad' not in bond_mode:
            msg = 'WARNING: {} is not in lacp mode'.format(iface)
            raise WarnError(msg)

        with open(bond_aggr) as fd:
            bond_aggr_value = fd.readline().strip()

        d_bond = {iface: bond_aggr_value}

        with open(bond_slaves) as fd:
            slaves = fd.readline().strip().split(' ')

        for slave in slaves:
            with open(SLAVE_TEMPLATE.format(slave)) as fd:
                slave_aggr_value = fd.readline().strip()

            d_bond[slave] = slave_aggr_value

            if slave_aggr_value != bond_aggr_value:
                msg = 'CRITICAL: aggregator_id mismatch '
                msg += '({0}:{1} - {2}:{3})'
                msg = msg.format(iface, bond_aggr_value,
                                 slave, slave_aggr_value)
                raise CriticalError(msg)

    else:
        msg = 'CRITICAL: {} is not a bonding interface'.format(iface)
        raise CriticalError(msg)

    extra_info = '{0}:{1}'.format(iface, d_bond[iface])
    for k_iface, v_aggrid in d_bond.items():
        if k_iface == iface:
            continue
        extra_info += ', {0}:{1}'.format(k_iface, v_aggrid)
    print('OK: bond config is healthy: {}'.format(extra_info))


def parse_args():
    parser = argparse.ArgumentParser(description='Check bond status')
    parser.add_argument('--iface', '-i',
                        help='bond iface name')
    args = parser.parse_args()

    if not args.iface:
        ifaces = map(os.path.basename, glob.glob('/sys/class/net/bond?'))
        print('UNKNOWN: Please specify one of these bond '
              'ifaces: {}'.format(','.join(ifaces)))
        sys.exit(1)
    return args


def main():
    args = parse_args()
    try_check(check_lacp_bond,
              args.iface)

if __name__ == '__main__':
    main()
