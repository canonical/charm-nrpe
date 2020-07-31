#!/usr/bin/env python3
"""Check lacp bonds and alert."""
# -*- coding: us-ascii -*-

# Copyright (C) 2017 Canonical
# All rights reserved
# Author: Alvaro Uria <alvaro.uria@canonical.com>

import argparse
import glob
import os
import sys

from nagios_plugin3 import CriticalError, WarnError, try_check

# LACPDU port states in binary
LACPDU_ACTIVE = 0b1  # 1 = Active, 0 = Passive
LACPDU_RATE = 0b10  # 1 = Short Timeout, 0 = Long Timeout
LACPDU_AGGREGATED = 0b100  # 1 = Yes, 0 = No (individual link)
LACPDU_SYNC = 0b1000  # 1 = In sync, 0 = Not in sync
LACPDU_COLLECT = 0b10000  # Mux is accepting traffic received on this port
LACPDU_DIST = 0b100000  # Mux is sending traffic using this port
LACPDU_DEFAULT = 0b1000000  # 1 = default settings, 0 = via LACP PDU
LACPDU_EXPIRED = 0b10000000  # In an expired state


def check_lacpdu_port(actor_port, partner_port):
    """Return message for LACPDU port state mismatch."""
    diff = int(actor_port) ^ int(partner_port)
    msg = []
    if diff & LACPDU_RATE:
        msg.append("lacp rate mismatch")
    if diff & LACPDU_AGGREGATED:
        msg.append("not aggregated")
    if diff & LACPDU_SYNC:
        msg.append("not in sync")
    if diff & LACPDU_COLLECT:
        msg.append("not collecting")
    return ", ".join(msg)


def check_lacp_bond(iface):
    """Check LACP bonds are correctly configured (AD Aggregator IDs match)."""
    bond_aggr_template = "/sys/class/net/{0}/bonding/ad_aggregator"
    bond_slaves_template = "/sys/class/net/{0}/bonding/slaves"
    bond_mode_template = "/sys/class/net/{0}/bonding/mode"
    slave_template = "/sys/class/net/{0}/bonding_slave/ad_aggregator_id"
    actor_port_state = "/sys/class/net/{0}/bonding_slave/ad_actor_oper_port_state"
    partnet_port_state = "/sys/class/net/{0}/bonding_slave/ad_partner_oper_port_state"

    bond_aggr = bond_aggr_template.format(iface)
    bond_slaves = bond_slaves_template.format(iface)

    if os.path.exists(bond_aggr):
        with open(bond_mode_template.format(iface)) as fd:
            bond_mode = fd.readline()

        if "802.3ad" not in bond_mode:
            msg = "WARNING: {} is not in lacp mode".format(iface)
            raise WarnError(msg)

        with open(bond_aggr) as fd:
            bond_aggr_value = fd.readline().strip()

        d_bond = {iface: bond_aggr_value}

        with open(bond_slaves) as fd:
            slaves = fd.readline().strip().split(" ")
        for slave in slaves:
            # Check aggregator ID
            with open(slave_template.format(slave)) as fd:
                slave_aggr_value = fd.readline().strip()

            d_bond[slave] = slave_aggr_value

            if slave_aggr_value != bond_aggr_value:
                # If we can report then only 1/2 the bond is down
                msg = "WARNING: aggregator_id mismatch "
                msg += "({0}:{1} - {2}:{3})"
                msg = msg.format(iface, bond_aggr_value, slave, slave_aggr_value)
                raise WarnError(msg)
            # Check LACPDU port state
            with open(actor_port_state.format(slave)) as fd:
                actor_port_value = fd.readline().strip()
            with open(partnet_port_state.format(slave)) as fd:
                partner_port_value = fd.readline().strip()
            if actor_port_value != partner_port_value:
                res = check_lacpdu_port(actor_port_value, partner_port_value)
                msg = (
                    "WARNING: LACPDU port state mismatch "
                    "({0}: {1} - actor_port_state={2}, "
                    "partner_port_state={3})".format(
                        res, slave, actor_port_value, partner_port_value
                    )
                )
                raise WarnError(msg)

    else:
        msg = "CRITICAL: {} is not a bonding interface".format(iface)
        raise CriticalError(msg)

    extra_info = "{0}:{1}".format(iface, d_bond[iface])
    for k_iface, v_aggrid in d_bond.items():
        if k_iface == iface:
            continue
        extra_info += ", {0}:{1}".format(k_iface, v_aggrid)
    print("OK: bond config is healthy: {}".format(extra_info))


def parse_args():
    """Parse command-line options."""
    parser = argparse.ArgumentParser(description="Check bond status")
    parser.add_argument("--iface", "-i", help="bond iface name")
    args = parser.parse_args()

    if not args.iface:
        ifaces = map(os.path.basename, glob.glob("/sys/class/net/bond?"))
        print(
            "UNKNOWN: Please specify one of these bond "
            "ifaces: {}".format(",".join(ifaces))
        )
        sys.exit(1)
    return args


def main():
    """Parse args and check the lacp bonds."""
    args = parse_args()
    try_check(check_lacp_bond, args.iface)


if __name__ == "__main__":
    main()
