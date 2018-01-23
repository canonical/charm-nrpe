#!/usr/bin/env python3
# -*- coding: us-ascii -*-

# Copyright (C) 2017 Canonical
# All rights reserved
# Author: Alvaro Uria <alvaro.uria@canonical.com>
#
# check_netlinks.py -i eth0 -o up -m 1500 -s 1000


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
FILTER = ('operstate', 'mtu', 'speed')


def check_iface(iface, skiperror, crit_thr):
    """Returns /sys/class/net/<iface>/<FILTER> values
    """
    FILE_PATH = '/sys/class/net/{0}/{1}'
    FILTER = ['operstate', 'mtu']
    if not os.path.exists(FILE_PATH.format(iface, 'bridge')) and \
       iface != 'lo':
        FILTER.append('speed')

    for metric_key in FILTER:
        try:
            with open(FILE_PATH.format(iface, metric_key)) as fd:
                metric_value = fd.readline().strip()
        except FileNotFoundError:
            if not skiperror:
                raise WarnError('WARNING: {} iface does not '
                                'exist'.format(iface))
            return

        if metric_key == 'operstate' and metric_value != 'up':
            if metric_value != crit_thr['operstate']:
                raise CriticalError('CRITICAL: {}' ' link state is '
                                    '{}'.format(iface, metric_value))

        if metric_value != crit_thr[metric_key]:
            raise CriticalError('CRITICAL: {}/{} is {} (target: '
                                '{})'.format(iface, metric_key, metric_value,
                                             crit_thr[metric_key]))

    for metric in crit_thr:
        if metric not in FILTER:
            crit_thr[metric] = 'n/a'
    crit_thr['iface'] = iface
    print('OK: {iface} matches thresholds: '
          'o:{operstate}, m:{mtu}, s:{speed}'.format(**crit_thr))


def parse_args():
    parser = argparse.ArgumentParser(description='check ifaces status')
    parser.add_argument('--iface', '-i', type=str,
                        help='interface to monitor; listed '
                        'in /sys/class/net/*)')
    parser.add_argument('--skip-unfound-ifaces', '-q', default=False,
                        action='store_true',
                        help='ignores unfound ifaces;'
                        ' otherwise, alert will be triggered')
    parser.add_argument('--operstate', '-o', default='up', type=str,
                        help='operstate: up, down, unknown (default: up)')
    parser.add_argument('--mtu', '-m', default='1500', type=str,
                        help='mtu size (default: 1500)')
    parser.add_argument('--speed', '-s', default='10000', type=str,
                        help='link speed in Mbps (default 10000)')
    args = parser.parse_args()

    if not args.iface:
        ifaces = map(os.path.basename, glob.glob('/sys/class/net/*'))
        print('UNKNOWN: Please specify one of these '
              'ifaces: {}'.format(','.join(ifaces)))
        sys.exit(1)
    return args


def main():
    args = parse_args()
    crit_thr = {'operstate': args.operstate.lower(),
                'mtu': args.mtu,
                'speed': args.speed}
    try_check(check_iface,
              args.iface, args.skip_unfound_ifaces, crit_thr)

if __name__ == '__main__':
    main()
