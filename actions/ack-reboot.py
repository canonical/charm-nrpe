#!/usr/bin/env python3
"""Acknowledge reboot alert.

Usage: juju run-action --wait nrpe/0 ack-reboot

It will:

- get current reboot time via `uptime --since`
- update the known reboot time record in unit db
- update arg in check_reboot.cfg with new reboot time

So when new check triggered, alert will be resolved.
"""
import sys

# current dir will be charm root dir
sys.path.append("hooks")

# ignore E402 since we have to import these after we append hooks to sys.path
from charmhelpers.core import hookenv  # noqa: E402

import nrpe_helpers  # noqa: E402

import services  # noqa: E402

if hookenv.config("reboot"):
    reboot_time = nrpe_helpers.set_known_reboot_time()
    services.get_manager().reconfigure_services("nrpe-config")
    hookenv.action_set({"message": "known reboot time updated to {}".format(reboot_time)})
else:
    hookenv.action_fail("reboot check is not enabled, this action has no effect")
