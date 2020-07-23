#!/usr/bin/python3
"""Check systemd service and alert."""
#
# Copyright 2016 Canonical Ltd
#
# Author: Brad Marshall <brad.marshall@canonical.com>
#
# Based on check_upstart_job and
# https://zignar.net/2014/09/08/getting-started-with-dbus-python-systemd/
#
import sys

import dbus


service_arg = sys.argv[1]
service_name = "%s.service" % service_arg

try:
    bus = dbus.SystemBus()
    systemd = bus.get_object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
    manager = dbus.Interface(systemd, dbus_interface="org.freedesktop.systemd1.Manager")
    try:
        service_unit = manager.LoadUnit(service_name)
        service_proxy = bus.get_object("org.freedesktop.systemd1", str(service_unit))
        service = dbus.Interface(
            service_proxy, dbus_interface="org.freedesktop.systemd1.Unit"
        )
        service_res = service_proxy.Get(
            "org.freedesktop.systemd1.Unit",
            "SubState",
            dbus_interface="org.freedesktop.DBus.Properties",
        )

        if service_res == "running":
            print("OK: %s is running" % service_name)
            sys.exit(0)
        else:
            print("CRITICAL: %s is not running" % service_name)
            sys.exit(2)

    except dbus.DBusException:
        print("CRITICAL: unable to find %s in systemd" % service_name)
        sys.exit(2)

except dbus.DBusException:
    print("CRITICAL: unable to connect to system for %s" % service_name)
    sys.exit(2)
