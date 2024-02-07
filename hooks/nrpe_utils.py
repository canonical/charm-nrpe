"""Nrpe utils module."""

import glob
import os
import shutil
import subprocess

from charmhelpers import fetch
from charmhelpers.core import hookenv, host
from charmhelpers.core.services import helpers
from charmhelpers.core.services.base import ManagerCallback, PortManagerCallback
from charmhelpers.core.templating import render

import nrpe_helpers

import yaml


def restart_rsync(service_name):
    """Restart rsync."""
    host.service_restart("rsync")


def restart_nrpe(service_name):
    """Restart nrpe."""
    host.service_restart("nagios-nrpe-server")


def determine_packages():
    """Return a list of packages this charm needs installed."""
    pkgs = [
        "nagios-nrpe-server",
        "nagios-plugins-basic",
        "nagios-plugins-standard",
        "python3",
        "python3-netifaces",
    ]

    if hookenv.config("export_nagios_definitions"):
        pkgs.append("rsync")

    return pkgs


def install_packages(service_name):
    """Install packages."""
    fetch.apt_update()
    apt_options = [
        # avoid installing rpcbind LP#1873171
        "--no-install-recommends",
        # and retain the default option too
        "--option=Dpkg::Options::=--force-confold",
    ]
    fetch.apt_install(determine_packages(), options=apt_options, fatal=True)


def remove_host_export_fragments(service_name):
    """Remove nagios host config fragment."""
    for fname in glob.glob("/var/lib/nagios/export/host__*"):
        os.unlink(fname)


def install_charm_files(service_name):
    """Install files shipped with charm."""
    # The preinst script of nagios-nrpe-server deb package will add nagios user
    # and create this dir as home
    # ref: https://git.launchpad.net/ubuntu/+source/nagios-nrpe/tree/debian/nagios-nrpe-server.preinst#n28  # NOQA: E501
    nagios_home = "/var/lib/nagios"

    # it's possible dir owner be changed to root by other process, e.g.: LP1866382
    # here we ensure owner is nagios, but didn't apply it resursively intentionally.
    shutil.chown(nagios_home, user="nagios", group="nagios")

    # the `2` in mode will setgid for group, set dir permission to `drwxr-sr-x`.
    # the `s` (setgid) will ensure any file created in this dir inherits parent dir
    # group `nagios`, regardless of the effective user, such as root.
    os.chmod(nagios_home, 0o2755)  # 2 will set the s flag for group

    nag_dirs = [
        "/etc/nagios/nrpe.d/",
        "/usr/local/lib/nagios/plugins",
        "/var/lib/nagios/export/",
    ]

    for nag_dir in nag_dirs:
        if not os.path.exists(nag_dir):
            host.mkdir(nag_dir, perms=0o755)
    charm_file_dir = os.path.join(hookenv.charm_dir(), "files")
    charm_plugin_dir = os.path.join(charm_file_dir, "plugins")
    pkg_plugin_dir = "/usr/lib/nagios/plugins/"
    local_plugin_dir = "/usr/local/lib/nagios/plugins/"
    nagios_plugin = "nagios_plugin3.py"

    shutil.copy2(
        os.path.join(charm_file_dir, "nagios_plugin3.py"),
        pkg_plugin_dir + "/nagios_plugin3.py",
    )
    os.chmod(pkg_plugin_dir + "/nagios_plugin3.py", 0o644)

    if hookenv.config("export_nagios_definitions"):
        shutil.copy2(
            os.path.join(charm_file_dir, "default_rsync"), "/etc/default/rsync"
        )
        shutil.copy2(os.path.join(charm_file_dir, "rsyncd.conf"), "/etc/rsyncd.conf")
        host.mkdir("/etc/rsync-juju.d", perms=0o755)

    for filename in os.listdir(charm_plugin_dir):
        source_file = os.path.join(charm_plugin_dir, filename)
        dest = os.path.join(local_plugin_dir, filename)
        if os.path.isfile(source_file):
            shutil.copy2(source_file, dest)
            os.chmod(dest, 0o755)

    if not os.path.exists(local_plugin_dir + nagios_plugin):
        os.symlink(
            os.path.join(pkg_plugin_dir, nagios_plugin),
            os.path.join(local_plugin_dir, nagios_plugin),
        )
    else:
        os.chmod(local_plugin_dir + "/nagios_plugin3.py", 0o644)


def render_nrpe_check_config(checkctxt):
    """Write nrpe check definition."""
    # Only render if we actually have cmd parameters.
    if checkctxt["cmd_params"]:
        render(
            "nrpe_command.tmpl",
            "/etc/nagios/nrpe.d/{}.cfg".format(checkctxt["cmd_name"]),
            checkctxt,
        )


def remove_nrpe_check_config(checkctxt):
    """Remove nrpe check definition."""
    # Remove all nrpe check related to this checktxt.
    for fname in checkctxt["matching_files"]:
        if os.path.exists(fname):
            os.unlink(fname)


def render_nrped_files(service_name):
    """Render each of the predefined checks."""
    for checkctxt in nrpe_helpers.SubordinateCheckDefinitions()["checks"]:
        remove_nrpe_check_config(checkctxt)
        render_nrpe_check_config(checkctxt)
    process_local_monitors()
    process_user_monitors()


def process_user_monitors():
    """Collect the user defined local monitors from config."""
    if hookenv.config("monitors"):
        monitors = yaml.safe_load(hookenv.config("monitors"))
    else:
        return
    try:
        local_user_checks = monitors["monitors"]["local"].keys()
    except KeyError as e:
        hookenv.log("no local monitors found in monitors config: {}".format(e))

        return

    for checktype in local_user_checks:
        for check in monitors["monitors"]["local"][checktype].keys():
            check_def = nrpe_helpers.NRPECheckCtxt(
                checktype, monitors["monitors"]["local"][checktype][check], "user"
            )
            render_nrpe_check_config(check_def)


def process_local_monitors():
    """Get all the monitor dicts and write out and local checks."""
    monitor_dicts = nrpe_helpers.MonitorsRelation().get_monitor_dicts()

    for monitor_src in monitor_dicts.keys():
        monitor_dict = monitor_dicts[monitor_src]

        if not (monitor_dict and "local" in monitor_dict["monitors"]):
            continue
        monitors = monitor_dict["monitors"]["local"]

        for checktype in monitors:
            for check in monitors[checktype]:
                render_nrpe_check_config(
                    nrpe_helpers.NRPECheckCtxt(
                        checktype,
                        monitors[checktype][check],
                        monitor_src,
                    )
                )


def update_nrpe_external_master_relation(service_name):
    """Update nrpe external master relation.

    Send updated nagios_hostname to charms attached
    to nrpe_external_master relation.
    """
    principal_relation = nrpe_helpers.PrincipalRelation()

    for rid in hookenv.relation_ids("nrpe-external-master"):
        hookenv.relation_set(
            relation_id=rid, relation_settings=principal_relation.provide_data()
        )


def update_monitor_relation(service_name):
    """Send updated monitor yaml to charms attached to monitor relation."""
    monitor_relation = nrpe_helpers.MonitorsRelation()

    for rid in hookenv.relation_ids("monitors"):
        hookenv.relation_set(
            relation_id=rid, relation_settings=monitor_relation.provide_data()
        )


def has_consumer():
    """Check for the monitor relation or external monitor config."""
    return hookenv.config("nagios_master") not in ["None", "", None] or bool(
        hookenv.relation_ids("monitors")
    )


def update_cis_audit_cronjob(service_name):
    """Install/Remove the cis-audit cron job."""
    crond_file = "/etc/cron.d/cis-audit"

    if not hookenv.config("cis_audit_enabled"):
        if os.path.exists(crond_file):
            os.remove(crond_file)
            hookenv.log("Cronjob removed at {}".format(crond_file), hookenv.DEBUG)

        return

    file = "/usr/local/lib/nagios/plugins/cron_cis_audit.py"
    profile = hookenv.config("cis_audit_profile")
    cronjob = "*/10 * * * * root ({} -p '{}') 2>&1 | logger -t {}\n"
    with open(crond_file, "w") as crond_fd:
        crond_fd.write(cronjob.format(file, profile, "cron_cis_audit"))
        hookenv.log("Cronjob configured at {}".format(crond_file), hookenv.DEBUG)


class TolerantPortManagerCallback(PortManagerCallback):
    """Manage unit ports.

    Specialization of the PortManagerCallback. It will open or close
    ports as its superclass, but will not raise an error on conflicts
    for opening ports

    For context, see:
    https://bugs.launchpad.net/juju/+bug/1750079 and
    https://github.com/juju/charm-helpers/pull/152
    """

    def __call__(self, manager, service_name, event_name):
        """Open unit ports."""
        service = manager.get_service(service_name)
        new_ports = service.get("ports", [])
        port_file = os.path.join(hookenv.charm_dir(), ".{}.ports".format(service_name))

        if os.path.exists(port_file):
            with open(port_file) as fp:
                old_ports = fp.read().split(",")

            for old_port in old_ports:
                if bool(old_port) and not self.ports_contains(old_port, new_ports):
                    hookenv.close_port(old_port)
        with open(port_file, "w") as fp:
            fp.write(",".join(str(port) for port in new_ports))

        for port in new_ports:
            # A port is either a number or 'ICMP'
            protocol = "TCP"

            if str(port).upper() == "ICMP":
                protocol = "ICMP"

            if event_name == "start":
                try:
                    hookenv.open_port(port, protocol)
                except subprocess.CalledProcessError as err:
                    if err.returncode == 1:
                        hookenv.log(
                            "open_port returns: {}, ignoring".format(err),
                            level=hookenv.INFO,
                        )
                    else:
                        raise
            elif event_name == "stop":
                hookenv.close_port(port, protocol)


maybe_open_ports = TolerantPortManagerCallback()


class ExportManagerCallback(ManagerCallback):
    """Defer lookup of nagios_hostname.

    This class exists in order to defer lookup of nagios_hostname()
    until the template is ready to be rendered.  This should reduce the
    incidence of incorrectly-rendered hostnames in /var/lib/nagios/exports.
    See charmhelpers.core.services.base.ManagerCallback and
    charmhelpers.core.services.helpers.TemplateCallback for more background.
    """

    def __call__(self, manager, service_name, event_name):
        """Render export_host.cfg."""
        nag_hostname = nrpe_helpers.PrincipalRelation().nagios_hostname()
        target = "/var/lib/nagios/export/host__{}.cfg".format(nag_hostname)
        renderer = helpers.render_template(
            source="export_host.cfg.tmpl",
            target=target,
            perms=0o644,
        )
        renderer(manager, service_name, event_name)


create_host_export_fragment = ExportManagerCallback()
