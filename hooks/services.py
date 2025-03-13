"""Nrpe service definifition."""

import subprocess

from charmhelpers.core import hookenv
from charmhelpers.core.hookenv import WARNING, log, status_set
from charmhelpers.core.services import helpers
from charmhelpers.core.services.base import ServiceManager

import nrpe_helpers
import nrpe_utils


def get_manager():
    """Instantiate a ServiceManager object."""
    config = hookenv.config()
    return ServiceManager(
        [
            {
                "service": "nrpe-install",
                "data_ready": [
                    nrpe_utils.install_packages,
                    nrpe_utils.install_charm_files,
                ],
                "start": [],
                "stop": [],
            },
            {
                "service": "nrpe-config",
                "required_data": [
                    config,
                    nrpe_helpers.MonitorsRelation(),
                    nrpe_helpers.PrincipalRelation(),
                    nrpe_helpers.NagiosInfo(),
                ],
                "data_ready": [
                    nrpe_utils.update_nrpe_external_master_relation,
                    nrpe_utils.update_monitor_relation,
                    nrpe_utils.create_host_export_fragment,
                    nrpe_utils.render_nrped_files,
                    nrpe_utils.update_cis_audit_cronjob,
                    helpers.render_template(source="nrpe.tmpl", target="/etc/nagios/nrpe.cfg"),
                ],
                "provided_data": [nrpe_helpers.PrincipalRelation()],
                "ports": [hookenv.config("server_port"), "ICMP"],
                "start": [nrpe_utils.maybe_open_ports, nrpe_utils.restart_nrpe],
                "stop": [],
            },
            {
                "service": "nrpe-rsync",
                "required_data": [
                    config,
                    nrpe_helpers.PrincipalRelation(),
                    nrpe_helpers.RsyncEnabled(),
                    nrpe_helpers.NagiosInfo(),
                ],
                "data_ready": [
                    nrpe_utils.remove_host_export_fragments,
                    helpers.render_template(
                        source="rsync-juju.d.tmpl",
                        target="/etc/rsync-juju.d/010-nrpe-external-master.conf",
                    ),
                    nrpe_utils.create_host_export_fragment,
                ],
                "start": [nrpe_utils.restart_rsync],
                "stop": [],
            },
        ]
    )


def manage():
    """Manage nrpe service."""
    status_set("maintenance", "starting")
    try:
        manager = get_manager()
    except (subprocess.CalledProcessError, KeyError, IndexError) as err:
        msg = "Public address not available yet"
        log(msg, level=WARNING)
        log(err, level=WARNING)
        status_set("waiting", msg)
    else:
        manager.manage()
        update_status()


def update_status():
    """Update Nrpe Juju status."""
    cis_misconfigured, cis_message = nrpe_helpers.is_cis_misconfigured()

    if not nrpe_utils.has_consumer():
        status_set("blocked", "Nagios server not configured or related")
    elif nrpe_helpers.has_netlinks_error():
        status_set("blocked", "Netlinks parsing encountered failure; see logs")
    elif cis_misconfigured:
        status_set("blocked", cis_message)
    elif subprocess.call(["systemctl", "is-active", "--quiet", "nagios-nrpe-server"]) != 0:
        status_set("blocked", "nagios-nrpe-server service inactive.")
    else:
        status_set("active", "Ready")
