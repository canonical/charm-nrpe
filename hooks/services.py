"""Nrpe service definifition."""

from charmhelpers.core import hookenv
from charmhelpers.core.hookenv import status_set
from charmhelpers.core.services import helpers
from charmhelpers.core.services.base import ServiceManager

import nrpe_helpers

import nrpe_utils


def manage():
    """Manage nrpe service."""
    status_set("maintenance", "starting")
    config = hookenv.config()
    manager = ServiceManager(
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
                    helpers.render_template(
                        source="nrpe.tmpl", target="/etc/nagios/nrpe.cfg"
                    ),
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
    manager.manage()
    if nrpe_utils.has_consumer():
        status_set("active", "ready")
    else:
        status_set("blocked", "Nagios server not configured or related")
