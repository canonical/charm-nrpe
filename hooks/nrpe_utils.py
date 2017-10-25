import os
import shutil
import glob

from charmhelpers import fetch
from charmhelpers.core import host
from charmhelpers.core import hookenv
from charmhelpers.core.services import helpers
from charmhelpers.core.services.base import ManagerCallback
from charmhelpers.core.templating import render

import nrpe_helpers


def restart_rsync(service_name):
    """ Restart rsync """
    host.service_restart('rsync')


def restart_nrpe(service_name):
    """ Restart nrpe """
    host.service_restart('nagios-nrpe-server')


def determine_packages():
    """ List of packages this charm needs installed """
    pkgs = [
        'nagios-nrpe-server',
        'nagios-plugins-basic',
        'nagios-plugins-standard'
    ]
    if hookenv.config('export_nagios_definitions'):
        pkgs.append('rsync')
    return pkgs


def install_packages(service_name):
    """ Install packages """
    fetch.apt_update()
    fetch.apt_install(determine_packages(), fatal=True)


def remove_host_export_fragments(service_name):
    """ Remove nagios host config fragment """
    for fname in glob.glob('/var/lib/nagios/export/host__*'):
        os.unlink(fname)


def install_charm_files(service_name):
    """ Install files shipped with charm """
    nag_dirs = ['/etc/nagios/nrpe.d/', '/usr/local/lib/nagios/plugins',
                '/var/lib/nagios/export/']
    for nag_dir in nag_dirs:
        if not os.path.exists(nag_dir):
            host.mkdir(nag_dir, perms=0o755)
    charm_file_dir = os.path.join(hookenv.charm_dir(), 'files')
    charm_plugin_dir = os.path.join(charm_file_dir, 'plugins')
    pkg_plugin_dir = '/usr/lib/nagios/plugins/'
    local_plugin_dir = '/usr/local/lib/nagios/plugins/'

    shutil.copy2(
        os.path.join(charm_file_dir, 'nagios_plugin.py'),
        pkg_plugin_dir + '/nagios_plugin.py'
    )
    shutil.copy2(
        os.path.join(charm_file_dir, 'default_rsync'),
        '/etc/default/rsync'
    )
    shutil.copy2(
        os.path.join(charm_file_dir, 'rsyncd.conf'),
        '/etc/rsyncd.conf'
    )
    host.rsync(
        charm_plugin_dir,
        '/usr/local/lib/nagios/',
        options=['--executability']
    )
    if not os.path.exists(local_plugin_dir + 'nagios_plugin.py'):
        os.symlink(pkg_plugin_dir + 'nagios_plugin.py',
                   local_plugin_dir + 'nagios_plugin.py')


def render_nrpe_check_config(checkctxt):
    """ Write nrpe check definition """
    # Only render if we actually have cmd parameters
    if checkctxt['cmd_params']:
        render(
            'nrpe_command.tmpl',
            '/etc/nagios/nrpe.d/{}.cfg'.format(checkctxt['cmd_name']),
            checkctxt
        )


def render_nrped_files(service_name):
    """ Render each of the predefined checks """
    for checkctxt in nrpe_helpers.SubordinateCheckDefinitions()['checks']:
        # Clean up existing files
        for fname in checkctxt['matching_files']:
            try:
                os.unlink(fname)
            except FileNotFoundError:
                # Don't clean up non-existent files
                pass
        render_nrpe_check_config(checkctxt)
    process_local_monitors()


def process_local_monitors():
    """ Get all the monitor dicts and write out and local checks """
    monitor_dicts = nrpe_helpers.MonitorsRelation().get_monitor_dicts()
    for monitor_src in monitor_dicts.keys():
        monitor_dict = monitor_dicts[monitor_src]
        if not (monitor_dict and 'local' in monitor_dict['monitors']):
            continue
        monitors = monitor_dict['monitors']['local']
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
    """
    Send updated nagios_hostname to charms attached to nrpe_external_master
    relation.
    """
    principal_relation = nrpe_helpers.PrincipalRelation()
    for rid in hookenv.relation_ids('nrpe-external-master'):
        hookenv.relation_set(
            relation_id=rid,
            relation_settings=principal_relation.provide_data()
        )


def update_monitor_relation(service_name):
    """ Send updated monitor yaml to charms attached to monitor relation """
    monitor_relation = nrpe_helpers.MonitorsRelation()
    for rid in hookenv.relation_ids('monitors'):
        hookenv.relation_set(
            relation_id=rid,
            relation_settings=monitor_relation.provide_data()
        )


class ExportManagerCallback(ManagerCallback):

    """
    This class exists in order to defer lookup of nagios_hostname()
    until the template is ready to be rendered.  This should reduce the
    incidence of incorrectly-rendered hostnames in /var/lib/nagios/exports.
    See charmhelpers.core.services.base.ManagerCallback and
    charmhelpers.core.services.helpers.TemplateCallback for more background.
    """

    def __call__(self, manager, service_name, event_name):
        nag_hostname = nrpe_helpers.PrincipalRelation().nagios_hostname()
        target = '/var/lib/nagios/export/host__{}.cfg'.format(nag_hostname)
        renderer = helpers.render_template(
            source='export_host.cfg.tmpl',
            target=target,
            perms=0o644,
        )
        renderer(manager, service_name, event_name)


create_host_export_fragment = ExportManagerCallback()
