import os
import shutil
import glob
import subprocess
import yaml

from charmhelpers import fetch
from charmhelpers.core import host
from charmhelpers.core import hookenv
from charmhelpers.core.services import helpers
from charmhelpers.core.services.base import (
    ManagerCallback,
    PortManagerCallback,
    )
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
        'nagios-plugins-standard',
        'python3',
    ]
    if hookenv.config('export_nagios_definitions'):
        pkgs.append('rsync')
    if hookenv.config('nagios_master') and hookenv.config('nagios_master') != 'None':
        pkgs.append('rsync')
    return pkgs


def install_packages(service_name):
    """ Install packages """
    fetch.apt_update()
    fetch.apt_install(determine_packages(), fatal=True)


def remove_rpcbind(service_name):
    """ Remove rpcbind LP#1873171 """
    fetch.apt_purge('rpcbind')


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
        os.path.join(charm_file_dir, 'nagios_plugin3.py'),
        pkg_plugin_dir + '/nagios_plugin3.py'
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
    for nagios_plugin in ('nagios_plugin.py', 'nagios_plugin3.py'):
        if not os.path.exists(local_plugin_dir + nagios_plugin):
            os.symlink(pkg_plugin_dir + nagios_plugin,
                       local_plugin_dir + nagios_plugin)


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
    process_user_monitors()


def process_user_monitors():
    """Collect the user defined local monitors from config"""
    if hookenv.config('monitors'):
        monitors = yaml.safe_load(hookenv.config('monitors'))
    else:
        return
    try:
        local_user_checks = monitors['monitors']['local'].keys()
    except KeyError as e:
        hookenv.log('no local monitors found in monitors config: {}'.format(e))
        return
    for checktype in local_user_checks:
        for check in monitors['monitors']['local'][checktype].keys():
            check_def = nrpe_helpers.NRPECheckCtxt(checktype,
                                                   monitors['monitors']['local'][checktype][check],
                                                   'user')
            render_nrpe_check_config(check_def)


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


class TolerantPortManagerCallback(PortManagerCallback):
    """
    Specialization of the PortManagerCallback. It will open or close
    ports as its superclass, but will not raise an error on conflicts
    for opening ports

    For context, see:
    https://bugs.launchpad.net/juju/+bug/1750079 and
    https://github.com/juju/charm-helpers/pull/152
    """
    def __call__(self, manager, service_name, event_name):
        service = manager.get_service(service_name)
        new_ports = service.get('ports', [])
        port_file = os.path.join(
            hookenv.charm_dir(), '.{}.ports'.format(service_name))
        if os.path.exists(port_file):
            with open(port_file) as fp:
                old_ports = fp.read().split(',')
            for old_port in old_ports:
                if bool(old_port) and not self.ports_contains(
                        old_port, new_ports):
                    hookenv.close_port(old_port)
        with open(port_file, 'w') as fp:
            fp.write(','.join(str(port) for port in new_ports))
        for port in new_ports:
            # A port is either a number or 'ICMP'
            protocol = 'TCP'
            if str(port).upper() == 'ICMP':
                protocol = 'ICMP'
            if event_name == 'start':
                try:
                    hookenv.open_port(port, protocol)
                except subprocess.CalledProcessError as err:
                    if err.returncode == 1:
                        hookenv.log(
                            "open_port returns: {}, ignoring".format(err),
                            level=hookenv.INFO)
                    else:
                        raise
            elif event_name == 'stop':
                hookenv.close_port(port, protocol)


maybe_open_ports = TolerantPortManagerCallback()


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
