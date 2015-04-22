import os
import shutil
import glob

from charmhelpers import fetch
from charmhelpers.core import host
from charmhelpers.core.templating import render
from charmhelpers.core import hookenv

import nrpe_helpers


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


def remove_rsync_fragments(service_name):
    """ Remove config fragment that configures rsync for export fragments """
    rsync_file = '/etc/rsync-juju.d/010-nrpe-external-master.conf'
    if os.path.isfile(rsync_file):
        os.unlink(rsync_file)


def install_charm_files(service_name):
    """ Install files shipped with charm """
    nag_dirs = ['/etc/nagios/nrpe.d/', '/usr/local/lib/nagios/plugins',
                '/var/lib/nagios/export/']
    for nag_dir in nag_dirs:
        if not os.path.exists(nag_dir):
            host.mkdir(nag_dir)
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
    """ Write nrpe check deifintion """
    render(
        'nrpe_command.tmpl',
        '/etc/nagios/nrpe.d/{}.cfg'.format(checkctxt['cmd_name']),
        checkctxt
    )


def render_nrped_files(service_name):
    """ Render each of the predefined checks """
    for checkctxt in nrpe_helpers.SubordinateCheckDefinitions()['checks']:
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


def update_monitor_relation(service_name):
    """ Send updated monitor yaml to charms attached to monitor relation """
    monitor_relation = nrpe_helpers.MonitorsRelation()
    for rid in hookenv.relation_ids('monitors'):
        hookenv.relation_set(
            relation_id=rid,
            relation_settings=monitor_relation.provide_data()
        )
