import glob
import socket
import yaml
import subprocess

from charmhelpers.core.services import helpers
from charmhelpers.core import hookenv
import os


class Monitors(dict):
    """ Represent the list of checks that a remote Nagios can query converting
        local check to ones that can be queried remotely
    """

    def __init__(self, version='0.3'):
        self['monitors'] = {
            'remote': {
                'nrpe': {}
            }
        }
        self['version'] = version

    def add_monitors(self, mdict, monitor_label='default'):
        if not mdict or not mdict.get('monitors'):
            return

        for checktype in mdict['monitors'].get('remote', []):
            check_details = mdict['monitors']['remote'][checktype]
            if self['monitors']['remote'].get(checktype):
                self['monitors']['remote'][checktype].update(check_details)
            else:
                self['monitors']['remote'][checktype] = check_details

        for checktype in mdict['monitors'].get('local', []):
            check_details = self.convert_local_checks(
                mdict['monitors']['local'],
                monitor_label,
            )
            self['monitors']['remote']['nrpe'].update(check_details)

    def add_nrpe_check(self, check_name, command):
        self['monitors']['remote']['nrpe'][check_name] = command

    def convert_local_checks(self, monitors, monitor_src):
        """ Convert check from local checks to remote nrpe checks

        monitors -- monitor dict
        monitor_src -- Monitor source principal, subordinate or user
        """
        mons = {}
        for checktype in monitors.keys():
            for checkname in monitors[checktype]:
                check_def = NRPECheckCtxt(
                    checktype,
                    monitors[checktype][checkname],
                    monitor_src,
                )
                mons[check_def['cmd_name']] = \
                    {'command': check_def['cmd_name']}
        return mons


class MonitorsRelation(helpers.RelationContext):
    name = 'monitors'
    interface = 'monitors'

    def __init__(self, *args, **kwargs):
        self.principal_relation = PrincipalRelation()
        super(MonitorsRelation, self).__init__(*args, **kwargs)

    def is_ready(self):
        return self.principal_relation.is_ready()

    def get_subordinate_monitors(self):
        """ Return default monitors defined by this charm """
        monitors = Monitors()
        for check in SubordinateCheckDefinitions()['checks']:
            if check['cmd_params']:
                monitors.add_nrpe_check(check['cmd_name'], check['cmd_name'])
        return monitors

    def get_user_defined_monitors(self):
        """ Return monitors defined by monitors config option """
        monitors = Monitors()
        monitors.add_monitors(yaml.safe_load(hookenv.config('monitors')),
                              'user')
        return monitors

    def get_principal_monitors(self):
        """ Return monitors passed by relation with principal """
        return self.principal_relation.get_monitors()

    def get_monitor_dicts(self):
        """ Return all monitor dicts """
        monitor_dicts = {
            'principal': self.get_principal_monitors(),
            'subordinate': self.get_subordinate_monitors(),
            'user': self.get_user_defined_monitors(),
        }
        return monitor_dicts

    def get_monitors(self):
        """ Return monitor dict of all monitors merged together and local
            monitors converted to remote nrpe checks
        """
        all_monitors = Monitors()
        monitors = [
            self.get_principal_monitors(),
            self.get_subordinate_monitors(),
            self.get_user_defined_monitors(),
        ]
        for mon in monitors:
            all_monitors.add_monitors(mon)
        return all_monitors

    def get_data(self):
        super(MonitorsRelation, self).get_data()
        if not hookenv.relation_ids(self.name):
            return
        addresses = [info['private-address'] for info in self['monitors']]
        self['monitor_allowed_hosts'] = ','.join(addresses)

    def provide_data(self):
        try:
            address = hookenv.network_get_primary_address('monitors')
        except NotImplementedError:
            address = hookenv.unit_get('private-address')

        relation_info = {
            'target-id': self.principal_relation.nagios_hostname(),
            'monitors': self.get_monitors(),
            'private-address': address,
            'machine_id': os.environ['JUJU_MACHINE_ID'],
        }
        return relation_info


class PrincipalRelation(helpers.RelationContext):

    def __init__(self, *args, **kwargs):
        if hookenv.relations_of_type('nrpe-external-master'):
            self.name = 'nrpe-external-master'
            self.interface = 'nrpe-external-master'
        elif hookenv.relations_of_type('general-info'):
            self.name = 'general-info'
            self.interface = 'juju-info'
        elif hookenv.relations_of_type('local-monitors'):
            self.name = 'local-monitors'
            self.interface = 'local-monitors'
        super(PrincipalRelation, self).__init__(*args, **kwargs)

    def is_ready(self):
        if self.name not in self:
            return False
        return '__unit__' in self[self.name][0]

    def nagios_hostname(self):
        """ Return the string that nagios will use to identify this host """
        host_context = hookenv.config('nagios_host_context')
        if host_context:
            host_context += '-'
        hostname_type = hookenv.config('nagios_hostname_type')
        if hostname_type == 'host' or not self.is_ready():
            nagios_hostname = "{}{}".format(host_context,
                                            socket.gethostname())
            return nagios_hostname
        else:
            principal_unitname = hookenv.principal_unit()
            # Fallback to using "primary" if it exists.
            if not principal_unitname:
                for relunit in self[self.name]:
                    if relunit.get('primary', 'False').lower() == 'true':
                        principal_unitname = relunit['__unit__']
                        break
            nagios_hostname = "{}{}".format(host_context, principal_unitname)
            nagios_hostname = nagios_hostname.replace('/', '-')
            return nagios_hostname

    def get_monitors(self):
        """ Return monitors passed by services on the self.interface relation
        """
        if not self.is_ready():
            return
        monitors = Monitors()
        for rel in self[self.name]:
            if rel.get('monitors'):
                monitors.add_monitors(yaml.load(rel['monitors']), 'principal')
        return monitors

    def provide_data(self):
        # Provide this data to principals because get_nagios_hostname expects
        # them in charmhelpers/contrib/charmsupport/nrpe when writing principal
        # service__* files
        return {'nagios_hostname': self.nagios_hostname(),
                'nagios_host_context': hookenv.config('nagios_host_context')}


class NagiosInfo(dict):
    def __init__(self):
        self.principal_relation = PrincipalRelation()
        self['external_nagios_master'] = '127.0.0.1'
        if hookenv.config('nagios_master') != 'None':
            self['external_nagios_master'] = \
                "{},{}".format(self['external_nagios_master'],
                               hookenv.config('nagios_master'))
        self['nagios_hostname'] = self.principal_relation.nagios_hostname()
        ip_key = hookenv.config('nagios_address_type') + '-address'
        self['nagios_ipaddress'] = hookenv.unit_get(ip_key)

        self['dont_blame_nrpe'] = '1' if hookenv.config('dont_blame_nrpe') else '0'
        self['debug'] = '1' if hookenv.config('debug') else '0'


class RsyncEnabled(helpers.RelationContext):

    def __init__(self):
        self['export_nagios_definitions'] = \
            hookenv.config('export_nagios_definitions')

    def is_ready(self):
        return self['export_nagios_definitions']


class NRPECheckCtxt(dict):
    """ Convert a local monitor definition into dict needed for writing the
        nrpe check definition
    """
    def __init__(self, checktype, check_opts, monitor_src):
        plugin_path = '/usr/lib/nagios/plugins'
        if checktype == 'procrunning':
            self['cmd_exec'] = plugin_path + '/check_procs'
            self['description'] = \
                'Check process {executable} is running'.format(**check_opts)
            self['cmd_name'] = 'check_proc_' + check_opts['executable']
            self['cmd_params'] = '-w {min} -c {max} -C {executable}'.format(
                **check_opts
            )
        elif checktype == 'processcount':
            self['cmd_exec'] = plugin_path + '/check_procs'
            self['description'] = 'Check process count'
            self['cmd_name'] = 'check_proc_principal'
            if 'min' in check_opts:
                self['cmd_params'] = '-w {min} -c {max}'.format(**check_opts)
            else:
                self['cmd_params'] = '-c {max}'.format(**check_opts)
        elif checktype == 'disk':
            self['cmd_exec'] = plugin_path + '/check_disk'
            self['description'] = 'Check disk usage ' + \
                check_opts['path'].replace('/', '_'),
            self['cmd_name'] = 'check_disk_principal'
            self['cmd_params'] = '-w 20 -c 10 -p ' + check_opts['path']
        self['description'] += ' ({})'.format(monitor_src)
        self['cmd_name'] += '_' + monitor_src


class SubordinateCheckDefinitions(dict):
    """ Return dict of checks the charm configures """
    def __init__(self):
        procs = self.proc_count()

        if hookenv.config('procs') == "auto":
            proc_thresholds = "-k -w {} -c {}".format(25 * procs + 100,
                                                      50 * procs + 100)
        else:
            proc_thresholds = hookenv.config('procs')

        if hookenv.config('load') == 'auto':
            # Give 1min load alerts higher thresholds than 15 min load alerts
            warn_multipliers = (4, 2, 1)
            crit_multipliers = (8, 4, 2)
            load_thresholds = ('-w %s -c %s') \
                % (','.join([str(m * procs) for m in warn_multipliers]),
                   ','.join([str(m * procs) for m in crit_multipliers]))
        else:
            load_thresholds = hookenv.config('load')

        if hookenv.config('disk_root'):
            disk_root_thresholds = hookenv.config('disk_root') + " -p / "
        else:
            disk_root_thresholds = ''

        pkg_plugin_dir = '/usr/lib/nagios/plugins/'
        local_plugin_dir = '/usr/local/lib/nagios/plugins/'
        checks = [
            {
                'description': 'Root disk',
                'cmd_name': 'check_disk_root',
                'cmd_exec': pkg_plugin_dir + 'check_disk',
                'cmd_params': disk_root_thresholds,
            },
            {
                'description': 'Number of Zombie processes',
                'cmd_name': 'check_zombie_procs',
                'cmd_exec': pkg_plugin_dir + 'check_procs',
                'cmd_params': hookenv.config('zombies'),
            },
            {
                'description': 'Number of processes',
                'cmd_name': 'check_total_procs',
                'cmd_exec': pkg_plugin_dir + 'check_procs',
                'cmd_params': proc_thresholds,
            },
            {
                'description': 'System Load',
                'cmd_name': 'check_load',
                'cmd_exec': pkg_plugin_dir + 'check_load',
                'cmd_params': load_thresholds,
            },
            {
                'description': 'Number of Users',
                'cmd_name': 'check_users',
                'cmd_exec': pkg_plugin_dir + 'check_users',
                'cmd_params': hookenv.config('users'),
            },
            {
                'description': 'Swap',
                'cmd_name': 'check_swap',
                'cmd_exec': pkg_plugin_dir + 'check_swap',
                'cmd_params': hookenv.config('swap'),
            },
            {
                'description': 'Swap Activity',
                'cmd_name': 'check_swap_activity',
                'cmd_exec': local_plugin_dir + 'check_swap_activity',
                'cmd_params': hookenv.config('swap_activity'),
            },
            {
                'description': 'Memory',
                'cmd_name': 'check_mem',
                'cmd_exec': local_plugin_dir + 'check_mem.pl',
                'cmd_params': hookenv.config('mem'),
            },
            {
                'description': 'Connnection tracking table',
                'cmd_name': 'check_conntrack',
                'cmd_exec': local_plugin_dir + 'check_conntrack.sh',
                'cmd_params': hookenv.config('conntrack'),
            },
            {
                'description': 'XFS Errors',
                'cmd_name': 'check_xfs_errors',
                'cmd_exec': local_plugin_dir + 'check_xfs_errors.py',
                'cmd_params': hookenv.config('xfs_errors'),
            },
        ]
        self['checks'] = []
        sub_postfix = str(hookenv.config("sub_postfix"))
        # Automatically use _sub for checks shipped on a unit with the nagios
        # charm. Mostly for backwards compatibility.
        principal_unit = hookenv.principal_unit()
        if sub_postfix == '' and principal_unit:
            md = hookenv._metadata_unit(principal_unit)
            if md and md.pop('name', None) == 'nagios':
                sub_postfix = '_sub'
        for check in checks:
            # This can be used to clean up old files before rendering the new ones
            check['matching_files'] = glob.glob('/etc/nagios/nrpe.d/{}*.cfg'.format(check['cmd_name']))
            check['description'] += " (sub)"
            check['cmd_name'] += sub_postfix
            self['checks'].append(check)

    def proc_count(self):
        """ Return number number of processing units """
        return int(subprocess.check_output('nproc'))
