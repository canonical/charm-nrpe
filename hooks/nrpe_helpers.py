import socket
import yaml
import subprocess

from charmhelpers.core.services import helpers
from charmhelpers.core import hookenv


class MonitorsRelation(helpers.RelationContext):
    name = 'monitors'
    interface = 'monitors'

    def __init__(self, *args, **kwargs):
        self.principle_relation = PrincipleRelation()
        super(MonitorsRelation, self).__init__(*args, **kwargs)

    def is_ready(self):
        return self.principle_relation.is_ready()

    def convert_local_checks(self, monitors, monitor_src):
        """ Convert check from local checks to remote nrpe checks

        monitors -- monitor dict
        monitor_src -- Monitor source principle, subordinate or user
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

    def get_subordinate_monitors(self):
        """ Return default monitors defined by this charm """
        monitors = {
            'monitors': {
                'remote': {
                    'nrpe': {}
                }
            }
        }
        for check in SubordinateCheckDefinitions()['checks']:
            monitors['monitors']['remote']['nrpe'][check['cmd_name']] = \
                {'command': check['cmd_name']}
        return monitors

    def get_user_defined_monitors(self):
        """ Return monitors defined by monitors config option """
        return yaml.safe_load(hookenv.config('monitors'))

    def get_principle_monitors(self):
        """ Return monitors passed by relation with principle """
        return self.principle_relation.get_monitors()

    def get_monitor_dicts(self):
        """ Return all monitor dicts """
        monitor_dicts = {
            'principle': self.get_principle_monitors(),
            'subordinate': self.get_subordinate_monitors(),
            'user': self.get_user_defined_monitors(),
        }
        return monitor_dicts

    def get_monitors(self):
        """ Return monitor dict of all monitors merged together and local
            monitors converted to remote nrpe checks
        """
        monitors = {
            'monitors': {
                'remote': {
                    'nrpe': {}
                }
            }
        }
        monitor_dicts = self.get_monitor_dicts()
        for monitor_src in monitor_dicts.keys():
            monitor_dict = monitor_dicts[monitor_src]
            if not monitor_dict or 'monitors' not in monitor_dict:
                continue
            if 'remote' in monitor_dict['monitors']:
                remote_mons = monitor_dict['monitors']['remote']
                for checktype in remote_mons.keys():
                    if checktype in monitors['monitors']['remote']:
                        monitors['monitors']['remote'][checktype].update(
                            remote_mons[checktype]
                        )
                    else:
                        monitors['monitors']['remote'][checktype] = \
                            remote_mons[checktype]
            if 'local' in monitor_dict['monitors']:
                monitors['monitors']['remote']['nrpe'].update(
                    self.convert_local_checks(
                        monitor_dict['monitors']['local'],
                        monitor_src,
                    )
                )
        monitors['version'] = '0.3'
        return monitors

    def get_data(self):
        super(MonitorsRelation, self).get_data()
        if not hookenv.relation_ids(self.name):
            return
        addresses = [info['private-address'] for info in self['monitors']]
        self['monitor_allowed_hosts'] = ','.join(addresses)

    def provide_data(self):
        relation_info = {
            'target-id': self.principle_relation.nagios_hostname(),
            'monitors': self.get_monitors(),
        }
        return relation_info


class PrincipleRelation(helpers.RelationContext):

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
        super(PrincipleRelation, self).__init__(*args, **kwargs)

    def is_ready(self):
        if self.name not in self:
            return False
        return '__unit__' in self[self.name][0]

    def nagios_hostname(self):
        """ Return the string that nagios will use to identify this host """
        host_context = hookenv.config('nagios_host_context')
        hostname_type = hookenv.config('nagios_hostname_type')
        if hostname_type == 'host' or not self.is_ready():
            return socket.gethostname()
        else:
            principle_unitname = self[self.name][0]['__unit__']
            nagios_hostname = "{}-{}".format(host_context, principle_unitname)
            nagios_hostname = nagios_hostname.replace('/', '-')
            return nagios_hostname

    def get_monitors(self):
        """ Return monitors passed by principle charm """
        if not self.is_ready():
            return
        if 'monitors' in self[self.name][0]:
            return yaml.load(self[self.name][0]['monitors'])

    def provide_data(self):
        return {'nagios_hostname': self.nagios_hostname()}


class NagiosInfo(dict):
    def __init__(self):
        self.principle_relation = PrincipleRelation()
        self['external_nagios_master'] = '127.0.0.1'
        if hookenv.config()['nagios_master'] != 'None':
            self['external_nagios_master'] = \
                "{},{}".format(self['external_nagios_master'],
                               hookenv.config()['nagios_master'])
        self['nagios_hostname'] = self.principle_relation.nagios_hostname()
        ip_key = hookenv.config('nagios_address_type') + '-address'
        self['nagios_ipaddress'] = hookenv.unit_get(ip_key)


class RsyncEnabled(helpers.RelationContext):

    def __init__(self):
        self['export_nagios_definitions'] = \
            hookenv.config()['export_nagios_definitions']

    def is_ready(self):
        return self['export_nagios_definitions']


class NRPECheckCtxt(dict):
    """ Convert a local monitor definition into dict needed for writting the
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
            self['cmd_name'] = 'check_proc_principle'
            if 'min' in check_opts:
                self['cmd_params'] = '-w {min} -c {max}'.format(**check_opts)
            else:
                self['cmd_params'] = '-c {max}'.format(**check_opts)
        elif checktype == 'disk':
            self['cmd_exec'] = plugin_path + '/check_disk'
            self['description'] = 'Check disk usage ' + \
                check_opts['path'].replace('/', '_'),
            self['cmd_name'] = 'check_disk_principle'
            self['cmd_params'] = '-w 20 -c 10 -p ' + check_opts['path']
        self['description'] += ' ({})'.format(monitor_src)
        self['cmd_name'] += '_' + monitor_src


class SubordinateCheckDefinitions(dict):
    """ Return dict of checks the charm configures """
    def __init__(self):
        if hookenv.config('procs') == "auto":
            procs = self.proc_count()
            proc_thresholds = "-w {} -c {}".format(25 * procs + 100,
                                                   50 * procs + 100)
        else:
            proc_thresholds = hookenv.config('procs')
        pkg_plugin_dir = '/usr/lib/nagios/plugins/'
        local_plugin_dir = '/usr/local/lib/nagios/plugins/'
        checks = [
            {
                'description': 'Root disk',
                'cmd_name': 'check_disk_root',
                'cmd_exec': pkg_plugin_dir + 'check_disk',
                'cmd_params': hookenv.config('disk_root') + " -p / ",
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
                'cmd_params': hookenv.config('load'),
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
                'description': 'Memory',
                'cmd_name': 'check_mem',
                'cmd_exec': local_plugin_dir + 'check_mem.pl',
                'cmd_params': hookenv.config('mem'),
            },
        ]
        self['checks'] = []
        for check in checks:
            check['description'] += " (sub)"
            check['cmd_name'] += "_sub"
            self['checks'].append(check)

    def proc_count(self):
        """ Return number number of processing units """
        return int(subprocess.check_output('nproc'))
