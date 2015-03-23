from mock import call
from test_utils import CharmTestCase
import nrpe_utils
import os

TO_PATCH = [
    'charm_dir',
    'config',
    'copy2',
    'glob',
    'mkdir',
    'os',
    'relations_of_type',
    'render',
    'rsync',
    'socket',
    'unit_get',
]


class NRPEUtilsTests(CharmTestCase):

    def setUp(self):

        def _unit_get(ipkey):
            ips = {
                'private-address': '192.168.20.10',
                'public-address': '8.8.8.8',
            }
            return ips[ipkey]

        super(NRPEUtilsTests, self).setUp(nrpe_utils, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.socket.getfqdn.return_value = 'myserver'
        self.unit_get.side_effect = _unit_get
        self.os.path.join.side_effect = os.path.join

    def tearDown(self):
        super(NRPEUtilsTests, self).tearDown()

    def test_restart_map(self):
        self.glob.glob.return_value = ['/etc/nagios/nrpe.d/check_swap.cfg']
        self.assertEquals({
            '/etc/rsync-juju.d/010-nrpe-external-master.conf': ['rsync'],
            '/etc/rsyncd.conf': ['rsync'],
            '/etc/nagios/nrpe.cfg': ['nagios-nrpe-server'],
            '/etc/nagios/nrpe.d/check_swap.cfg': ['nagios-nrpe-server'],
        }, nrpe_utils.restart_map())

    def test_determine_packages(self):
        self.assertEquals(['nagios-nrpe-server', 'nagios-plugins-basic',
                           'nagios-plugins-standard', 'rsync'],
                          nrpe_utils.determine_packages())

    def test_nrpe_ctxt_default(self):
        expect = {
            'allowed_hosts': '127.0.0.1',
            'server_port': 5666,
        }
        self.assertEquals(nrpe_utils.nrpe_ctxt(), expect)

    def test_nrpe_ctxt(self):
        self.test_config.set('nagios_master', '10.0.0.10')
        self.test_config.set('server_port', 5777)
        expect = {
            'allowed_hosts': '127.0.0.1,10.0.0.10',
            'server_port': 5777,
        }
        self.assertEquals(nrpe_utils.nrpe_ctxt(), expect)

    def test_rsync_jujud_ctxt_default(self):
        expect = {
            'nagios_master': '127.0.0.1',
        }
        self.assertEquals(nrpe_utils.rsync_jujud_ctxt(), expect)

    def test_rsync_jujud_ctxt_nag_master(self):
        self.test_config.set('nagios_master', '10.0.0.10')
        expect = {
            'nagios_master': '10.0.0.10',
        }
        self.assertEquals(nrpe_utils.rsync_jujud_ctxt(), expect)

    def test_exp_host_ctxt_default(self):
        self.test_config.set('nagios_hostname_type', 'host')
        expect = {
            'nagios_hostname': 'myserver',
            'ipaddress': '192.168.20.10',
            'hostcheck_inherit': 'server',
            'hostgroups': '',
        }
        self.assertEquals(nrpe_utils.exp_host_ctxt(), expect)

    def test_write_config(self):
        self.test_config.set('nagios_hostname_type', 'host')
        old_host_def = '/var/lib/nagios/export/host__olddef.cfg'
        self.glob.glob.return_value = [old_host_def]
        nrpe_ctxt = {
            'allowed_hosts': '127.0.0.1',
            'server_port': 5666,
        }
        rsync_jujud_ctxt = {
            'nagios_master': '127.0.0.1',
        }
        exp_host_ctxt = {
            'nagios_hostname': 'myserver',
            'ipaddress': '192.168.20.10',
            'hostcheck_inherit': 'server',
            'hostgroups': '',
        }
        nrpe_utils.write_config()
        calls = [
            call('nrpe.tmpl', '/etc/nagios/nrpe.cfg', nrpe_ctxt),
            call('rsync-juju.d.tmpl',
                 '/etc/rsync-juju.d/010-nrpe-external-master.conf',
                 rsync_jujud_ctxt),
            call('export_host.cfg.tmpl',
                 '/var/lib/nagios/export/host__myserver.cfg',
                 exp_host_ctxt)]
        self.render.assert_has_calls(calls)
        self.os.unlink.assert_called_with(old_host_def)

    def test_install_charm_files_mkdirs(self):
        self.os.path.exists.return_value = False
        nrpe_utils.install_charm_files()
        calls = [
            call('/etc/nagios/nrpe.d/'),
            call('/usr/local/lib/nagios/plugins'),
            call('/var/lib/nagios/export/'),
        ]
        self.mkdir.assert_has_calls(calls)

    def test_install_charm_files_no_mkdir(self):
        self.os.path.exists.return_value = True
        nrpe_utils.install_charm_files()
        self.assertEquals(self.mkdir.call_args_list, [])

    def test_install_charm_files_copy(self):
        self.charm_dir.return_value = '/tmp'
        calls = [
            call('/tmp/files/nagios_plugin.py',
                 '/usr/lib/nagios/plugins/nagios_plugin.py'),
            call('/tmp/files/default_rsync', '/etc/default/rsync'),
            call('/tmp/files/rsyncd.conf', '/etc/rsyncd.conf'),
        ]
        nrpe_utils.install_charm_files()
        self.copy2.assert_has_calls(calls)
        self.rsync.assert_called_with('/tmp/files/plugins',
                                      '/usr/local/lib/nagios/')

    def test_install_charm_symlink(self):
        self.os.path.exists.return_value = False
        nrpe_utils.install_charm_files()
        self.os.symlink.assert_called_with(
            '/usr/lib/nagios/plugins/nagios_plugin.py',
            '/usr/local/lib/nagios/plugins/nagios_plugin.py'
        )

    def test_proc_count(self):
        self.assertTrue(nrpe_utils.proc_count() > 0)

    def test_nrpe_checks_manual(self):
        checks = {
            'check_disk_root': {
                'override': '-u GB -w 50% -c 40% -K 10',
                'expect': '-u GB -w 50% -c 40% -K 10 -p / ',
                'setting': 'disk_root',
            },
            'check_zombie_procs': {
                'override': '-w 6 -c 12 -s Z',
                'setting': 'zombies',
            },
            'check_total_procs': {
                'override': '-w 100 -c 300',
                'setting': 'procs',
            },
            'check_load': {
                'override': '-w 16,16,16 -c 30,30,30',
                'setting': 'load',
            },
            'check_users': {
                'override': '-w 40 -c 50',
                'setting': 'users',
            },
            'check_swap': {
                'override': '-w 80% -c 70',
                'setting': 'swap',
            },
        }
        for check in checks.iterkeys():
            self.test_config.set(checks[check]['setting'],
                                 checks[check]['override'])
        output = nrpe_utils.nrpe_checks()
        for entry in output:
            key = entry['cmd_name']
            if 'expect' in checks[key]:
                self.assertEqual(entry['cmd_params'], checks[key]['expect'])
            else:
                self.assertEqual(entry['cmd_params'], checks[key]['override'])

    def test_install_nrped_files(self):
        check_file = [
            '/etc/nagios/nrpe.d/%s.cfg' % ('check_disk_root'),
            '/etc/nagios/nrpe.d/%s.cfg' % ('check_zombie_procs'),
            '/etc/nagios/nrpe.d/%s.cfg' % ('check_total_procs'),
            '/etc/nagios/nrpe.d/%s.cfg' % ('check_load'),
            '/etc/nagios/nrpe.d/%s.cfg' % ('check_users'),
            '/etc/nagios/nrpe.d/%s.cfg' % ('check_swap'),
        ]
        nrpe_utils.install_nrped_files()
        rendered_files = [x[0][1] for x in self.render.call_args_list]
        self.assertEqual(check_file, rendered_files)

    def test_nagios_hostname_host(self):
        self.test_config.set('nagios_hostname_type', 'host')
        self.assertEqual(nrpe_utils.nagios_hostname(), 'myserver')

    def test_nagios_hostname_unit_nrpeextmast(self):
        def _relations_of_type(relname):
            relations = {
                'nrpe-external-master': [{
                    u'private-address': u'10.0.1.84',
                    '__unit__': u'cinder/0',
                    '__relid__': u'nrpe-external-master:2'
                }],
                'general-info': [],
            }
            return relations[relname]
        self.relations_of_type.side_effect = _relations_of_type
        self.test_config.set('nagios_hostname_type', 'unit')
        self.assertEqual(nrpe_utils.nagios_hostname(), 'juju-cinder-0')

    def test_nagios_hostname_unit_jujuinfo(self):
        def _relations_of_type(relname):
            relations = {
                'general-info': [{
                    u'private-address': u'10.0.1.84',
                    '__unit__': u'ubuntu/0',
                    '__relid__': u'general-info:2'
                }],
                'nrpe-external-master': [],
            }
            return relations[relname]
        self.relations_of_type.side_effect = _relations_of_type
        self.test_config.set('nagios_hostname_type', 'unit')
        self.assertEqual(nrpe_utils.nagios_hostname(),
                         'juju-ubuntu-0')

    def test_nagios_hostname_unit_jujuinfo_hostctxt(self):
        def _relations_of_type(relname):
            relations = {
                'general-info': [{
                    u'private-address': u'10.0.1.84',
                    '__unit__': u'ubuntu/0',
                    '__relid__': u'general-info:2'
                }],
                'nrpe-external-master': [],
            }
            return relations[relname]
        self.relations_of_type.side_effect = _relations_of_type
        self.test_config.set('nagios_hostname_type', 'unit')
        self.test_config.set('nagios_host_context', 'bob')
        self.assertEqual(nrpe_utils.nagios_hostname(),
                         'bob-ubuntu-0')

    def test_nagios_ipaddress_public(self):
        self.test_config.set('nagios_address_type', 'public')
        self.assertEqual(nrpe_utils.nagios_ipaddress(), '8.8.8.8')

    def test_nagios_ipaddress_private(self):
        self.test_config.set('nagios_address_type', 'private')
        self.assertEqual(nrpe_utils.nagios_ipaddress(), '192.168.20.10')
