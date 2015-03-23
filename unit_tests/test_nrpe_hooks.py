from test_utils import CharmTestCase
import nrpe_hooks as hooks

TO_PATCH = [
    'apt_install',
    'apt_update',
    'determine_packages',
    'config',
    'install_charm_files',
    'install_nrped_files',
    'nagios_hostname',
    'relation_ids',
    'relation_set',
    'service_reload',
    'update_monitor_relation',
    'write_config',
]


class NRPEHooksTests(CharmTestCase):

    def setUp(self):
        super(NRPEHooksTests, self).setUp(hooks, TO_PATCH)

        self.config.side_effect = self.test_config.get

    def test_install_hook(self):
        self.determine_packages.return_value = ['foo', 'bar']
        hooks.install()
        self.apt_update.assert_called_with()
        self.apt_install.assert_called_with(
            ['foo', 'bar'], fatal=True)

    def test_config_chanmged(self):
        self.relation_ids.return_value = ['rid1']
        self.nagios_hostname.return_value = 'myserver'
        hooks.config_changed()
        self.install_charm_files.assert_called_with()
        self.install_nrped_files.assert_called_with()
        self.write_config.assert_called_with()
        rel_info = {
            'nagios_hostname': 'myserver',
            'nagios_host_context': 'juju',
        }
        self.relation_set.assert_called_with(relation_id='rid1',
                                             relation_settings=rel_info)

    def test_upgrade_charm(self):
        hooks.upgrade_charm()
        self.install_charm_files.assert_called_with()
        self.install_nrped_files.assert_called_with()
        self.write_config.assert_called_with()
        self.service_reload.assert_called_with('nagios-nrpe-server')

    def test_nrpe_master_changed(self):
        hooks.nrpe_master_changed()
        self.write_config.assert_called_with()
        self.update_monitor_relation.assert_called_with()

    def test_nrpe_master_joined(self):
        self.nagios_hostname.return_value = 'myserver'
        hooks.nrpe_master_joined()
        rel_info = {
            'nagios_hostname': 'myserver',
            'nagios_host_context': 'juju',
        }
        self.relation_set.assert_called_with(relation_id=None,
                                             relation_settings=rel_info)
