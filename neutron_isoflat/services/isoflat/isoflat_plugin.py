from neutron.db import servicetype_db as st_db
from neutron.services import provider_configuration as pconf
from neutron.services import service_base
from neutron_lib import exceptions as n_exc
from oslo_log import log as logging
from oslo_utils import excutils

from neutron_isoflat.common import constants
from neutron_isoflat.db import isoflat_db
from neutron_isoflat.extensions import isoflat

LOG = logging.getLogger(__name__)


# TODO: on remote network subnet changes, refresh isoflat rules
class IsoflatPlugin(isoflat_db.IsoflatDbMixin):

    supported_extension_aliases = ["isoflat"]
    path_prefix = "/isoflat"

    @staticmethod
    def _check_network_type(network):
        if network['provider:network_type'] != 'flat':
            raise isoflat.InvalidNetworkType(network_id=network['id'])

    def _check_network(self, context, network):
        if network['tenant_id'] != context.tenant_id or not context.is_admin:
            raise isoflat.NotAuthorizedToEditRule(network_id=network['id'])
        self._check_network_type(network)

    def _prepare_rule_dict_for_agent(self, context, rule, physical_network):
        if rule['remote_ip'] is not None:
            remote_ips = [rule['remote_ip']]
        elif rule.get('remote_network_id', None) is not None:
            # get subnets and ips
            subnets = self._get_subnets(context, rule['remote_network_id'])
            remote_ips = [subnet['cidr'] for subnet in subnets]
        else:
            remote_ips = ['0.0.0.0/0']
        return {
            'physical_network': physical_network,
            'direction': rule['direction'],
            'protocol': rule['protocol'],
            'port_range_min': rule['port_range_min'],
            'port_range_max': rule['port_range_max'],
            'ethertype': rule['ethertype'],
            'remote_ips': remote_ips
        }

    def __init__(self):
        LOG.debug("ISOFLAT PLUGIN INITIALIZED")
        self.service_type_manager = st_db.ServiceTypeManager.get_instance()
        self.service_type_manager.add_provider_configuration(constants.ISOFLAT,
                                                             pconf.ProviderConfiguration('neutron_isoflat'))
        drivers, default_provider = service_base.load_drivers(constants.ISOFLAT, self)
        if default_provider in drivers:
            self.driver = drivers[default_provider]
        else:
            raise n_exc.Invalid("Error retrieving driver for provider %s" % default_provider)

    def get_rules_by_physical_network(self, context, physical_network):
        rules = self._get_rules_by_physical_network(context, physical_network)
        return [self._prepare_rule_dict_for_agent(context, rule, physical_network) for rule in rules]

    def create_rule(self, context, rule):
        LOG.debug("IsoflatPlugin.create_rule() called")
        r = rule['rule']
        network = self._get_network_details(context, r['network_id'])
        physical_network = network['provider:physical_network']
        self._check_network(context, network)
        if r['remote_network_id'] is not None:
            remote_network = self._get_network_details(context, r['network_id'])
            self._check_network_type(remote_network)

        with context.session.begin(subtransactions=True):
            r = super(IsoflatPlugin, self).create_rule(context, rule)
            rule = self._prepare_rule_dict_for_agent(context, r, physical_network)
            self.driver.create_rule_precommit(context, rule)
        try:
            self.driver.create_rule_postcommit(context, rule)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error("Failed to create isoflat rule on driver,"
                          "deleting rule %s", r['id'])
                super(IsoflatPlugin, self).delete_rule(context, r['id'])
        return r

    def delete_rule(self, context, rule_id):
        LOG.debug("IsoflatPlugin.delete_rule() called")
        with context.session.begin(subtransactions=True):
            r = self.get_rule(context, rule_id)
            network = self._get_network_details(context, r['network_id'])
            physical_network = network['provider:physical_network']
            self._check_network(context, network)
            super(IsoflatPlugin, self).delete_rule(context, rule_id)

            rule = self._prepare_rule_dict_for_agent(context, r, physical_network)
            self.driver.delete_rule_precommit(context, rule)
        try:
            self.driver.delete_rule_postcommit(context, rule)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error("Failed to delete rule on driver. "
                          "rule: %s", rule_id)
