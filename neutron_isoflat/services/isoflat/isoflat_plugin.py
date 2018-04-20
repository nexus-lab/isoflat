from neutron.db import servicetype_db as st_db
from neutron.services import provider_configuration as pconf
from neutron.services import service_base
from neutron_lib import exceptions as n_exc
from oslo_log import log as logging

from neutron_isoflat.common import constants
from neutron_isoflat.db import isoflat_db
from neutron_isoflat.extensions import isoflat

LOG = logging.getLogger(__name__)


class IsoflatPlugin(isoflat_db.IsoflatDbMixin):

    supported_extension_aliases = ["isoflat"]
    path_prefix = "/isoflat"

    def _check_network(self, context, network_id):
        network = self._get_network_details(context, network_id)
        if network['tenant_id'] != context.tenant_id or not context.is_admin:
            raise isoflat.NotAuthorizedToEditRule(network_id=network_id)
        if network['provider:network_type'] != 'flat':
            raise isoflat.InvalidNetworkType(network_id=network_id)

    def _check_remote_network(self, context, network_id):
        network = self._get_network_details(context, network_id)
        if network['provider:network_type'] != 'flat':
            raise isoflat.InvalidNetworkType(network_id=network_id)

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

    def create_rule(self, context, rule):
        LOG.debug("IsoflatPlugin.create_rule() called")
        r = rule['rule']
        self._check_network(context, r['network_id'])
        if r['remote_network_id'] is not None:
            self._check_remote_network(context, r['remote_network_id'])
        with context.session.begin(subtransactions=True):
            r = super(IsoflatPlugin, self).create_rule(context, rule)
        return r

    def delete_rule(self, context, rule_id):
        LOG.debug("IsoflatPlugin.delete_rule() called")
        with context.session.begin(subtransactions=True):
            r = self.get_rule(context, rule_id)
            self._check_network(context, r['network_id'])
            super(IsoflatPlugin, self).delete_rule(context, rule_id)
