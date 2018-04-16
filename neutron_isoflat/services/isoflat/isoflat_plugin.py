from neutron.db import servicetype_db as st_db
from neutron.services import provider_configuration as pconf
from neutron.services import service_base
from neutron_lib import exceptions as n_exc
from neutron_lib.utils import helpers
from oslo_config import cfg
from oslo_log import log as logging

from neutron_isoflat.common import constants
from neutron_isoflat.extensions import isoflat

LOG = logging.getLogger(__name__)


class IsoflatPlugin(isoflat.IsoflatPluginBase):

    supported_extension_aliases = ["isoflat"]
    path_prefix = "/isoflat"

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

    def get_rules(self, context, filters=None, fields=None,
                  sorts=None, limit=None, marker=None,
                  page_reverse=False):
        LOG.debug("LISTING ISOFLAT RULES")
        bridge_mappings = helpers.parse_mappings(
            cfg.CONF.ISOFLAT.bridge_mappings)
        LOG.debug(bridge_mappings)
        pass

    def get_rule(self, context, rule_id, fields=None):
        pass

    def create_rule(self, context, rule):
        pass

    def delete_rule(self, context, rule_id):
        pass
