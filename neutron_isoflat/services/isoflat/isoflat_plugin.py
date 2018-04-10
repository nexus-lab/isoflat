from oslo_log import log as logging
from neutron_isoflat.extensions import isoflat

LOG = logging.getLogger(__name__)


class IsoFlatPlugin(isoflat.IsoFlatPluginBase):

    supported_extension_aliases = ["isoflat"]
    path_prefix = "/isoflat"

    def __init__(self):
        super(IsoFlatPlugin, self).__init__()
        LOG.debug("ISOFLAT PLUGIN INITIALIZED")
        return

    def get_rules(self, context, filters=None, fields=None,
                  sorts=None, limit=None, marker=None,
                  page_reverse=False):
        LOG.debug("LISTING ISOFLAT RULES")
        pass

    def get_rule(self, context, rule_id, fields=None):
        pass

    def create_rule(self, context, rule):
        pass

    def delete_rule(self, context, rule_id):
        pass
