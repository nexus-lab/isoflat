import oslo_messaging as messaging
from neutron.common import rpc as n_rpc
from oslo_log import log as logging

from neutron_isoflat.common import constants

LOG = logging.getLogger(__name__)


class IsoflatRpcDriver(object):

    def __init__(self, service_plugin):
        LOG.debug("Loading IsoflatRpcDriver.")
        self.service_plugin = service_plugin
        self.endpoints = [self]
        self.conn = n_rpc.create_connection()
        self.conn.create_consumer(constants.TOPIC_ISOFLAT_PLUGIN, self.endpoints, fanout=False)
        self.conn.consume_in_threads()
        target = messaging.Target(topic=constants.TOPIC_ISOFLAT_AGENT, version='1.0')
        self.client = n_rpc.get_client(target)

    @property
    def service_type(self):
        pass

    def _update_rules_rpc(self, context, rule):
        physical_network = rule['physical_network']
        rules = self.service_plugin.get_rules_by_physical_network(context, physical_network)
        LOG.debug("Sending the RPC call for updating isoflat rules on network %s" % physical_network)
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, 'update_rules', physical_network=physical_network, isoflat_rules=rules)

    def create_rule_precommit(self, context, rule):
        pass

    def create_rule_postcommit(self, context, rule):
        self._update_rules_rpc(context, rule)

    def delete_rule_precommit(self, context, rule):
        pass

    def delete_rule_postcommit(self, context, rule):
        self._update_rules_rpc(context, rule)

    def get_rules_for_network(self, context, physical_network):
        return self.service_plugin.get_rules_by_physical_network(context, physical_network)
