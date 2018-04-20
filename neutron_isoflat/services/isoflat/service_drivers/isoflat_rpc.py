import oslo_messaging as messaging
from neutron.common import rpc as n_rpc
from oslo_config import cfg
from oslo_log import log as logging

from neutron_isoflat.common import constants

LOG = logging.getLogger(__name__)


class IsoflatRpcDriver(object):

    def __init__(self, service_plugin):
        LOG.debug("Loading IsoflatRpcDriver.")
        self.host = cfg.CONF.host
        self.service_plugin = service_plugin
        self.endpoints = []
        self.conn = n_rpc.create_connection()
        self.conn.create_consumer(constants.TOPIC_ISOFLAT_PLUGIN,
                                  self.endpoints, fanout=False)
        self.conn.consume_in_threads()
        target = messaging.Target(topic=constants.TOPIC_ISOFLAT_AGENT, version='1.0')
        self.client = n_rpc.get_client(target)

    @property
    def service_type(self):
        pass

    def create_rule_precommit(self, context, rule):
        pass

    def create_rule_postcommit(self, context, rule):
        LOG.debug("RPC call from %s for creating isoflat rule %s" % (self.host, rule))
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, 'create_rule', rule=rule)

    def delete_rule_precommit(self, context, rule):
        pass

    def delete_rule_postcommit(self, context, rule):
        LOG.debug("RPC call from %s for deleting isoflat rule %s" % (self.host, rule))
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, 'delete_rule', rule=rule)
