import abc

import six
from neutron import manager
from neutron.common import rpc as n_rpc
from neutron_lib.agent import l2_extension
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service

from neutron_isoflat.common import constants
from neutron_isoflat._i18n import _

LOG = logging.getLogger(__name__)

OPTS = [
    cfg.IntOpt(
        'agent_periodic_interval',
        default=5,
        help=_('Seconds between periodic task runs')
    )
]
cfg.CONF.register_opts(OPTS, constants.ISOFLAT)


@six.add_metaclass(abc.ABCMeta)
class IsoflatAgentDriver(object):

    @abc.abstractmethod
    def initialize(self):
        """Agent driver initialization."""

    @abc.abstractmethod
    def consume_api(self, agent_api):
        """Consume the AgentAPI instance from the IsoflatAgentExtension.

        :param agent_api: An instance of an agent specific API
        """

    @abc.abstractmethod
    def create_rule(self, context, rule):
        """Create an Isoflat rule."""

    @abc.abstractmethod
    def delete_rule(self, context, rule):
        """Delete an Isoflat rule."""


class IsoflatAgentExtension(l2_extension.L2AgentExtension):
    agent_api = None
    driver = None

    def _setup_rpc(self):
        endpoints = [self]
        conn = n_rpc.create_connection()
        conn.create_consumer(constants.TOPIC_ISOFLAT_AGENT, endpoints, fanout=False)
        conn.consume_in_threads()

    def consume_api(self, agent_api):
        self.agent_api = agent_api

    def initialize(self, connection, driver_type):
        LOG.debug("Isoflat agent initialize called")
        self.driver = manager.NeutronManager.load_class_for_provider(
            'neutron_isoflat.isoflat.agent_drivers', driver_type)()
        self.driver.consume_api(self.agent_api)
        self.driver.initialize()

        self._setup_rpc()
        IsoflatAgentService(self).start()

    def handle_port(self, context, data):
        pass

    def delete_port(self, context, data):
        pass

    def create_rule(self, context, rule):
        LOG.debug("Received an RPC call for creating isoflat rule %s" % rule)
        self.driver.create_rule(context, rule)

    def delete_rule(self, context, rule):
        LOG.debug("Received an RPC call for deleting isoflat rule %s" % rule)
        self.driver.delete_rule(context, rule)

    def periodic_tasks(self):
        pass


class IsoflatAgentService(service.Service):
    def __init__(self, driver):
        super(IsoflatAgentService, self).__init__()
        self.driver = driver

    def start(self):
        super(IsoflatAgentService, self).start()
        self.tg.add_timer(
            int(cfg.CONF.ISOFLAT.agent_periodic_interval),
            self.driver.periodic_tasks, None)
