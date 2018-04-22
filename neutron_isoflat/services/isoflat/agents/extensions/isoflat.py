import abc
import random
import string

import six
from neutron import manager
from neutron.common import rpc as n_rpc
from neutron_lib.agent import l2_extension
from neutron_lib.utils import helpers
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import service

from neutron_isoflat._i18n import _
from neutron_isoflat.common import constants

LOG = logging.getLogger(__name__)

OPTS = [
    cfg.IntOpt(
        'agent_periodic_interval',
        default=5,
        help=_('Seconds between periodic task runs')
    ),
    cfg.ListOpt('bridge_mappings',
                default=constants.DEFAULT_BRIDGE_MAPPINGS,
                help=_("Comma-separated list of <physical_network>:<bridge> "
                       "tuples mapping physical network names to the agent's "
                       "node-specific Open vSwitch/Linux bridge names to be used "
                       "for flat networks. The length of bridge "
                       "names should be no more than 11. Each bridge must "
                       "exist, and should have a physical network interface "
                       "configured as a port. All physical networks "
                       "configured on the server should have mappings to "
                       "appropriate bridges on each agent. "
                       "Note: If you remove a bridge from this "
                       "mapping, make sure to disconnect it from the "
                       "integration bridge as it won't be managed by the "
                       "agent anymore.")),
]
cfg.CONF.register_opts(OPTS, constants.ISOFLAT)


@six.add_metaclass(abc.ABCMeta)
class IsoflatAgentDriverBase(object):

    @staticmethod
    def _random_name():
        return constants.ISOFLAT_BR_PREFIX + \
               ''.join(random.choice(string.lowercase + '0123456789')
                       for _ in range(constants.ISOFLAT_IF_LENGTH - len(constants.ISOFLAT_BR_PREFIX)))

    @staticmethod
    def _get_phy_if_name(bridge_name):
        """
        Veth interface name that plugs into the physical bridge.

        :param bridge_name: The Isoflat mirror bridge name
        """
        return constants.ISOFLAT_IF_PREFIX + bridge_name[len(constants.ISOFLAT_BR_PREFIX):]

    @staticmethod
    def _get_iso_if_name(bridge_name):
        """
        Veth interface name that plugs into the Isoflat mirror bridge.

        :param bridge_name: The physical bridge name
        """
        return constants.PHYSIBR_IF_PREFIX + bridge_name[len(constants.ISOFLAT_BR_PREFIX):]

    @staticmethod
    def _parse_bridge_mappings(bridge_mappings):
        try:
            return helpers.parse_mappings(bridge_mappings)
        except ValueError as e:
            raise ValueError(_("Parsing bridge_mappings failed: %s.") % e)

    @abc.abstractmethod
    def initialize(self):
        """Agent driver initialization."""

    @abc.abstractmethod
    def consume_api(self, agent_api):
        """Consume the AgentAPI instance from the IsoflatAgentExtension.

        :param agent_api: An instance of an agent specific API
        """

    @abc.abstractmethod
    def setup_mirror_bridges(self):
        """
        Check if the [ovs] or [linux_bridges] section bridge_mappings has all the provider networks.
        If not, set up the bridges and restart the agent.
        """

    @abc.abstractmethod
    def save_bridge_mappings(self):
        """
        Write the new bridge mappings to the [ovs] or [linux_bridge] section
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
        self.driver.setup_mirror_bridges()
        self.driver.save_bridge_mappings()
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
