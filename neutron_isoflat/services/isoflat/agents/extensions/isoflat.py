import abc
import random
import string

import oslo_messaging as messaging
import six
from neutron import manager
from neutron.common import rpc as n_rpc
from neutron_lib import context as qcontext
from neutron_lib.agent import l2_extension
from neutron_lib.utils import helpers
from oslo_config import cfg
from oslo_log import log as logging

from neutron_isoflat._i18n import _
from neutron_isoflat.common import constants
from neutron_isoflat.services.isoflat.agents.firewall.linux import firewall

LOG = logging.getLogger(__name__)

OPTS = [
    cfg.StrOpt(
        'firewall_driver',
        default='ebtables',
        help=_('Class name of the firewall driver Isoflat uses to filter flat network traffic.')
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

    def __init__(self, agent_extension):
        self.agent_extension = agent_extension
        firewall_driver = cfg.CONF.ISOFLAT.firewall_driver
        LOG.debug("Init Isoflat firewall settings (driver=%s)", firewall_driver)
        firewall_class = firewall.load_firewall_driver_class(firewall_driver)
        self.firewall = firewall_class()
        self.firewall.init_firewall()

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
    def _parse_bridge_mappings(bridge_mappings, unique_values=True):
        try:
            return helpers.parse_mappings(bridge_mappings, unique_values)
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
    def setup_isoflat_bridges(self):
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
    def update_rules(self, context, physical_network, isoflat_rules):
        """Update firewall rules for a physical network."""


class IsoflatAgentExtension(l2_extension.L2AgentExtension):
    agent_api = None
    driver = None
    context = None

    def _setup_rpc(self):
        endpoints = [self]
        conn = n_rpc.create_connection()
        conn.create_consumer(constants.TOPIC_ISOFLAT_AGENT, endpoints, fanout=False)
        conn.consume_in_threads()
        target = messaging.Target(topic=constants.TOPIC_ISOFLAT_PLUGIN, version='1.0')
        self.client = n_rpc.get_client(target)

    def consume_api(self, agent_api):
        self.agent_api = agent_api

    def initialize(self, connection, driver_type):
        LOG.debug("Isoflat agent initialize called")
        self.context = qcontext.get_admin_context_without_session()
        self._setup_rpc()

        self.driver = manager.NeutronManager.load_class_for_provider(
            'neutron_isoflat.isoflat.agent_drivers', driver_type)(self)
        self.driver.consume_api(self.agent_api)
        self.driver.setup_isoflat_bridges()
        self.driver.save_bridge_mappings()
        self.driver.initialize()

    def handle_port(self, context, data):
        pass

    def delete_port(self, context, data):
        pass

    def update_rules(self, context, physical_network, isoflat_rules):
        LOG.debug("Received an RPC call for updating isoflat rules on network %s" % physical_network)
        self.driver.update_rules(context, physical_network, isoflat_rules)

    def get_rules_for_network(self, physical_network):
        LOG.debug("Get isoflat rules for physical network %s via rpc", physical_network)
        cctxt = self.client.prepare()
        return cctxt.call(self.context, 'get_rules_for_network', physical_network=physical_network)
