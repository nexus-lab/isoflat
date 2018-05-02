import os
import sys
from ConfigParser import SafeConfigParser

from neutron.agent.common import ovs_lib
from neutron.agent.common import utils
from neutron.agent.linux import bridge_lib
from neutron.agent.linux import ip_lib
from oslo_config import cfg
from oslo_log import log as logging

from neutron_isoflat.services.isoflat.agents.extensions import isoflat

LOG = logging.getLogger(__name__)


class IsoflatOvsDriver(isoflat.IsoflatAgentDriverBase):

    _bridge_mappings_changed = False

    def __init__(self, agent_extension):
        super(IsoflatOvsDriver, self).__init__(agent_extension)
        self.ovs_bridge_mappings = self._parse_bridge_mappings(cfg.CONF.OVS.bridge_mappings)
        self.iso_bridge_mappings = self._parse_bridge_mappings(cfg.CONF.ISOFLAT.bridge_mappings, False)

    def initialize(self):
        # reboot the agent if bridge mappings changes
        if self._bridge_mappings_changed:
            os.execl(sys.executable, sys.executable, *sys.argv)
        # refresh firewall rules on agent restart
        for physical_network in self.iso_bridge_mappings:
            rules = self.agent_extension.get_rules_for_network(physical_network)
            self.update_rules(None, physical_network, rules)

    def consume_api(self, agent_api):
        pass

    @staticmethod
    def _if_bridge_exists(bridge_name):
        ovs = ovs_lib.BaseOVS()
        if bridge_name in ovs.get_bridges() or bridge_lib.BridgeDevice(bridge_name).exists():
            return True
        return False

    def _allocate_bridge_name(self):
        """
        Create a random bridge name and make sure no bridge with the same name exists.
        """
        name = None
        while name is None:
            name = self._random_name()
            if name in self.iso_bridge_mappings.values() or name in self.ovs_bridge_mappings.values():
                name = None
            if self._if_bridge_exists(name):
                name = None
        return name

    def setup_mirror_bridges(self):
        ovs = ovs_lib.BaseOVS()
        ip_wrapper = ip_lib.IPWrapper()
        for physical_network in self.iso_bridge_mappings:
            if physical_network not in self.ovs_bridge_mappings:
                self._bridge_mappings_changed = True
                br_name = self.iso_bridge_mappings[physical_network]
                if not bridge_lib.BridgeDevice(br_name).exists():
                    LOG.error("Linux bridge %(bridge)s for physical network "
                              "%(physical_network)s does not exist. Isoflat agent "
                              "terminated!",
                              {'physical_network': physical_network,
                               'bridge': br_name})
                    sys.exit(1)
                mir_br_name = self._allocate_bridge_name()
                self.ovs_bridge_mappings[physical_network] = mir_br_name
                iso_br = ovs.add_bridge(mir_br_name)
                phy_br = bridge_lib.BridgeDevice(br_name)
                phy_if_name = self._get_phy_if_name(mir_br_name)
                iso_if_name = self._get_iso_if_name(mir_br_name)
                device = ip_lib.IPDevice(iso_if_name)
                if device.exists():
                    device.link.delete()
                    # Give udev a chance to process its rules here, to avoid
                    # race conditions between commands launched by udev rules
                    # and the subsequent call to ip_wrapper.add_veth
                    utils.execute(['udevadm', 'settle', '--timeout=10'])
                phy_veth, iso_veth = ip_wrapper.add_veth(phy_if_name, iso_if_name)
                iso_br.add_port(iso_if_name)
                phy_br.addif(phy_veth)
                LOG.info("Added OVS Isoflat bridge %s and veth port pair "
                         "(%s, %s)" % (mir_br_name, phy_if_name, iso_if_name))
                # enable veth to pass traffic
                phy_veth.link.set_up()
                iso_veth.link.set_up()

    def save_bridge_mappings(self):
        if not self._bridge_mappings_changed:
            return
        for i, arg in enumerate(sys.argv):
            if arg == '--config-file':
                config_file = sys.argv[i + 1]
                parser = SafeConfigParser()
                parser.read(config_file)
                if not parser.has_section('isoflat'):
                    continue
                bridge_mapping_str = ','.join([network + ':' + bridge
                                               for network, bridge in self.ovs_bridge_mappings.items()])
                if not parser.has_section('ovs'):
                    parser.add_section('ovs')
                parser.set('ovs', 'bridge_mappings', bridge_mapping_str)
                with open(config_file, 'wb') as f:
                    parser.write(f)

    def update_rules(self, context, physical_network, isoflat_rules):
        mirror_bridge = self.ovs_bridge_mappings[physical_network]
        device = self._get_phy_if_name(mirror_bridge)
        self.firewall.update_firewall_rules(device, physical_network, isoflat_rules)
