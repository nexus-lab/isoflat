from neutron_isoflat.services.isoflat.agents.extensions import isoflat


class IsoflatLinuxBridgeDriver(isoflat.IsoflatAgentDriverBase):

    def save_bridge_mappings(self):
        pass

    def setup_isoflat_bridges(self):
        pass

    def initialize(self):
        pass

    def consume_api(self, agent_api):
        pass

    def update_rules(self, context, physical_network, isoflat_rules):
        pass
