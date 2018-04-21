from neutron_isoflat.services.isoflat.agents.extensions import isoflat


class IsoflatLinuxBridgeDriver(isoflat.IsoflatAgentDriver):

    def initialize(self):
        pass

    def consume_api(self, agent_api):
        pass

    def create_rule(self, context, rule):
        pass

    def delete_rule(self, context, rule):
        pass
