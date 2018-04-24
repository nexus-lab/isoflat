import abc

import six
from neutron_lib.utils import runtime


def load_firewall_driver_class(driver):
    return runtime.load_class_by_alias_or_classname(
        'neutron_isoflat.services.isoflat.agents.firewall.linux', driver)


@six.add_metaclass(abc.ABCMeta)
class FirewallDriver(object):

    @abc.abstractmethod
    def init_firewall(self):
        """
        The firewall initialization work should go here.
        """

    @abc.abstractmethod
    def update_firewall_rules(self, device, physical_network, isoflat_rules):
        """
        Update firewall rules for a specific port.
        """