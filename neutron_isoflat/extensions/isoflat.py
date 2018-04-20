import abc

import six
from neutron.api.v2 import resource_helper
from neutron.extensions.securitygroup import convert_ethertype_to_case_insensitive
from neutron.extensions.securitygroup import convert_ip_prefix_to_cidr
from neutron.extensions.securitygroup import convert_protocol
from neutron.extensions.securitygroup import convert_validate_port_value
from neutron.extensions.securitygroup import sg_supported_ethertypes
from neutron_lib import exceptions as qexception
from neutron_lib.api import extensions
from neutron_lib.services import base as service_base
from oslo_config import cfg

from neutron_isoflat._i18n import _
from neutron_isoflat.common import constants

DEFAULT_BRIDGE_MAPPINGS = []

RESOURCE_ATTRIBUTE_MAP = {
    'rules': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'validate': {'type:string': None},
                      'required_by_policy': True, 'is_visible': True},
        'network_id': {'allow_post': True, 'allow_put': False,
                       'is_visible': True, 'required_by_policy': True},
        'direction': {'allow_post': True, 'allow_put': False,
                      'is_visible': True,
                      'validate': {'type:values': ['ingress', 'egress', 'both']}},
        'protocol': {'allow_post': True, 'allow_put': False,
                     'is_visible': True, 'default': None,
                     'convert_to': convert_protocol},
        'port_range_min': {'allow_post': True, 'allow_put': False,
                           'convert_to': convert_validate_port_value,
                           'default': None, 'is_visible': True},
        'port_range_max': {'allow_post': True, 'allow_put': False,
                           'convert_to': convert_validate_port_value,
                           'default': None, 'is_visible': True},
        'ethertype': {'allow_post': True, 'allow_put': False,
                      'is_visible': True, 'default': 'IPv4',
                      'convert_to': convert_ethertype_to_case_insensitive,
                      'validate': {'type:values': sg_supported_ethertypes}},
        'remote_ip': {'allow_post': True, 'allow_put': False,
                      'default': None, 'is_visible': True},
        'remote_network_id': {'allow_post': True, 'allow_put': False,
                              'default': None, 'is_visible': True,
                              'convert_to': convert_ip_prefix_to_cidr},
        'description': {'allow_post': True, 'allow_put': True,
                        'validate': {
                            'type:string': constants.DESCRIPTION_FIELD_SIZE},
                        'is_visible': True, 'default': ''},
    }
}

IsoflatOpts = [
    cfg.StrOpt('driver',
               default='',
               help=_("Name of the TaaS Driver")),
    cfg.ListOpt('bridge_mappings',
                default=DEFAULT_BRIDGE_MAPPINGS,
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
cfg.CONF.register_opts(IsoflatOpts, constants.ISOFLAT)


class IsoflatRuleNotFound(qexception.NotFound):
    message = _("Isoflat rule %(rule_id)s does not exist")


class NotAuthorizedToEditRule(qexception.NotAuthorized):
    message = _("The specified network %(network_id)s does not belong to you or you are not an admin")


class InvalidNetworkType(qexception.Invalid):
    message = _("The specified network %(network_id)s is not a flat network")


# Class name here has to be lowercase except the initial letter
class Isoflat(extensions.ExtensionDescriptor):
    """API extension for handling HDN tasks."""

    @classmethod
    def get_name(cls):
        return "Neutron flat network multiplexing and firewalling"

    @classmethod
    def get_alias(cls):
        return "isoflat"

    @classmethod
    def get_description(cls):
        return "Neutron flat network multiplexing and firewalling extension."

    @classmethod
    def get_updated(cls):
        return "2018-04-10T12:30:00-00:00"

    @classmethod
    def get_plugin_interface(cls):
        return IsoflatPluginBase

    @classmethod
    def get_resources(cls):
        """Returns Ext Resources."""
        plural_mappings = resource_helper.build_plural_mappings(
            {}, RESOURCE_ATTRIBUTE_MAP)

        return resource_helper.build_resource_info(plural_mappings,
                                                   RESOURCE_ATTRIBUTE_MAP,
                                                   constants.ISOFLAT,
                                                   translate_name=False,
                                                   allow_bulk=True)

    def update_attributes_map(self, attributes):
        super(Isoflat, self).update_attributes_map(
            attributes, extension_attrs_map=RESOURCE_ATTRIBUTE_MAP)

    def get_extended_resources(self, version):
        if version == "2.0":
            return RESOURCE_ATTRIBUTE_MAP
        else:
            return {}


@six.add_metaclass(abc.ABCMeta)
class IsoflatPluginBase(service_base.ServicePluginBase):

    def get_plugin_name(self):
        return constants.ISOFLAT

    def get_plugin_description(self):
        return "Isoflat Service Plugin"

    @classmethod
    def get_plugin_type(cls):
        return constants.ISOFLAT

    @abc.abstractmethod
    def get_rules(self, context, filters=None, fields=None,
                  sorts=None, limit=None, marker=None,
                  page_reverse=False):
        """List all Isoflat rules."""
        pass

    @abc.abstractmethod
    def get_rule(self, context, rule_id, fields=None):
        """Get an Isoflat rule."""
        pass

    @abc.abstractmethod
    def create_rule(self, context, rule):
        """Create an Isoflat rule."""
        pass

    @abc.abstractmethod
    def delete_rule(self, context, rule_id):
        """Delete an Isoflat rule."""
        pass
