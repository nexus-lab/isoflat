import abc
import six

from neutron.api.v2 import resource_helper
from neutron.extensions.securitygroup import convert_ethertype_to_case_insensitive
from neutron.extensions.securitygroup import convert_ip_prefix_to_cidr
from neutron.extensions.securitygroup import convert_protocol
from neutron.extensions.securitygroup import convert_validate_port_value
from neutron.extensions.securitygroup import sg_supported_ethertypes
from neutron_lib.api import extensions
from neutron_lib.services import base as service_base

from neutron_isoflat.common import constants

RESOURCE_ATTRIBUTE_MAP = {
    'rules': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
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
        return IsoFlatPluginBase

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
class IsoFlatPluginBase(service_base.ServicePluginBase):

    def get_plugin_name(self):
        return constants.ISOFLAT

    def get_plugin_description(self):
        return "IsoFlat Service Plugin"

    @classmethod
    def get_plugin_type(cls):
        return constants.ISOFLAT

    @abc.abstractmethod
    def get_rules(self, context, filters=None, fields=None,
                  sorts=None, limit=None, marker=None,
                  page_reverse=False):
        """List all IsoFlat rules."""
        pass

    @abc.abstractmethod
    def get_rule(self, context, rule_id, fields=None):
        """Get an IsoFlat rule."""
        pass

    @abc.abstractmethod
    def create_rule(self, context, rule):
        """Create an IsoFlat rule."""
        pass

    @abc.abstractmethod
    def delete_rule(self, context, rule_id):
        """Delete an IsoFlat rule."""
        pass
