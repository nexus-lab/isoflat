from neutronclient._i18n import _
from neutronclient.common import extension
from neutronclient.common import utils
from neutronclient.neutron import v2_0 as neutronV20
from neutronclient.neutron.v2_0.securitygroup import _get_remote
from neutronclient.neutron.v2_0.securitygroup import _get_protocol_port
from neutronclient.neutron.v2_0.securitygroup import generate_default_ethertype


class IsoflatRule(extension.NeutronClientExtension):
    resource = 'rule'
    resource_plural = '%ss' % resource
    object_path = '/isoflat/%s' % resource_plural
    resource_path = '/isoflat/%s/%%s' % resource_plural
    versions = ['2.0']


class ListIsoflatRule(extension.ClientExtensionList, IsoflatRule):
    """List Isoflat rules."""

    shell_command = 'isoflat-rule-list'
    list_columns = ['id', 'network_id', 'description', 'direction', 'ethertype',
                    'port/protocol', 'remote']
    digest_fields = {
        'remote': {
            'method': _get_remote,
            'depends_on': ['remote_ip', 'remote_network_id']},
        'port/protocol': {
            'method': _get_protocol_port,
            'depends_on': ['protocol', 'port_range_min', 'port_range_max']}}
    pagination_support = True
    sorting_support = True


class DeleteIsoflatRule(extension.ClientExtensionDelete, IsoflatRule):
    """Delete an Isoflat rule."""

    shell_command = 'isoflat-rule-delete'


class ShowIsoflatRule(extension.ClientExtensionShow, IsoflatRule):
    """Show an Isoflat rule."""

    shell_command = 'isoflat-rule-show'


class CreateIsoflatRule(extension.ClientExtensionCreate, IsoflatRule):
    """Create an Isoflat rule."""

    shell_command = 'isoflat-rule-create'

    def get_parser(self, prog_name):
        parser = super(neutronV20.CreateCommand, self).get_parser(prog_name)
        # we do not need tenant id
        self.add_known_arguments(parser)
        return parser

    def add_known_arguments(self, parser):
        parser.add_argument(
            '--description',
            help=_('Description of Isoflat rule.'))
        parser.add_argument(
            'network_id', metavar='NETWORK',
            help=_('ID of the Isoflat to which the rule is added.'))
        parser.add_argument(
            '--direction',
            type=utils.convert_to_lowercase,
            default='ingress', choices=['ingress', 'egress', 'both'],
            help=_('Direction of traffic to be dropped: ingress/egress/both.'))
        parser.add_argument(
            '--ethertype',
            help=_('IPv4/IPv6'))
        parser.add_argument(
            '--protocol',
            type=utils.convert_to_lowercase,
            help=_('Protocol of packet. Allowed values are '
                   '[icmp, icmpv6, tcp, udp] and '
                   'integer representations [0-255].'))
        parser.add_argument(
            '--port-range-min',
            help=_('Starting port range. For ICMP it is type.'))
        parser.add_argument(
            '--port-range-max',
            help=_('Ending port range. For ICMP it is code.'))
        parser.add_argument(
            '--remote-ip',
            help=_('CIDR to match on.'))
        parser.add_argument(
            '--remote-network-id', metavar='REMOTE_NETWORK',
            help=_('ID of the remote flat network to which the rule is applied.'))

    def args2body(self, parsed_args):
        body = {'ethertype': parsed_args.ethertype or
                generate_default_ethertype(parsed_args.protocol)}
        neutronV20.update_dict(parsed_args, body,
                               ['direction', 'protocol', 'port_range_min', 'port_range_max',
                                'remote_ip', 'remote_network_id',
                                'description'])
        return {self.resource: body}