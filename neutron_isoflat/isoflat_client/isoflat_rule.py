from neutronclient._i18n import _
from neutronclient.common import extension
from neutronclient.common import utils
from neutronclient.neutron import v2_0 as neutronV20


def _get_remote(rule):
    if rule['remote_ip']:
        remote = '%s (CIDR)' % rule['remote_ip']
    elif rule['remote_network_id']:
        remote = '%s (network)' % rule['remote_network_id']
    else:
        remote = None
    return remote


def _get_protocol_port(rule):
    proto = rule['protocol']
    port_min = rule['port_range_min']
    port_max = rule['port_range_max']
    if proto in ('tcp', 'udp'):
        if port_min and port_min == port_max:
            protocol_port = '%s/%s' % (port_min, proto)
        elif port_min:
            protocol_port = '%s-%s/%s' % (port_min, port_max, proto)
        else:
            protocol_port = proto
    elif proto == 'icmp':
        icmp_opts = []
        if port_min is not None:
            icmp_opts.append('type:%s' % port_min)
        if port_max is not None:
            icmp_opts.append('code:%s' % port_max)

        if icmp_opts:
            protocol_port = 'icmp (%s)' % ', '.join(icmp_opts)
        else:
            protocol_port = 'icmp'
    elif proto is not None:
        # port_range_min/max are not recognized for protocol
        # other than TCP, UDP and ICMP.
        protocol_port = proto
    else:
        protocol_port = None

    return protocol_port


def generate_default_ethertype(protocol):
    if protocol == 'icmpv6':
        return 'IPv6'
    return 'IPv4'


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
    """Delete a Isoflat rule."""

    shell_command = 'isoflat-rule-delete'


class ShowIsoflatRule(extension.ClientExtensionShow, IsoflatRule):
    """Show a Isoflat rule."""

    shell_command = 'isoflat-rule-show'


class CreateIsoflatRule(extension.ClientExtensionCreate, IsoflatRule):
    """Create a Isoflat rule."""

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
