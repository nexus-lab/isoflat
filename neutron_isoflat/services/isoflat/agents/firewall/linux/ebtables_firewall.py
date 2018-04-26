from neutron.agent.linux import iptables_comments as ic
from neutron.common import constants as n_const
from neutron.common import utils as c_utils
from neutron_lib import constants
from oslo_log import log as logging

from neutron_isoflat.services.isoflat.agents.firewall.linux import ebtables_manager
from neutron_isoflat.services.isoflat.agents.firewall.linux import firewall

LOG = logging.getLogger(__name__)

BINARY_NAME = 'neutron-isoflat'
ISOFLAT_CHAIN = 'iso-chain'
CHAIN_NAME_PREFIX = {constants.INGRESS_DIRECTION: 'i-',
                     constants.EGRESS_DIRECTION: 'o-'}


class EbtablesFirewall(firewall.FirewallDriver):

    def __init__(self):
        self.ebtables = ebtables_manager.EbtablesManager(state_less=True, _binary_name=BINARY_NAME)
        self._add_isoflat_chain_v4v6()
        self._add_fallback_chain_v4v6()

    @staticmethod
    def _network_chain_name(physical_network, direction):
        return ebtables_manager.get_chain_name(
            '%s%s' % (CHAIN_NAME_PREFIX[direction], physical_network))

    def _add_chain_by_name_v4v6(self, chain_name):
        self.ebtables.tables['filter'].add_chain(chain_name)

    def _remove_chain_by_name_v4v6(self, chain_name):
        self.ebtables.tables['filter'].remove_chain(chain_name)

    def _add_chain(self, chain_name, device, direction):
        self._add_chain_by_name_v4v6(chain_name)

        if direction == constants.EGRESS_DIRECTION:
            jump_rule = ['-%s %s -j $%s' % ('i', device, chain_name)]
            self._add_rules_to_chain_v4v6('INPUT', jump_rule, comment=ic.INPUT_TO_SG)
            self._add_rules_to_chain_v4v6('FORWARD', jump_rule, comment=ic.SG_TO_VM_SG)

        if direction == constants.INGRESS_DIRECTION:
            jump_rule = ['-%s %s -j $%s' % ('o', device, chain_name)]
            self._add_rules_to_chain_v4v6('OUTPUT', jump_rule, comment=ic.INPUT_TO_SG)
            self._add_rules_to_chain_v4v6('FORWARD', jump_rule, comment=ic.SG_TO_VM_SG)

    def _add_rules_to_chain(self, chain_name, rules):
        # split groups by ip version
        rules = self._split_rules_by_remote_ips(rules)
        ipv4_rules, ipv6_rules = self._split_rules_by_ethertype(rules)
        ebtables_rules = self._convert_isoflat_to_ebtables_rules(ipv4_rules, 4)
        ebtables_rules += self._convert_isoflat_to_ebtables_rules(ipv6_rules, 6)
        # finally add the rules to the port chain for a given direction
        self._add_rules_to_chain_v4v6(chain_name, ebtables_rules)

    def _setup_chain(self, device, physical_network, rules, direction):
        chain_name = self._network_chain_name(physical_network, direction)
        self._add_chain(chain_name, device, direction)
        new_rules = [rule for rule in rules if rule['direction'] == direction]
        self._add_rules_to_chain(chain_name, new_rules)

    def _remove_chain(self, physical_network, direction):
        chain_name = self._network_chain_name(physical_network, direction)
        self._remove_chain_by_name_v4v6(chain_name)

    def _add_isoflat_chain_v4v6(self):
        self._add_chain_by_name_v4v6(ISOFLAT_CHAIN)

    def _add_fallback_chain_v4v6(self):
        """
        Accept all traffic by default.
        """
        self.ebtables.tables['filter'].add_chain('fallback')
        self.ebtables.tables['filter'].add_rule('fallback', '-j ACCEPT')

    def _add_rules_to_chain_v4v6(self, chain_name, rules, comment=None):
        for rule in rules:
            self.ebtables.tables['filter'].add_rule(chain_name, rule, comment=comment)

    @staticmethod
    def _ip_prefix_arg(direction, ip_prefix):
        if ip_prefix:
            if '/' not in ip_prefix:
                # we need to convert it into a prefix to match ebtables
                ip_prefix = c_utils.ip_to_cidr(ip_prefix)
            elif ip_prefix.endswith('/0'):
                # an allow for every address is not a constraint so
                # ebtables drops it
                return []
            return ['--%s' % direction, ip_prefix]
        return []

    @staticmethod
    def _protocol_arg(protocol, ip_version):
        ebtables_rule = []
        rule_protocol = n_const.IPTABLES_PROTOCOL_NAME_MAP.get(protocol, protocol)
        # protocol zero is a special case and requires no '-p'
        proto_arg_prefix = '--ip' if ip_version == 4 else '--ip6'
        ebtables_rule += ['-p', 'ipv4' if ip_version == 4 else 'ipv6']
        if rule_protocol:
            ebtables_rule = [proto_arg_prefix + '-proto', rule_protocol]
        return ebtables_rule

    @staticmethod
    def _port_arg(direction, protocol, port_range_min, port_range_max):
        args = []
        if port_range_min is None:
            return args

        protocol = n_const.IPTABLES_PROTOCOL_NAME_MAP.get(protocol, protocol)
        # TODO: can't filter icmp right now
        if protocol in ['ipv6-icmp']:
            protocol_type = 'icmpv6' if protocol == 'ipv6-icmp' else 'icmp'
            # Note(xuhanp): port_range_min/port_range_max represent
            # icmp type/code when protocol is icmp or icmpv6
            args += ['--%s-type' % protocol_type, '%s' % port_range_min]
            # icmp code can be 0 so we cannot use "if port_range_max" here
            if port_range_max is not None:
                args[-1] += '/%s' % port_range_max
        elif port_range_min == port_range_max:
            args += ['--%s' % direction, '%s' % (port_range_min,)]
        else:
            args += ['--%s' % direction, '%s:%s' % (port_range_min, port_range_max)]
        return args

    def _generate_protocol_and_port_args(self, rule, ip_version):
        args = self._protocol_arg(rule.get('protocol'), ip_version)
        port_arg_prefix = 'ip' if ip_version == 4 else 'ip6'
        port_arg_suffix = 'dport' if rule.get('direction') == constants.EGRESS_DIRECTION else 'sport'
        args += self._port_arg('%s-%s' % (port_arg_prefix, port_arg_suffix),
                               rule.get('protocol'),
                               rule.get('port_range_min'),
                               rule.get('port_range_max'))
        return args

    def _convert_to_ebtables_args(self, rule, ip_version):
        """
        Drop traffic matched by rules.
        """
        ip_arg_prefix = 'ip' if ip_version == 4 else 'ip6'
        ip_arg_suffix = 'dst' if rule.get('direction') == constants.EGRESS_DIRECTION else 'src'
        args = self._ip_prefix_arg('%s-%s' % (ip_arg_prefix, ip_arg_suffix), rule.get('remote_ip'))
        args += self._generate_protocol_and_port_args(rule, ip_version)
        args += ['-j DROP']
        return args

    def _convert_isoflat_to_ebtables_rules(self, isoflat_rules, ip_version):
        ebtables_rules = []
        seen_rules = set()
        for rule in isoflat_rules:
            args = self._convert_to_ebtables_args(rule, ip_version)
            if args:
                rule_command = ' '.join(args)
                if rule_command in seen_rules:
                    continue
                seen_rules.add(rule_command)
                ebtables_rules.append(rule_command)
        ebtables_rules += ['-j $fallback']
        return ebtables_rules

    @staticmethod
    def _split_rules_by_ethertype(isoflat_rules):
        ipv4_sg_rules = []
        ipv6_sg_rules = []
        for rule in isoflat_rules:
            if rule.get('ethertype') == constants.IPv4:
                ipv4_sg_rules.append(rule)
            elif rule.get('ethertype') == constants.IPv6:
                if rule.get('protocol') == 'icmp':
                    rule['protocol'] = 'ipv6-icmp'
                ipv6_sg_rules.append(rule)
        return ipv4_sg_rules, ipv6_sg_rules

    @staticmethod
    def _split_rules_by_remote_ips(isoflat_rules):
        rules = []
        for rule in isoflat_rules:
            for remote_ip in rule['remote_ips']:
                new_rule = dict(rule)
                new_rule['remote_ip'] = remote_ip
                rules.append(new_rule)
        return rules

    def init_firewall(self):
        pass

    def update_firewall_rules(self, device, physical_network, isoflat_rules):
        self._remove_chain(physical_network, constants.INGRESS_DIRECTION)
        self._remove_chain(physical_network, constants.EGRESS_DIRECTION)
        self._setup_chain(device, physical_network, isoflat_rules, constants.INGRESS_DIRECTION)
        self._setup_chain(device, physical_network, isoflat_rules, constants.EGRESS_DIRECTION)
        self.ebtables.apply()
