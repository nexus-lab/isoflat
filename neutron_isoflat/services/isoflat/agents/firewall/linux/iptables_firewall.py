from neutron.agent.linux import iptables_comments as ic
from neutron.agent.linux import iptables_manager
from neutron.common import constants as n_const
from neutron.common import ipv6_utils
from neutron.common import utils as c_utils
from neutron_lib import constants
from oslo_log import log as logging

from neutron_isoflat.services.isoflat.agents.firewall.linux import firewall

LOG = logging.getLogger(__name__)

ISOFLAT_CHAIN = 'isoflat-chain'
CHAIN_NAME_PREFIX = {constants.INGRESS_DIRECTION: 'i',
                     constants.EGRESS_DIRECTION: 'o'}
IPSET_DIRECTION = {constants.INGRESS_DIRECTION: 'src',
                   constants.EGRESS_DIRECTION: 'dst'}
IPTABLES_DIRECTION = {constants.INGRESS_DIRECTION: 'physdev-out',
                      constants.EGRESS_DIRECTION: 'physdev-in'}
comment_rule = iptables_manager.comment_rule


class IptablesFirewall(firewall.FirewallDriver):

    def __init__(self):
        self.iptables = iptables_manager.IptablesManager(state_less=True,
                                                         use_ipv6=ipv6_utils.is_enabled_and_bind_by_default())
        self._add_fallback_chain_v4v6()

    @staticmethod
    def _network_chain_name(physical_network, direction):
        return iptables_manager.get_chain_name(
            '%s%s' % (CHAIN_NAME_PREFIX[direction], physical_network))

    def _add_chain_by_name_v4v6(self, chain_name):
        self.iptables.ipv4['filter'].add_chain(chain_name)
        self.iptables.ipv6['filter'].add_chain(chain_name)

    def _remove_chain_by_name_v4v6(self, chain_name):
        self.iptables.ipv4['filter'].remove_chain(chain_name)
        self.iptables.ipv6['filter'].remove_chain(chain_name)

    def _add_chain(self, chain_name, device, direction):
        self._add_chain_by_name_v4v6(chain_name)

        jump_rule = ['-m physdev --%s %s --physdev-is-bridged '
                     '-j $%s' % (IPTABLES_DIRECTION[direction],
                                 device,
                                 ISOFLAT_CHAIN)]
        self._add_rules_to_chain_v4v6('FORWARD', jump_rule, jump_rule,
                                      comment=ic.VM_INT_SG)

        # jump to the chain based on the device
        jump_rule = ['-m physdev --%s %s --physdev-is-bridged '
                     '-j $%s' % (IPTABLES_DIRECTION[direction],
                                 device,
                                 chain_name)]
        self._add_rules_to_chain_v4v6(ISOFLAT_CHAIN, jump_rule, jump_rule,
                                      comment=ic.SG_TO_VM_SG)

        if direction == constants.EGRESS_DIRECTION:
            self._add_rules_to_chain_v4v6('INPUT', jump_rule, jump_rule,
                                          comment=ic.INPUT_TO_SG)

    def _add_rules_to_chain(self, chain_name, rules):
        # split groups by ip version
        # for ipv4, iptables command is used
        # for ipv6, iptables6 command is used
        rules = self._split_rules_by_remote_ips(rules)
        ipv4_sg_rules, ipv6_sg_rules = self._split_rules_by_ethertype(rules)
        ipv4_iptables_rules = self._convert_isoflat_to_iptables_rules(ipv4_sg_rules)
        ipv6_iptables_rules = self._convert_isoflat_to_iptables_rules(ipv6_sg_rules)
        # finally add the rules to the port chain for a given direction
        self._add_rules_to_chain_v4v6(chain_name,
                                      ipv4_iptables_rules,
                                      ipv6_iptables_rules)

    def _setup_chain(self, device, rules, physical_network, direction):
        chain_name = self._network_chain_name(physical_network, direction)
        self._add_chain(chain_name, device, direction)
        new_rules = [rule for rule in rules if rule['direction'] == direction]
        self._add_rules_to_chain(chain_name, new_rules)

    def _remove_chain(self, physical_network, direction):
        chain_name = self._network_chain_name(physical_network, direction)
        self._remove_chain_by_name_v4v6(chain_name)

    def _add_fallback_chain_v4v6(self):
        """
        Accept all traffic by default.
        """
        self.iptables.ipv4['filter'].add_chain('isoflat-fallback')
        self.iptables.ipv4['filter'].add_rule('isoflat-fallback', '-j ACCEPT')
        self.iptables.ipv6['filter'].add_chain('isoflat-fallback')
        self.iptables.ipv6['filter'].add_rule('isoflat-fallback', '-j ACCEPT')

    def _add_rules_to_chain_v4v6(self, chain_name, ipv4_rules, ipv6_rules,
                                 comment=None):
        for rule in ipv4_rules:
            self.iptables.ipv4['filter'].add_rule(chain_name, rule, comment=comment)
        for rule in ipv6_rules:
            self.iptables.ipv6['filter'].add_rule(chain_name, rule, comment=comment)

    @staticmethod
    def _allow_established():
        # Allow established connections
        return comment_rule('-m state --state RELATED,ESTABLISHED -j RETURN',
                            comment=ic.ALLOW_ASSOC)

    @staticmethod
    def _ip_prefix_arg(direction, ip_prefix):
        if ip_prefix:
            if '/' not in ip_prefix:
                # we need to convert it into a prefix to match iptables
                ip_prefix = c_utils.ip_to_cidr(ip_prefix)
            elif ip_prefix.endswith('/0'):
                # an allow for every address is not a constraint so
                # iptables drops it
                return []
            return ['-%s' % direction, ip_prefix]
        return []

    @staticmethod
    def _protocol_arg(protocol, is_port):
        iptables_rule = []
        rule_protocol = n_const.IPTABLES_PROTOCOL_NAME_MAP.get(protocol, protocol)
        # protocol zero is a special case and requires no '-p'
        if rule_protocol:
            iptables_rule = ['-p', rule_protocol]

            if is_port and rule_protocol in constants.IPTABLES_PROTOCOL_MAP:
                # iptables adds '-m protocol' when the port number is specified
                iptables_rule += ['-m', constants.IPTABLES_PROTOCOL_MAP[rule_protocol]]
        return iptables_rule

    @staticmethod
    def _port_arg(direction, protocol, port_range_min, port_range_max):
        args = []
        if port_range_min is None:
            return args

        protocol = n_const.IPTABLES_PROTOCOL_NAME_MAP.get(protocol, protocol)
        if protocol in ['icmp', 'ipv6-icmp']:
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
            args += ['-m', 'multiport', '--%ss' % direction,
                     '%s:%s' % (port_range_min, port_range_max)]
        return args

    def _generate_protocol_and_port_args(self, rule):
        is_port = rule.get('port_range_min') is not None
        args = self._protocol_arg(rule.get('protocol'), is_port)
        args += self._port_arg('dport' if rule.get('direction') == 'egress' else 'sport',
                               rule.get('protocol'),
                               rule.get('port_range_min'),
                               rule.get('port_range_max'))
        return args

    def _convert_isoflat_to_iptables_args(self, rule):
        """
        Drop traffic matched by rules.
        """
        args = self._ip_prefix_arg('d', rule.get('remote_ip'))
        args += self._generate_protocol_and_port_args(rule)
        args += ['-j DROP']
        return args

    def _convert_isoflat_to_iptables_rules(self, isoflat_rules):
        iptables_rules = [self._allow_established()]
        seen_rules = set()
        for rule in isoflat_rules:
            args = self._convert_isoflat_to_iptables_args(rule)
            if args:
                rule_command = ' '.join(args)
                if rule_command in seen_rules:
                    continue
                seen_rules.add(rule_command)
                iptables_rules.append(rule_command)
        iptables_rules += [comment_rule('-m state --state ' 'INVALID -j DROP',
                                        comment=ic.INVALID_DROP)]
        iptables_rules += [comment_rule('-j $isoflat-fallback',
                                        comment=ic.UNMATCHED)]
        return iptables_rules

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
            for remote_ip in rule['remote_ip']:
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
        self.iptables.apply()
