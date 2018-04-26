import collections
import contextlib
import difflib
import re

from neutron.agent.linux import ip_lib
from neutron.agent.linux import iptables_comments as ic
from neutron.agent.linux import utils as linux_utils
from neutron.agent.linux.iptables_manager import binary_name
from neutron.agent.linux.iptables_manager import comment_rule
from neutron.agent.linux.iptables_manager import get_chain_name
from neutron_lib import exceptions as qexceptions
from neutron_lib.utils import runtime
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils

from neutron_isoflat._i18n import _

LOG = logging.getLogger(__name__)

# RESOURCE_PROBLEM in include/xtables.h
XTABLES_RESOURCE_PROBLEM_CODE = 4

# xlock wait interval, in microseconds
XLOCK_WAIT_INTERVAL = 200000

# Number of ebtables rules to print before and after a rule that causes a
# a failure during ebtables-restore
EBTABLES_ERROR_LINES_OF_CONTEXT = 5


class EbTablesApplyException(qexceptions.NeutronException):
    def __init__(self, message=None):
        self.message = message
        super(EbTablesApplyException, self).__init__()


class EbtablesRule(object):
    """An ebtables rule.

    You shouldn't need to use this class directly, it's only used by
    EbtablesManager.
    """

    def __init__(self, chain, rule, wrap=True, top=False,
                 _binary_name=binary_name, tag=None, comment=None):
        self.chain = get_chain_name(chain, wrap)
        self.rule = rule
        self.wrap = wrap
        self.top = top
        self.wrap_name = _binary_name[:16]
        self.tag = tag
        self.comment = comment

    def __eq__(self, other):
        return ((self.chain == other.chain) and
                (self.rule == other.rule) and
                (self.top == other.top) and
                (self.wrap == other.wrap))

    def __ne__(self, other):
        return not self == other

    def __str__(self):
        if self.wrap:
            chain = '%s-%s' % (self.wrap_name, self.chain)
        else:
            chain = self.chain
        rule = '-A %s %s' % (chain, self.rule)
        # If self.rule is '' the above will cause a trailing space, which
        # could cause us to not match on save/restore, so strip it now.
        return comment_rule(rule.strip(), self.comment)


class EbtablesTable(object):
    """An ebtables table."""

    def __init__(self, _binary_name=binary_name):
        self.rules = []
        self.remove_rules = []
        self.chains = set()
        self.unwrapped_chains = set()
        self.remove_chains = set()
        self.wrap_name = _binary_name[:16]

    def add_chain(self, name, wrap=True):
        """Adds a named chain to the table.

        The chain name is wrapped to be unique for the component creating
        it, so different components of Nova can safely create identically
        named chains without interfering with one another.

        At the moment, its wrapped name is <binary name>-<chain name>,
        so if neutron-openvswitch-agent creates a chain named 'OUTPUT',
        it'll actually end up being named 'neutron-openvswi-OUTPUT'.

        """
        name = get_chain_name(name, wrap)
        if wrap:
            self.chains.add(name)
        else:
            self.unwrapped_chains.add(name)

    def _select_chain_set(self, wrap):
        if wrap:
            return self.chains
        else:
            return self.unwrapped_chains

    def remove_chain(self, name, wrap=True):
        """Remove named chain.

        This removal "cascades". All rule in the chain are removed, as are
        all rules in other chains that jump to it.

        If the chain is not found, this is merely logged.

        """
        name = get_chain_name(name, wrap)
        chain_set = self._select_chain_set(wrap)

        if name not in chain_set:
            LOG.debug('Attempted to remove chain %s which does not exist',
                      name)
            return

        chain_set.remove(name)

        if not wrap:
            # non-wrapped chains and rules need to be dealt with specially,
            # so we keep a list of them to be iterated over in apply()
            self.remove_chains.add(name)

            # Add rules to remove that have a matching chain name or
            # a matching jump chain
            jump_snippet = '-j %s' % name
            self.remove_rules += [str(r) for r in self.rules
                                  if r.chain == name or jump_snippet in r.rule]
        else:
            jump_snippet = '-j %s-%s' % (self.wrap_name, name)

        # Remove rules from list that have a matching chain name or
        # a matching jump chain
        self.rules = [r for r in self.rules
                      if r.chain != name and jump_snippet not in r.rule]

    def add_rule(self, chain, rule, wrap=True, top=False, tag=None,
                 comment=None):
        """Add a rule to the table.

        This is just like what you'd feed to ebtables, just without
        the '-A <chain name>' bit at the start.

        However, if you need to jump to one of your wrapped chains,
        prepend its name with a '$' which will ensure the wrapping
        is applied correctly.

        """
        chain = get_chain_name(chain, wrap)
        if wrap and chain not in self.chains:
            raise LookupError(_('Unknown chain: %r') % chain)

        if '$' in rule:
            rule = ' '.join(
                self._wrap_target_chain(e, wrap) for e in rule.split(' '))

        self.rules.append(EbtablesRule(chain, rule, wrap, top, self.wrap_name,
                                       tag, comment))

    def _wrap_target_chain(self, s, wrap):
        if s.startswith('$'):
            s = ('%s-%s' % (self.wrap_name, get_chain_name(s[1:], wrap)))

        return s

    def remove_rule(self, chain, rule, wrap=True, top=False, comment=None):
        """Remove a rule from a chain.

        Note: The rule must be exactly identical to the one that was added.
        You cannot switch arguments around like you can with the ebtables
        CLI tool.

        """
        chain = get_chain_name(chain, wrap)
        try:
            if '$' in rule:
                rule = ' '.join(
                    self._wrap_target_chain(e, wrap) for e in rule.split(' '))

            self.rules.remove(EbtablesRule(chain, rule, wrap, top,
                                           self.wrap_name,
                                           comment=comment))
            if not wrap:
                self.remove_rules.append(str(EbtablesRule(chain, rule, wrap,
                                                          top, self.wrap_name,
                                                          comment=comment)))
        except ValueError:
            LOG.warning('Tried to remove rule that was not there:'
                        ' %(chain)r %(rule)r %(wrap)r %(top)r',
                        {'chain': chain, 'rule': rule,
                         'top': top, 'wrap': wrap})

    def _get_chain_rules(self, chain, wrap):
        chain = get_chain_name(chain, wrap)
        return [rule for rule in self.rules
                if rule.chain == chain and rule.wrap == wrap]

    def empty_chain(self, chain, wrap=True):
        """Remove all rules from a chain."""
        chained_rules = self._get_chain_rules(chain, wrap)
        for rule in chained_rules:
            self.rules.remove(rule)

    def clear_rules_by_tag(self, tag):
        if not tag:
            return
        rules = [rule for rule in self.rules if rule.tag == tag]
        for rule in rules:
            self.rules.remove(rule)


class EbtablesManager(object):
    """
    Wrapper for ebtables.
    """

    # Flag to denote we've already tried and used -w successfully, so don't
    # run ebtables-restore without it.
    use_table_lock = False

    def __init__(self, _execute=None, state_less=False, namespace=None, _binary_name=binary_name):
        if _execute:
            self.execute = _execute
        else:
            self.execute = linux_utils.execute

        self.namespace = namespace
        self.ebtables_apply_deferred = False
        self.wrap_name = _binary_name[:16]

        self.tables = {
            'filter': EbtablesTable(_binary_name=self.wrap_name),
            'broute': EbtablesTable(_binary_name=self.wrap_name)
        }

        # Add a neutron-filter-top chain. It's intended to be shared
        # among the various neutron components. It sits at the very top
        # of FORWARD and OUTPUT.
        self.tables['filter'].add_chain('neutron-filter-top', wrap=False)
        self.tables['filter'].add_rule('FORWARD', '-j neutron-filter-top',
                                       wrap=False, top=True)
        self.tables['filter'].add_rule('OUTPUT', '-j neutron-filter-top',
                                       wrap=False, top=True)

        self.tables['filter'].add_chain('local')
        self.tables['filter'].add_rule('neutron-filter-top', '-j $local',
                                       wrap=False)

        # Wrap the built-in chains
        builtin_chains = {
            'filter': ['INPUT', 'OUTPUT', 'FORWARD'],
            'broute': ['BROUTING']
        }
        self._configure_builtin_chains(builtin_chains)

        if not state_less:
            self.initialize_nat_table()

    def initialize_nat_table(self):
        self.tables.update(
            {'nat': EbtablesTable(_binary_name=self.wrap_name)})

        builtin_chains = {'nat': ['PREROUTING', 'OUTPUT', 'POSTROUTING']}
        self._configure_builtin_chains(builtin_chains)

        # Add a neutron-postrouting-bottom chain. It's intended to be
        # shared among the various neutron components. We set it as the
        # last chain of POSTROUTING chain.
        self.tables['nat'].add_chain('neutron-postrouting-bottom', wrap=False)
        self.tables['nat'].add_rule(
            'POSTROUTING', '-j neutron-postrouting-bottom', wrap=False)

        # We add a snat chain to the shared neutron-postrouting-bottom
        # chain so that it's applied last.
        self.tables['nat'].add_chain('snat')
        self.tables['nat'].add_rule('neutron-postrouting-bottom',
                                    '-j $snat', wrap=False,
                                    comment=ic.SNAT_OUT)

        # And then we add a float-snat chain and jump to first thing in
        # the snat chain.
        self.tables['nat'].add_chain('float-snat')
        self.tables['nat'].add_rule('snat', '-j $float-snat')

    def _configure_builtin_chains(self, builtin_chains):
        for table, chains in builtin_chains.items():
            for chain in chains:
                self.tables[table].add_chain(chain)
                self.tables[table].add_rule(chain, '-j $%s' %
                                            chain, wrap=False)

    def get_chain(self, table, chain, wrap=True):
        try:
            requested_table = self.tables[table]
        except KeyError:
            return []
        return requested_table._get_chain_rules(chain, wrap)

    def is_chain_empty(self, table, chain, wrap=True):
        return not self.get_chain(table, chain, wrap)

    @contextlib.contextmanager
    def defer_apply(self):
        """Defer apply context."""
        self.defer_apply_on()
        try:
            yield
        finally:
            try:
                self.defer_apply_off()
            except EbTablesApplyException:
                # already in the format we want, just reraise
                raise
            except Exception:
                msg = _('Failure applying ebtables rules')
                LOG.exception(msg)
                raise EbTablesApplyException(msg)

    def defer_apply_on(self):
        self.ebtables_apply_deferred = True

    def defer_apply_off(self):
        self.ebtables_apply_deferred = False
        self._apply()

    def apply(self):
        if self.ebtables_apply_deferred:
            return

        return self._apply()

    def _apply(self):
        lock_name = 'ebtables'
        if self.namespace:
            lock_name += '-' + self.namespace

        with lockutils.lock(lock_name, runtime.SYNCHRONIZED_PREFIX, True):
            first = self._apply_synchronized()
            if not cfg.CONF.AGENT.debug_iptables_rules:
                return first
            second = self._apply_synchronized()
            if second:
                msg = (_("Ebtables Rules did not converge. Diff: %s") %
                       '\n'.join(second))
                LOG.error(msg)
                raise EbTablesApplyException(msg)
            return first

    @property
    def xlock_wait_time(self):
        # give agent some time to report back to server
        return str(int(cfg.CONF.AGENT.report_interval / 3.0))

    def _do_run_restore(self, args, commands, lock=False):
        args = args[:]
        if lock:
            args += ['-w', self.xlock_wait_time, '-W', XLOCK_WAIT_INTERVAL]
        try:
            kwargs = {} if lock else {'log_fail_as_error': False}
            self.execute(args, process_input='\n'.join(commands),
                         run_as_root=True, **kwargs)
        except RuntimeError as error:
            return error

    def _run_restore(self, args, commands):
        # If we've already tried and used -w successfully, don't
        # run ebtables-restore without it.
        if self.use_table_lock:
            return self._do_run_restore(args, commands, lock=True)

        err = self._do_run_restore(args, commands)
        if (isinstance(err, linux_utils.ProcessExecutionError) and
                err.returncode == XTABLES_RESOURCE_PROBLEM_CODE):
            err = self._do_run_restore(args, commands, lock=True)
            if not err:
                self.__class__.use_table_lock = True
        return err

    @staticmethod
    def _log_restore_err(err, commands):
        try:
            line_no = int(re.search('ebtables-restore: line ([0-9]+?)', str(err)).group(1))
            context = EBTABLES_ERROR_LINES_OF_CONTEXT
            log_start = max(0, line_no - context)
            log_end = line_no + context
        except AttributeError:
            # line error wasn't found, print all lines instead
            log_start = 0
            log_end = len(commands)
        log_lines = ('%7d. %s' % (idx, l)
                     for idx, l in enumerate(
            commands[log_start:log_end],
            log_start + 1)
                     )
        LOG.error("EbtablesManager.apply failed to apply the "
                  "following set of ebtables rules:\n%s",
                  '\n'.join(log_lines))

    def _apply_synchronized(self):
        """Apply the current in-memory set of ebtables rules.

        This will create a diff between the rules from the previous runs
        and replace them with the current set of rules.
        This happens atomically, thanks to ebtables-restore.

        Returns a list of the changes that were sent to ebtables-save.
        """
        s = [('ebtables', self.tables)]
        all_commands = []  # variable to keep track all commands for return val
        for cmd, tables in s:
            args = ['%s-save' % (cmd,)]
            if self.namespace:
                args = ['ip', 'netns', 'exec', self.namespace] + args
            try:
                save_output = self.execute(args, run_as_root=True)
            except RuntimeError:
                # We could be racing with a cron job deleting namespaces.
                # It is useless to try to apply ebtables rules over and
                # over again in a endless loop if the namespace does not
                # exist.
                with excutils.save_and_reraise_exception() as ctx:
                    if self.namespace and not ip_lib.network_namespace_exists(self.namespace):
                        ctx.reraise = False
                        LOG.error("Namespace %s was deleted during ebtables "
                                  "operations.", self.namespace)
                        return []
            all_lines = save_output.split('\n')
            commands = []
            # Traverse tables in sorted order for predictable dump output
            for table_name in sorted(tables):
                table = tables[table_name]
                # isolate the lines of the table we are modifying
                start, end = self._find_table(all_lines, table_name)
                old_rules = all_lines[start:end]
                # generate the new table state we want
                new_rules = self._modify_rules(old_rules, table)
                # generate the ebtables commands to get between the old state
                # and the new state
                changes = _generate_path_between_rules(old_rules, new_rules)
                if changes:
                    # if there are changes to the table, we put on the header
                    # and footer that ebtables-save needs
                    commands += (['# Generated by ebtables_manager'] +
                                 ['*%s' % table_name] + changes +
                                 ['COMMIT', '# Completed by ebtables_manager'])
            if not commands:
                continue
            all_commands += commands

            # always end with a new line
            commands.append('')

            args = ['%s-restore' % (cmd,), '-n']
            if self.namespace:
                args = ['ip', 'netns', 'exec', self.namespace] + args

            err = self._run_restore(args, commands)
            if err:
                self._log_restore_err(err, commands)
                raise err

        LOG.debug("EbtablesManager.apply completed with success. %d ebtables "
                  "commands were issued", len(all_commands))
        return all_commands

    @staticmethod
    def _find_table(lines, table_name):
        if len(lines) < 3:
            # length only <2 when fake ebtables
            return 0, 0
        try:
            start = lines.index('*%s' % table_name)
        except ValueError:
            # Couldn't find table_name
            LOG.debug('Unable to find table %s', table_name)
            return 0, 0
        end = lines[start:].index('COMMIT') + start + 1
        return start, end

    @staticmethod
    def _find_rules_index(lines):
        seen_chains = False
        rules_index = 0
        for rules_index, rule in enumerate(lines):
            if not seen_chains:
                if rule.startswith(':'):
                    seen_chains = True
            else:
                if not rule.startswith(':'):
                    break

        if not seen_chains:
            rules_index = 2

        return rules_index

    def _modify_rules(self, current_lines, table):
        # Chains are stored as sets to avoid duplicates.
        # Sort the output chains here to make their order predictable.
        unwrapped_chains = sorted(table.unwrapped_chains)
        chains = sorted(table.chains)
        rules = set(map(str, table.rules))

        # we don't want to change any rules that don't belong to us so we start
        # the new_filter with these rules
        # there are some rules that belong to us but they don't have the wrap
        # name. we want to add them in the right location in case our new rules
        # changed the order
        # (e.g. '-A FORWARD -j neutron-filter-top')
        new_filter = [line.strip() for line in current_lines
                      if self.wrap_name not in line and
                      line.strip() not in rules]

        # generate our list of chain names
        our_chains = [':%s-%s' % (self.wrap_name, name) for name in chains]

        # the unwrapped chains (e.g. neutron-filter-top) may already exist in
        # the new_filter since they aren't marked by the wrap_name so we only
        # want to add them if they arent' already there
        our_chains += [':%s' % name for name in unwrapped_chains
                       if not any(':%s' % name in s for s in new_filter)]

        our_top_rules = []
        our_bottom_rules = []
        for rule in table.rules:
            rule_str = str(rule)

            if rule.top:
                # rule.top == True means we want this rule to be at the top.
                our_top_rules += [rule_str]
            else:
                our_bottom_rules += [rule_str]

        our_chains_and_rules = our_chains + our_top_rules + our_bottom_rules

        # locate the position immediately after the existing chains to insert
        # our chains and rules
        rules_index = self._find_rules_index(new_filter)
        new_filter[rules_index:rules_index] = our_chains_and_rules

        def _weed_out_removes(line):
            # remove any rules or chains from the filter that were slated
            # for removal
            if line.startswith(':'):
                chain = line[1:]
                if chain in table.remove_chains:
                    table.remove_chains.remove(chain)
                    return False
            else:
                if line in table.remove_rules:
                    table.remove_rules.remove(line)
                    return False
            # Leave it alone
            return True

        seen_lines = set()

        # TODO(kevinbenton): remove this function and the next one. They are
        # just oversized brooms to sweep bugs under the rug!!! We generate the
        # rules and we shouldn't be generating duplicates.
        def _weed_out_duplicates(line):
            if line in seen_lines:
                thing = 'chain' if line.startswith(':') else 'rule'
                LOG.warning("Duplicate ebtables %(thing)s detected. This "
                            "may indicate a bug in the ebtables "
                            "%(thing)s generation code. Line: %(line)s",
                            {'thing': thing, 'line': line})
                return False
            seen_lines.add(line)
            # Leave it alone
            return True

        new_filter.reverse()
        new_filter = [line for line in new_filter
                      if _weed_out_duplicates(line) and
                      _weed_out_removes(line)]
        new_filter.reverse()

        # flush lists, just in case a rule or chain marked for removal
        # was already gone. (chains is a set, rules is a list)
        table.remove_chains.clear()
        table.remove_rules = []

        return new_filter


def _generate_path_between_rules(old_rules, new_rules):
    """Generates ebtables commands to get from old_rules to new_rules.

    This function diffs the two rule sets and then calculates the ebtables
    commands necessary to get from the old rules to the new rules using
    insert and delete commands.
    """
    old_by_chain = _get_rules_by_chain(old_rules)
    new_by_chain = _get_rules_by_chain(new_rules)
    old_chains, new_chains = set(old_by_chain.keys()), set(new_by_chain.keys())
    # all referenced chains should be declared at the top before rules.

    # NOTE(kevinbenton): sorting and grouping chains is for determinism in
    # tests. ebtables doesn't care about the order here
    statements = [':%s - [0:0]' % c for c in sorted(new_chains - old_chains)]
    sg_chains = []
    other_chains = []
    for chain in sorted(old_chains | new_chains):
        if '-sg-' in chain:
            sg_chains.append(chain)
        else:
            other_chains.append(chain)

    for chain in other_chains + sg_chains:
        statements += _generate_chain_diff_ebtables_commands(
            chain, old_by_chain[chain], new_by_chain[chain])
    # unreferenced chains get the axe
    for chain in sorted(old_chains - new_chains):
        statements += ['-X %s' % chain]
    return statements


def _get_rules_by_chain(rules):
    by_chain = collections.defaultdict(list)
    for line in rules:
        if line.startswith(':'):
            chain = line[1:].split(' ', 1)[0]
            # even though this is a default dict, we need to manually add
            # chains to ensure that ones without rules are included because
            # they might be a jump reference
            if chain not in by_chain:
                by_chain[chain] = []
        elif line.startswith('-A'):
            chain = line[3:].split(' ', 1)[0]
            by_chain[chain].append(line)
    return by_chain


def _generate_chain_diff_ebtables_commands(chain, old_chain_rules, new_chain_rules):
    # keep track of the old index because we have to insert rules
    # in the right position
    old_index = 1
    statements = []
    for line in difflib.ndiff(old_chain_rules, new_chain_rules):
        if line.startswith('?'):
            # skip ? because that's a guide string for intraline differences
            continue
        elif line.startswith('-'):  # line deleted
            statements.append('-D %s %d' % (chain, old_index))
            # since we are removing a line from the old rules, we
            # backup the index by 1
            old_index -= 1
        elif line.startswith('+'):  # line added
            # strip the chain name since we have to add it before the index
            rule = line[5:].split(' ', 1)[-1]
            # EbtableRule does not add trailing spaces for rules, so we
            # have to detect that here by making sure this chain isn't
            # referencing itself
            if rule == chain:
                rule = ''
            # rule inserted at this position
            statements.append('-I %s %d %s' % (chain, old_index, rule))
        old_index += 1
    return statements
