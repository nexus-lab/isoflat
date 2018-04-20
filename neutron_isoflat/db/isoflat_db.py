from neutron.db import common_db_mixin as base_db
from neutron_lib.plugins import directory
from oslo_log import log as logging
from oslo_utils import uuidutils
from sqlalchemy.orm import exc

from neutron_isoflat.db.models.isoflat import IsoflatRule
from neutron_isoflat.extensions import isoflat

LOG = logging.getLogger(__name__)


class IsoflatDbMixin(isoflat.IsoflatPluginBase, base_db.CommonDbMixin):

    def _core_plugin(self):
        return directory.get_plugin()

    def _get_network_details(self, context, network_id):
        with context.session.begin(subtransactions=True):
            network = self._core_plugin().get_network(context, network_id)

        return network

    def _get_rule(self, context, id):
        try:
            return self._get_by_id(context, IsoflatRule, id)
        except exc.NoResultFound:
            raise isoflat.IsoflatRuleNotFound(rule_id=id)

    def _make_isoflat_rule_dict(self, rule, fields=None):
        res = {
            'id': rule['id'],
            'project_id': rule['project_id'],
            'network_id': rule['network_id'],
            'direction': rule['direction'],
            'protocol': rule['protocol'],
            'port_range_min': rule['port_range_min'],
            'port_range_max': rule['port_range_max'],
            'ethertype': rule['ethertype'],
            'remote_ip': rule['remote_ip'],
            'remote_network_id': rule['remote_network_id'],
            'description': rule['description'],
        }
        return self._fields(res, fields)

    def create_rule(self, context, rule):
        LOG.debug("IsoflatDbMixin.create_rule() called")
        r = rule['rule']
        with context.session.begin(subtransactions=True):
            isoflat_rule = IsoflatRule(
                id=uuidutils.generate_uuid(),
                project_id=r['project_id'],
                network_id=r['network_id'],
                direction=r['direction'],
                protocol=r['protocol'],
                port_range_min=r['port_range_min'],
                port_range_max=r['port_range_max'],
                ethertype=r['ethertype'],
                remote_ip=r['remote_ip'],
                remote_network_id=r['remote_network_id'],
                description=r['description']
            )
            LOG.debug(isoflat_rule)
            context.session.add(isoflat_rule)
        return self._make_isoflat_rule_dict(isoflat_rule)

    def delete_rule(self, context, id):
        LOG.debug("IsoflatDbMixin.delete_rule() called")
        rule = self._get_rule(context, id)
        context.session.delete(rule)

    def get_rule(self, context, id, fields=None):
        LOG.debug("IsoflatDbMixin.get_rule() called")
        t_s = self._get_rule(context, id)
        return self._make_isoflat_rule_dict(t_s, fields)

    def get_rules(self, context, filters=None, fields=None,
                  sorts=None, limit=None, marker=None,
                  page_reverse=False):
        LOG.debug("IsoflatDbMixin.get_rules() called")
        return self._get_collection(context, IsoflatRule,
                                    self._make_isoflat_rule_dict,
                                    filters=filters, fields=fields, sorts=sorts,
                                    limit=limit, marker_obj=marker, page_reverse=page_reverse)
