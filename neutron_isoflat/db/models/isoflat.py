import sqlalchemy as sa
from neutron.db import standard_attr
from neutron.db.models_v2 import Network
from neutron_lib import constants
from neutron_lib.db import constants as db_const
from neutron_lib.db import model_base
from sqlalchemy import orm


class IsoflatRule(standard_attr.HasStandardAttributes, model_base.BASEV2, model_base.HasId,
                  model_base.HasProjectNoIndex):
    """Represents a v2 neutron isoflat rule."""

    __tablename__ = 'isoflatrules'
    network_id = sa.Column(sa.String(length=db_const.UUID_FIELD_SIZE),
                           sa.ForeignKey("networks.id", ondelete="CASCADE"),
                           nullable=False)
    direction = sa.Column(sa.Enum(constants.INGRESS_DIRECTION, constants.EGRESS_DIRECTION,
                                  name='isoflatrules_direction'),
                          nullable=False)
    protocol = sa.Column(sa.String(length=40))
    port_range_min = sa.Column(sa.Integer())
    port_range_max = sa.Column(sa.Integer())
    ethertype = sa.Column(sa.String(length=40))
    remote_ip = sa.Column(sa.String(length=255))
    remote_network_id = sa.Column(sa.String(length=db_const.UUID_FIELD_SIZE),
                                  sa.ForeignKey("networks.id", ondelete="CASCADE"),
                                  nullable=True)

    revises_on_change = ('network',)
    network = orm.relationship(
        Network, load_on_pending=True,
        primaryjoin="Network.id==IsoflatRule.network_id")
    remote_network = orm.relationship(
        Network,
        primaryjoin="Network.id==IsoflatRule.remote_network_id")
    api_collections = ['isoflat_rules']
