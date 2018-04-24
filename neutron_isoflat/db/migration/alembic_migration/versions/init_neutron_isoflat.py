import sqlalchemy as sa
from alembic import op
from neutron_lib import constants
from neutron_lib.db import constants as db_const

# revision identifiers, used by Alembic.
revision = 'init_neutron_isoflat'
down_revision = None


direction_types = sa.Enum(constants.INGRESS_DIRECTION, constants.EGRESS_DIRECTION,
                          name='isoflatrule_direction')


def upgrade():
    op.create_table(
        'isoflatrules',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=255), nullable=True, index=True),
        sa.Column('network_id', sa.String(length=36), nullable=False),
        sa.Column('direction', direction_types, nullable=False),
        sa.Column('protocol', sa.String(length=40), nullable=True),
        sa.Column('port_range_min', sa.Integer(), nullable=True),
        sa.Column('port_range_max', sa.Integer(), nullable=True),
        sa.Column('ethertype', sa.String(length=40), nullable=True),
        sa.Column('remote_ip', sa.String(length=255), nullable=True),
        sa.Column('remote_network_id', sa.String(db_const.UUID_FIELD_SIZE),
                  sa.ForeignKey("networks.id", ondelete="CASCADE"),
                  nullable=True),
        sa.Column('standard_attr_id', sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(['network_id'], ['networks.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['remote_network_id'], ['networks.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['standard_attr_id'], ['standardattributes.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'))
