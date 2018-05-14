"""empty message

Revision ID: 0c35f58a2e73
Revises: 55c791eac900
Create Date: 2018-03-31 00:03:50.296931

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0c35f58a2e73'
down_revision = '55c791eac900'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('appconfig', schema=None) as batch_op:
        batch_op.add_column(sa.Column('attribute_oid', sa.Integer(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('appconfig', schema=None) as batch_op:
        batch_op.drop_column('attribute_oid')

    # ### end Alembic commands ###