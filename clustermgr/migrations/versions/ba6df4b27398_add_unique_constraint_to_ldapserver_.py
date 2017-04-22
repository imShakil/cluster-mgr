"""add unique constraint to ldapserver hostname

Revision ID: ba6df4b27398
Revises: 16ad82eedbea
Create Date: 2017-04-22 19:01:23.387106

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ba6df4b27398'
down_revision = '16ad82eedbea'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('ldap_server') as batch_op:
        batch_op.create_unique_constraint("unique_hostname", ['hostname'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('ldap_server') as batch_op:
        batch_op.drop_constraint("unique_hostname", type_='unique')
    # ### end Alembic commands ###
