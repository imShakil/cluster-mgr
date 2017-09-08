"""added name to ldapserver, ip to oxauth

Revision ID: 51eb2fa5452c
Revises: 43f25b682d03
Create Date: 2017-09-08 10:59:08.660257

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '51eb2fa5452c'
down_revision = '43f25b682d03'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('ldap_server', sa.Column('name', sa.String(length=50), nullable=True))
    op.add_column('oxauth_server', sa.Column('ip', sa.String(length=45), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table("oxauth_server") as batch_op:
        batch_op.drop_column('ip')

    with op.batch_alter_table("ldap_server") as batch_op:
        batch_op.drop_column('name')
    # ### end Alembic commands ###