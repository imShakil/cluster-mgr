"""add jks remote path column

Revision ID: 16ad82eedbea
Revises: 4e676791e227
Create Date: 2017-04-13 15:58:54.421105

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '16ad82eedbea'
down_revision = '4e676791e227'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('keyrotation', sa.Column('jks_remote_path', sa.String(length=255), nullable=True, server_default="/opt/gluu-server-3.0.1/etc/certs/oxauth-keys.jks"))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('keyrotation') as batch_op:
        batch_op.drop_column('jks_remote_path')
    # ### end Alembic commands ###