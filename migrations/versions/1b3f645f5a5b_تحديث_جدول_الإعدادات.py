"""تحديث جدول الإعدادات

Revision ID: 1b3f645f5a5b
Revises: 6afc327f4c72
Create Date: 2025-07-28 18:26:40.811467
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '1b3f645f5a5b'
down_revision = '6afc327f4c72'
branch_labels = None
depends_on = None


def upgrade():
    # ### تعديل جدول المتابعين مع تسمية القيود ###
    with op.batch_alter_table('followers', schema=None) as batch_op:
        batch_op.create_foreign_key('fk_followers_username', 'users', ['username'], ['username'])
        batch_op.create_foreign_key('fk_followers_followed_username', 'users', ['followed_username'], ['username'])

    # ### تعديل جدول الإعدادات ###
    with op.batch_alter_table('settings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('site_description', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('auto_verify_users', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('max_login_attempts', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('ban_duration_minutes', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('max_poem_length', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('post_interval_seconds', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('enable_likes', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('enable_comments', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('enable_saved', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('enable_notifications', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('enable_messages', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('instagram_url', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('twitter_url', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('contact_email', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('admin_panel_name', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('dark_mode', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('blocked_words', sa.Text(), nullable=True))

    # لا تحذف شيء من جدول المستخدمين هنا إذا لم يكن "followers" موجودًا مسبقًا.
    # تم تعليق هذا السطر لأنه يسبب خطأ إذا لم يكن العمود موجود أصلاً:
    # with op.batch_alter_table('users', schema=None) as batch_op:
    #     batch_op.drop_column('followers')


def downgrade():
    with op.batch_alter_table('settings', schema=None) as batch_op:
        batch_op.drop_column('blocked_words')
        batch_op.drop_column('dark_mode')
        batch_op.drop_column('admin_panel_name')
        batch_op.drop_column('contact_email')
        batch_op.drop_column('twitter_url')
        batch_op.drop_column('instagram_url')
        batch_op.drop_column('enable_messages')
        batch_op.drop_column('enable_notifications')
        batch_op.drop_column('enable_saved')
        batch_op.drop_column('enable_comments')
        batch_op.drop_column('enable_likes')
        batch_op.drop_column('post_interval_seconds')
        batch_op.drop_column('max_poem_length')
        batch_op.drop_column('ban_duration_minutes')
        batch_op.drop_column('max_login_attempts')
        batch_op.drop_column('auto_verify_users')
        batch_op.drop_column('site_description')

    with op.batch_alter_table('followers', schema=None) as batch_op:
        batch_op.drop_constraint('fk_followers_username', type_='foreignkey')
        batch_op.drop_constraint('fk_followers_followed_username', type_='foreignkey')