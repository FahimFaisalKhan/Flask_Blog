"""empty message

Revision ID: 288a4d0e2e4b
Revises: fdacce17ff5c
Create Date: 2022-08-21 12:33:52.866456

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '288a4d0e2e4b'
down_revision = 'fdacce17ff5c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user_final',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('email', sa.String(length=250), nullable=False),
    sa.Column('name', sa.String(length=150), nullable=False),
    sa.Column('password', sa.Text(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    schema='flask_blog'
    )
    op.create_table('blog_posts_final',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('author_id', sa.Integer(), nullable=True),
    sa.Column('title', sa.String(length=250), nullable=False),
    sa.Column('subtitle', sa.String(length=250), nullable=False),
    sa.Column('date', sa.String(length=1000), nullable=False),
    sa.Column('body', sa.Text(), nullable=False),
    sa.Column('img_url', sa.String(length=250), nullable=False),
    sa.ForeignKeyConstraint(['author_id'], ['flask_blog.user_final.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('title'),
    schema='flask_blog'
    )
    op.create_table('comments',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('commenter_id', sa.Integer(), nullable=True),
    sa.Column('comment_of_post', sa.Integer(), nullable=True),
    sa.Column('text', sa.Text(), nullable=False),
    sa.ForeignKeyConstraint(['comment_of_post'], ['flask_blog.blog_posts_final.title'], ),
    sa.ForeignKeyConstraint(['commenter_id'], ['flask_blog.user_final.id'], ),
    sa.PrimaryKeyConstraint('id'),
    schema='flask_blog'
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('comments', schema='flask_blog')
    op.drop_table('blog_posts_final', schema='flask_blog')
    op.drop_table('user_final', schema='flask_blog')
    # ### end Alembic commands ###
