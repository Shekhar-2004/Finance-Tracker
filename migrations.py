"""Add user authentication and relationships

Revision ID: xyz123
Revises: abc456
Create Date: 2024-02-28 19:45:00.000000

"""
from alembic import op
import sqlalchemy as sa

def upgrade():
    # Create users table
    op.create_table(
        'user',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(80), nullable=False),
        sa.Column('password_hash', sa.String(120), nullable=False),
        sa.Column('email', sa.String(120), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('username'),
        sa.UniqueConstraint('email')
    )
    
    # Add user_id to existing tables
    op.add_column('budget', sa.Column('user_id', sa.Integer()))
    op.add_column('expense', sa.Column('user_id', sa.Integer()))
    
    # Create foreign key constraints
    op.create_foreign_key(None, 'budget', 'user', ['user_id'], ['id'])
    op.create_foreign_key(None, 'expense', 'user', ['user_id'], ['id'])
    
    # Create unique constraint for budget
    op.create_unique_constraint(None, 'budget', ['user_id', 'month'])

def downgrade():
    # Remove constraints first
    op.drop_constraint(None, 'budget', type_='unique')
    op.drop_constraint(None, 'budget', type_='foreignkey')
    op.drop_constraint(None, 'expense', type_='foreignkey')
    
    # Remove columns
    op.drop_column('budget', 'user_id')
    op.drop_column('expense', 'user_id')
    
    # Drop users table
    op.drop_table('user') 