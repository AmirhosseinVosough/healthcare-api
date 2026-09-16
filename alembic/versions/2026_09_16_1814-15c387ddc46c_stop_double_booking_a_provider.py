"""stop double booking a provider

Revision ID: 15c387ddc46c
Revises: 20ba22d4f737
Create Date: 2026-09-16 18:14:56.415356

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '15c387ddc46c'
down_revision: Union[str, Sequence[str], None] = '20ba22d4f737'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Refuse two overlapping appointments for the same provider.

    Written by hand: Alembic's autogenerate does not detect EXCLUDE
    constraints, so it produced an empty migration for this. It does not try
    to drop them either, so later autogenerate runs leave this alone.
    """
    # gist indexes cannot compare uuids with = on their own. btree_gist adds
    # that, which is what lets one index mix plain equality with range overlap.
    op.execute("CREATE EXTENSION IF NOT EXISTS btree_gist")

    op.execute(
        """
        ALTER TABLE appointments
        ADD CONSTRAINT no_provider_double_booking
        EXCLUDE USING gist (
            tenant_id WITH =,
            provider_id WITH =,
            tstzrange(scheduled_start, scheduled_end) WITH &&
        ) WHERE (status <> 'cancelled')
        """
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE appointments DROP CONSTRAINT no_provider_double_booking"
    )
    # btree_gist is left installed on purpose. Dropping an extension other
    # things may be leaning on is not this migration's business.
