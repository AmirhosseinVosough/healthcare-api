"""row level security on users and appointments

Revision ID: f51637a07eb0
Revises: 15c387ddc46c
Create Date: 2026-09-17 17:06:12.391405

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f51637a07eb0"
down_revision: str | Sequence[str] | None = "15c387ddc46c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Make Postgres itself refuse rows belonging to another clinic.

    Written by hand; autogenerate does not see policies.

    The clinic is read from a setting attached to the database session, put
    there at the start of each request. A query that forgets its WHERE clause
    now returns nothing instead of another clinic's rows.

    NULLIF guards the cast: an unset setting reads as NULL and an empty one as
    the empty string, and ''::uuid would raise rather than simply match
    nothing. Unset means see nothing, which is the safe way round.
    """
    for table in ("users", "appointments"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        # ENABLE on its own does not apply to whoever owns the table, and the
        # app connects as the owner. Without FORCE the policy below would be
        # decoration.
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation ON {table}
            FOR ALL
            USING (
                tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
            )
            WITH CHECK (
                tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
            )
            """
        )


def downgrade() -> None:
    for table in ("users", "appointments"):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
