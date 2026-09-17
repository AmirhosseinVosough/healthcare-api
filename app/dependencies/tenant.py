"""Works out which clinic an unauthenticated request is talking about.

Only needed for /auth/register and /auth/login, where nobody is logged in yet.
Every request after that carries its clinic inside the signed token, where the
caller cannot touch it.
"""

from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import Tenant
from app.database.session import get_db, use_tenant


async def get_tenant(
    x_tenant_slug: Annotated[
        str,
        Header(
            alias="X-Tenant-Slug",
            description="Which clinic, e.g. riverside-clinic",
            examples=["riverside-clinic"],
        ),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Tenant:
    tenant = await db.scalar(
        select(Tenant).where(
            Tenant.slug == x_tenant_slug.strip().lower(),
            Tenant.is_active.is_(True),
        )
    )
    if tenant is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Unknown clinic"
        )

    # From here on this transaction can only see this clinic's rows, enforced
    # by Postgres rather than by remembering to write the right WHERE clause.
    await use_tenant(db, tenant.id)
    return tenant
