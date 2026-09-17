import uuid
from collections.abc import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings

engine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Plain per-request session. Later phases wrap this with the tenant GUC."""
    async with AsyncSessionLocal() as session:
        yield session


async def use_tenant(db: AsyncSession, tenant_id: uuid.UUID) -> None:
    """Tell Postgres which clinic this transaction is acting for.

    The third argument to set_config is `is_local`. True makes this the
    function form of SET LOCAL: the setting belongs to the current transaction
    and is dropped at commit or rollback, whatever the connection pool does
    with the connection afterwards.

    Plain SET would outlive the transaction and ride the pooled connection
    into whoever borrows it next — which is the whole point of doing it this
    way, and is demonstrated in docs/rls-pooling-bug.md.

    set_config rather than `SET LOCAL app.tenant_id = ...` because SET does
    not accept bind parameters, and building that string by hand is how you
    end up with an injection hole in the one place meant to prevent leaks.
    """
    await db.execute(
        text("SELECT set_config('app.tenant_id', :tenant_id, true)"),
        {"tenant_id": str(tenant_id)},
    )
