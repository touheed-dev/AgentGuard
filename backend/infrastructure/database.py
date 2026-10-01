import os
from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine


def database_url() -> str:
    return os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./agentguard-phase2.db")


def create_engine(url: str | None = None) -> AsyncEngine:
    return create_async_engine(url or database_url(), future=True, pool_pre_ping=True)


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def session_scope(factory: async_sessionmaker[AsyncSession]) -> AsyncIterator[AsyncSession]:
    async with factory() as session:
        yield session
