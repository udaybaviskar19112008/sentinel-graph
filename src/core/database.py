"""Async SQLAlchemy engine and sessions for the scan database (``DATABASE_URL``)."""

from collections.abc import AsyncIterator
from functools import lru_cache
from typing import Any

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from src.core.config import get_settings
from src.models.db_models import Base


def make_engine(url: str, **engine_options: Any) -> AsyncEngine:
    """An async engine; on SQLite, foreign keys (and ON DELETE CASCADE) are switched on."""
    engine = create_async_engine(url, **engine_options)
    if engine.dialect.name == "sqlite":
        # SQLite ignores foreign keys unless every connection opts in.
        @event.listens_for(engine.sync_engine, "connect")
        def _enable_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    return make_engine(get_settings().DATABASE_URL)


@lru_cache(maxsize=1)
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    # expire_on_commit=False: records stay readable after commit, e.g. to serialise a response.
    return async_sessionmaker(get_engine(), expire_on_commit=False)


async def init_db(engine: AsyncEngine | None = None) -> None:
    """Create any missing tables."""
    async with (engine or get_engine()).begin() as connection:
        await connection.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Dispose the process-wide engine (app shutdown, or before switching DATABASE_URL)."""
    if get_engine.cache_info().currsize:
        await get_engine().dispose()
    get_sessionmaker.cache_clear()
    get_engine.cache_clear()


async def get_db_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: one session per request; uncommitted work is rolled back on exit."""
    async with get_sessionmaker()() as session:
        yield session
