"""
Database Connection Module
--------------------------
This module establishes the database connection, manages sessions,
and provides dependency injection for FastAPI routes.

Key Components:
- `get_async_engine()`: Lazy-initialised async engine (test-friendly).
- `get_engine()`: Lazy-initialised sync engine (test-friendly).
- `async_engine`: Module-level async engine (lazy proxy).
- `engine`: Module-level sync engine (lazy proxy).
- `AsyncSessionLocal`: Async session factory for FastAPI routes.
- `SessionLocal`: Sync session factory for background tasks/migrations.
- `get_db()`: FastAPI dependency for database sessions.
- `reset_engine()`: Dispose and recreate engines (for test teardown).
- `log_sql_execute()`: Logs executed SQL queries.
"""

import os
from collections.abc import AsyncGenerator, Generator
from typing import Annotated

from fastapi import Depends
from sqlalchemy import event as sa_event, Engine
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool, QueuePool, SingletonThreadPool, StaticPool, AsyncAdaptedQueuePool
from sqlmodel import Session, create_engine

from swx_core.config.settings import settings
from swx_core.middleware.logging_middleware import logger


_POOL_CLASS_MAP = {
    "QueuePool": QueuePool,
    "NullPool": NullPool,
    "SingletonThreadPool": SingletonThreadPool,
    "StaticPool": StaticPool,
}


def _resolve_pool_class():
    cls = _POOL_CLASS_MAP.get(settings.DB_POOL_CLASS)
    if cls is None:
        raise ValueError(
            f"Unknown DB_POOL_CLASS '{settings.DB_POOL_CLASS}'. "
            f"Choose from: {', '.join(_POOL_CLASS_MAP)}"
        )
    return cls


def _async_database_url() -> str:
    if settings.TESTING and settings.TEST_DATABASE_URL:
        url = settings.TEST_DATABASE_URL
        if url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
        elif url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql+asyncpg://", 1)
        return url
    return str(settings.ASYNC_SQLALCHEMY_DATABASE_URI)


def _sync_database_url() -> str:
    if settings.TESTING and settings.TEST_DATABASE_URL:
        return settings._strip_async_drivers(settings.TEST_DATABASE_URL)
    return str(settings.SQLALCHEMY_DATABASE_URI)


def _build_connect_args() -> dict[str, object]:
    connect_args: dict[str, object] = {}
    if (
        settings.DB_STATEMENT_TIMEOUT_MS > 0
        and settings.DATABASE_TYPE in ("postgres", "postgresql")
    ):
        connect_args["server_settings"] = {
            "statement_timeout": str(settings.DB_STATEMENT_TIMEOUT_MS),
        }
    return connect_args


_async_engine = None
_sync_engine = None
_async_engine_pid = None
_sync_engine_pid = None


def _post_fork_stale() -> bool:
    """True when the current process forked after the engines were built."""
    return _async_engine_pid not in (None, os.getpid()) or _sync_engine_pid not in (
        None,
        os.getpid(),
    )


def _reset_stale_post_fork_state() -> None:
    """Drop cached engines built in the parent process (fork-safe lifecycle)."""
    global _async_engine, _sync_engine, _async_engine_pid, _sync_engine_pid
    logger.warning("Stale DB engines from parent process discarded after fork (pid %d)", os.getpid())
    _async_engine = None
    _sync_engine = None
    _async_engine_pid = None
    _sync_engine_pid = None


def get_async_engine():
    global _async_engine, _async_engine_pid
    if _post_fork_stale():
        _reset_stale_post_fork_state()
        AsyncSessionLocal.invalidate()
        SessionLocal.invalidate()
    if _async_engine is None:
        pool_class = _resolve_pool_class()
        if pool_class is QueuePool:
            pool_class = AsyncAdaptedQueuePool
        pool_kwargs: dict[str, object] = {}
        if pool_class is not NullPool:
            pool_kwargs = {
                "pool_size": settings.DB_POOL_SIZE,
                "max_overflow": settings.DB_MAX_OVERFLOW,
                "pool_timeout": settings.DB_POOL_TIMEOUT,
                "pool_recycle": settings.DB_POOL_RECYCLE,
                "pool_use_lifo": settings.DB_POOL_USE_LIFO,
            }
        _async_engine = create_async_engine(
            _async_database_url(),
            echo=False,
            poolclass=pool_class,
            connect_args=_build_connect_args(),
            **pool_kwargs,
        )
    _async_engine_pid = os.getpid() if _async_engine_pid is None else _async_engine_pid
    return _async_engine


def get_engine():
    global _sync_engine, _sync_engine_pid
    if _post_fork_stale():
        _reset_stale_post_fork_state()
        AsyncSessionLocal.invalidate()
        SessionLocal.invalidate()
    if _sync_engine is None:
        pool_class = _resolve_pool_class()
        pool_kwargs: dict[str, object] = {}
        if pool_class is not NullPool:
            pool_kwargs = {
                "pool_size": settings.DB_SYNC_POOL_SIZE,
                "max_overflow": settings.DB_SYNC_MAX_OVERFLOW,
                "pool_recycle": settings.DB_POOL_RECYCLE,
            }
        _sync_engine = create_engine(
            _sync_database_url(),
            echo=False,
            poolclass=pool_class,
            connect_args=_build_connect_args(),
            **pool_kwargs,
        )
    _sync_engine_pid = os.getpid() if _sync_engine_pid is None else _sync_engine_pid
    return _sync_engine


def reset_engine():
    """Dispose existing engines, clear cached references and sessionmakers.

    Call this in test teardown to release connections and allow
    a fresh engine to be created on the next request. Also the
    documented hook for workers that need their own pool after fork —
    get_async_engine()/get_engine() additionally self-heal on pid change.
    """
    global _async_engine, _sync_engine, _async_engine_pid, _sync_engine_pid
    if _async_engine is not None:
        _async_engine.sync_engine.dispose()
        _async_engine = None
    if _sync_engine is not None:
        _sync_engine.dispose()
        _sync_engine = None
    _async_engine_pid = None
    _sync_engine_pid = None
    AsyncSessionLocal.invalidate()
    SessionLocal.invalidate()


class _LazyAsyncEngine:
    """Proxy that delegates all attribute access to the real async engine.

    This allows existing code that imports ``async_engine`` from
    ``swx_core.database.db`` to continue working without changes,
    while the actual engine is created lazily on first access.
    """

    def __getattr__(self, name):
        return getattr(get_async_engine(), name)

    def __repr__(self):
        eng = get_async_engine()
        return repr(eng)


class _LazySyncEngine:
    """Proxy that delegates all attribute access to the real sync engine."""

    def __getattr__(self, name):
        return getattr(get_engine(), name)

    def __repr__(self):
        eng = get_engine()
        return repr(eng)


async_engine = _LazyAsyncEngine()  # type: ignore[assignment]
engine = _LazySyncEngine()  # type: ignore[assignment]


def _build_async_session_factory():
    return async_sessionmaker(
        bind=get_async_engine(),
        class_=AsyncSession,
        expire_on_commit=False,
    )


def _build_sync_session_factory():
    return sessionmaker(
        bind=get_engine(),
        class_=Session,
        expire_on_commit=False,
    )


class _LazySessionFactory:
    """Callable session source that rebinds after reset_engine()/fork.

    ``AsyncSessionLocal()`` keeps working everywhere: each call builds a
    session from the *current* sessionmaker, and the sessionmaker itself
    is rebuilt lazily whenever ``invalidate()`` drops it (reset_engine,
    post-fork engine recreation).
    """

    __slots__ = ("_build", "_make")

    def __init__(self, build):
        self._build = build
        self._make = None

    def __call__(self):
        if self._make is None:
            self._make = self._build()
        return self._make()

    def invalidate(self) -> None:
        self._make = None


AsyncSessionLocal = _LazySessionFactory(_build_async_session_factory)
SessionLocal = _LazySessionFactory(_build_sync_session_factory)


def _fork_stale_check() -> None:
    """Recreate engines/sessions when they were built in a parent process."""
    if _post_fork_stale():
        _reset_stale_post_fork_state()
        AsyncSessionLocal.invalidate()
        SessionLocal.invalidate()


async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    _fork_stale_check()
    async with AsyncSessionLocal() as session:
        yield session


def get_db() -> Generator[Session, None, None]:
    _fork_stale_check()
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@sa_event.listens_for(Engine, "before_cursor_execute")
def log_sql_execute(conn, cursor, statement, parameters, context, executemany):
    logger.debug(f"SQL QUERY: {statement} | Params: {parameters}")


SessionDep = Annotated[AsyncSession, Depends(get_async_db)]
SyncSessionDep = Annotated[Session, Depends(get_db)]

get_session = get_async_db

async_session = AsyncSessionLocal