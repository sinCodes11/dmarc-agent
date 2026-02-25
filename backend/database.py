from __future__ import annotations

import logging
import os
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL", "")
_db_configured = bool(DATABASE_URL)

if not DATABASE_URL:
    # Keeps module importable for non-DB endpoints; DB routes will fail gracefully.
    DATABASE_URL = "postgresql+asyncpg://invalid:invalid@localhost/invalid"
elif DATABASE_URL.startswith("postgres://"):
    # Heroku/Railway shorthand — must use full scheme with driver
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+asyncpg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    # Railway standard format — force asyncpg driver
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)

engine = create_async_engine(DATABASE_URL, future=True, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session


async def init_db() -> None:
    if not _db_configured:
        logger.warning("DATABASE_URL not set — skipping database initialisation. Auth and dashboard routes will not work.")
        return

    from backend import db_models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
