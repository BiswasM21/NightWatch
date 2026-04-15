"""Database session management."""

import aiosqlite
from pathlib import Path
from typing import Optional
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from contextlib import asynccontextmanager
from .database import Base

DEFAULT_DB_PATH = Path.home() / "NightWatch" / "nightwatch.db"


class Database:
    """Async database manager for NightWatch."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or str(DEFAULT_DB_PATH)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._engine = None
        self._session_factory = None
        self._sync_engine = None
        self._sync_session_factory = None

    async def initialize(self):
        """Initialize async engine."""
        url = f"sqlite+aiosqlite:///{self.db_path}"
        self._engine = create_async_engine(url, echo=False)
        self._session_factory = async_sessionmaker(
            self._engine, class_=AsyncSession, expire_on_commit=False
        )
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    def initialize_sync(self):
        """Initialize sync engine (for CLI usage)."""
        url = f"sqlite:///{self.db_path}"
        self._sync_engine = create_engine(url, echo=False)
        Base.metadata.create_all(self._sync_engine)
        self._sync_session_factory = sessionmaker(bind=self._sync_engine)

    @asynccontextmanager
    async def session(self):
        """Async session context manager."""
        if not self._session_factory:
            await self.initialize()
        async with self._session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    def get_sync_session(self):
        """Get a synchronous session."""
        if not self._sync_session_factory:
            self.initialize_sync()
        return self._sync_session_factory()

    async def close(self):
        """Close the database engine."""
        if self._engine:
            await self._engine.dispose()


# Global instance
_db: Optional[Database] = None


def get_db(db_path: Optional[str] = None) -> Database:
    global _db
    if _db is None:
        _db = Database(db_path)
    return _db
