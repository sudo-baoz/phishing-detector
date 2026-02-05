"""
Phishing Detector - AI-Powered Threat Intelligence System
Copyright (c) 2026 BaoZ

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

"""
Complete Database Configuration
SQLAlchemy Async with MySQL, PostgreSQL, SQLite support
"""

import logging
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool, QueuePool
from sqlalchemy import event, text

from app.core.config import settings

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """Base class for all database models"""
    pass


def get_engine_config():
    """Get database engine configuration"""
    config = {"echo": settings.DEBUG}
    
    if settings.DB_TYPE == "sqlite":
        config.update({
            "connect_args": {"check_same_thread": False, "timeout": 30.0},
            "poolclass": NullPool,
        })
    elif settings.DB_TYPE == "mysql":
        config.update({
            "pool_size": 5,
            "max_overflow": 10,
            "pool_pre_ping": True,
            "pool_recycle": 3600,
            "pool_timeout": 30,
            "poolclass": QueuePool,
            "connect_args": {"connect_timeout": 10, "charset": "utf8mb4"}
        })
    elif settings.DB_TYPE == "postgresql":
        config.update({
            "pool_size": 5,
            "max_overflow": 10,
            "pool_pre_ping": True,
            "pool_recycle": 3600,
            "pool_timeout": 30,
            "poolclass": QueuePool,
        })
    
    return config


# Create async engine
engine_config = get_engine_config()
engine = create_async_engine(settings.database_url, **engine_config)

logger.info(f"Database engine created: {settings.DB_TYPE}")

# Create session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

# SQLite optimizations
if settings.DB_TYPE == "sqlite":
    @event.listens_for(engine.sync_engine, "connect")
    def set_sqlite_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Database session dependency"""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as e:
            logger.error(f"Database session error: {e}")
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Initialize database - create tables"""
    logger.info("Initializing database...")
    
    try:
        from app.models import User, ScanHistory  # noqa
        
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            logger.info("Database tables created")
        
        table_names = list(Base.metadata.tables.keys())
        logger.info(f"Tables: {', '.join(table_names)}")
        
        await test_connection()
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise


async def test_connection():
    """Test database connection"""
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
            logger.info("[OK] Database connection test successful")
            return True
    except Exception as e:
        logger.error(f"Database connection test failed: {e}")
        raise


async def close_db():
    """Close database connections"""
    logger.info("Closing database connections...")
    try:
        await engine.dispose()
        logger.info("[OK] Database connections closed")
    except Exception as e:
        logger.error(f"Error closing database: {e}")


async def check_database_health() -> dict:
    """Check database health"""
    health_info = {
        "status": "unhealthy",
        "database_type": settings.DB_TYPE,
        "connected": False,
        "tables": []
    }
    
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
            health_info["connected"] = True
            health_info["status"] = "healthy"
        
        health_info["tables"] = list(Base.metadata.tables.keys())
        return health_info
        
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        health_info["error"] = str(e)
        return health_info
