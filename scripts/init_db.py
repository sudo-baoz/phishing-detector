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
Database initialization script
Creates all tables defined in SQLAlchemy models
"""

import asyncio
import sys
import logging
from pathlib import Path

# Add app directory to path
sys.path.insert(0, str(Path(__file__).parent))

from app.database import engine, Base
from app.models import User, ScanHistory
from app.config import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


async def init_database():
    """Initialize database by creating all tables"""
    
    logger.info("=" * 60)
    logger.info("Database Initialization Script")
    logger.info("=" * 60)
    logger.info(f"Database Type: {settings.DB_TYPE}")
    
    if settings.DB_TYPE == "sqlite":
        logger.info(f"Database File: {settings.DB_NAME}.db")
    else:
        logger.info(f"Database Host: {settings.DB_HOST}")
        logger.info(f"Database Port: {settings.DB_PORT or 'default'}")
        logger.info(f"Database Name: {settings.DB_NAME}")
        logger.info(f"Database User: {settings.DB_USER}")
    
    logger.info("-" * 60)
    
    try:
        # Create all tables
        async with engine.begin() as conn:
            logger.info("Creating tables...")
            
            # Optional: Drop all tables first (uncomment if you want clean slate)
            # await conn.run_sync(Base.metadata.drop_all)
            # logger.info("Dropped existing tables")
            
            await conn.run_sync(Base.metadata.create_all)
            logger.info("✓ All tables created successfully")
        
        # Display created tables
        logger.info("-" * 60)
        logger.info("Created tables:")
        for table_name in Base.metadata.tables.keys():
            logger.info(f"  ✓ {table_name}")
        
        logger.info("=" * 60)
        logger.info("Database initialization completed successfully!")
        logger.info("=" * 60)
        
        return True
        
    except Exception as e:
        logger.error("=" * 60)
        logger.error(f"❌ Failed to initialize database: {e}")
        logger.error("=" * 60)
        logger.error("\nPossible solutions:")
        logger.error("1. Check database credentials in .env file")
        logger.error("2. Ensure database server is running")
        logger.error("3. Verify database exists (or user has CREATE DATABASE permission)")
        logger.error("4. Check network connectivity to database server")
        
        if settings.DB_TYPE == "mysql":
            logger.error("\nFor MySQL, you can create database manually:")
            logger.error(f"  CREATE DATABASE {settings.DB_NAME};")
            logger.error(f"  GRANT ALL PRIVILEGES ON {settings.DB_NAME}.* TO '{settings.DB_USER}'@'localhost';")
        elif settings.DB_TYPE == "postgresql":
            logger.error("\nFor PostgreSQL, you can create database manually:")
            logger.error(f"  CREATE DATABASE {settings.DB_NAME};")
            logger.error(f"  GRANT ALL PRIVILEGES ON DATABASE {settings.DB_NAME} TO {settings.DB_USER};")
        
        return False
    
    finally:
        # Close engine
        await engine.dispose()
        logger.info("Database connection closed")


async def drop_all_tables():
    """Drop all tables - USE WITH CAUTION!"""
    
    logger.warning("=" * 60)
    logger.warning("⚠️  WARNING: Dropping all tables!")
    logger.warning("=" * 60)
    
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            logger.info("✓ All tables dropped successfully")
        return True
    except Exception as e:
        logger.error(f"❌ Failed to drop tables: {e}")
        return False
    finally:
        await engine.dispose()


def main():
    """Main entry point"""
    
    # Check command line arguments
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "drop":
            # Drop all tables
            response = input("Are you sure you want to drop all tables? (yes/no): ")
            if response.lower() == "yes":
                asyncio.run(drop_all_tables())
            else:
                logger.info("Operation cancelled")
        elif command == "reset":
            # Drop and recreate
            response = input("Are you sure you want to reset the database? (yes/no): ")
            if response.lower() == "yes":
                asyncio.run(drop_all_tables())
                asyncio.run(init_database())
            else:
                logger.info("Operation cancelled")
        else:
            logger.error(f"Unknown command: {command}")
            logger.info("Available commands:")
            logger.info("  python init_db.py        - Create tables")
            logger.info("  python init_db.py drop   - Drop all tables")
            logger.info("  python init_db.py reset  - Drop and recreate tables")
    else:
        # Default: create tables
        asyncio.run(init_database())


if __name__ == "__main__":
    main()
