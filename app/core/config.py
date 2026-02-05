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
Core Configuration Module
Uses pydantic-settings to manage environment variables
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Literal


class Settings(BaseSettings):
    """
    Application settings loaded from .env file
    Manages all environment variables for the application
    """
    
    # ==================== Database Configuration ====================
    DB_TYPE: Literal["mysql", "postgresql", "sqlite"] = "mysql"
    DB_HOST: str = "localhost"
    DB_USER: str = ""
    DB_PASSWORD: str = ""
    DB_NAME: str = "phishing_detector"
    DB_PORT: int | None = None
    
    # ==================== Server Configuration ====================
    PORT: int = 8000
    HOST: str = "0.0.0.0"
    
    # ==================== CORS Configuration ====================
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"
    
    # ==================== Application Settings ====================
    APP_NAME: str = "Phishing URL Detection API"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = "API for detecting phishing URLs using Machine Learning"
    DEBUG: bool = False
    
    # ==================== ML Model Settings ====================
    MODEL_PATH: str = "models/phishing_model.pkl"
    
    # ==================== AI Integration Settings ====================
    GEMINI_API_KEY: str = ""
    
    # Pydantic settings configuration
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"  # Ignore extra fields in .env
    )
    
    # ==================== Computed Properties ====================
    
    @property
    def database_url(self) -> str:
        """
        Generate database URL for SQLAlchemy based on DB_TYPE
        
        Returns:
            Async database connection URL
            
        Raises:
            ValueError: If database configuration is invalid
        """
        
        if self.DB_TYPE == "sqlite":
            # SQLite - file-based database
            return f"sqlite+aiosqlite:///./{self.DB_NAME}.db"
        
        elif self.DB_TYPE == "postgresql":
            # PostgreSQL with asyncpg driver
            port = self.DB_PORT or 5432
            if not self.DB_USER or not self.DB_PASSWORD:
                raise ValueError("DB_USER and DB_PASSWORD are required for PostgreSQL")
            return f"postgresql+asyncpg://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{port}/{self.DB_NAME}"
        
        elif self.DB_TYPE == "mysql":
            # MySQL/MariaDB with aiomysql driver
            port = self.DB_PORT or 3306
            if not self.DB_USER or not self.DB_PASSWORD:
                raise ValueError("DB_USER and DB_PASSWORD are required for MySQL")
            return f"mysql+aiomysql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{port}/{self.DB_NAME}"
        
        else:
            raise ValueError(f"Unsupported database type: {self.DB_TYPE}")
    
    @property
    def cors_origins_list(self) -> list[str]:
        """
        Parse CORS origins from comma-separated string
        
        Returns:
            List of allowed CORS origins
        """
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]
    
    @property
    def server_url(self) -> str:
        """
        Get server URL
        
        Returns:
            Full server URL
        """
        return f"http://{self.HOST}:{self.PORT}"


# ==================== Global Settings Instance ====================
settings = Settings()
