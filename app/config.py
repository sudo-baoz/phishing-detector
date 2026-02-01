"""Application configuration using pydantic-settings"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Literal


class Settings(BaseSettings):
    """Application settings loaded from .env file"""
    
    # Database settings
    DB_TYPE: Literal["mysql", "postgresql", "sqlite"] = "mysql"
    DB_HOST: str = "localhost"
    DB_USER: str = ""
    DB_PASSWORD: str = ""
    DB_NAME: str = "phishing_detector"
    DB_PORT: int | None = None
    
    # Server settings
    PORT: int = 8000
    
    # CORS settings
    CORS_ORIGINS: str = "http://your-frontend-domain.com"
    
    # Application settings
    APP_NAME: str = "Phishing URL Detection API"
    DEBUG: bool = False
    
    # AI Integration settings
    GEMINI_API_KEY: str = ""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True
    )
    
    @property
    def database_url(self) -> str:
        """Generate database URL for SQLAlchemy based on DB_TYPE"""
        
        if self.DB_TYPE == "sqlite":
            # SQLite - file-based database
            return f"sqlite+aiosqlite:///./{self.DB_NAME}.db"
        
        elif self.DB_TYPE == "postgresql":
            # PostgreSQL
            port = self.DB_PORT or 5432
            if not self.DB_USER or not self.DB_PASSWORD:
                raise ValueError("DB_USER and DB_PASSWORD are required for PostgreSQL")
            return f"postgresql+asyncpg://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{port}/{self.DB_NAME}"
        
        elif self.DB_TYPE == "mysql":
            # MySQL/MariaDB
            port = self.DB_PORT or 3306
            if not self.DB_USER or not self.DB_PASSWORD:
                raise ValueError("DB_USER and DB_PASSWORD are required for MySQL")
            return f"mysql+aiomysql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{port}/{self.DB_NAME}"
        
        else:
            raise ValueError(f"Unsupported database type: {self.DB_TYPE}")
    
    @property
    def cors_origins_list(self) -> list[str]:
        """Parse CORS origins from comma-separated string"""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]


# Global settings instance
settings = Settings()
