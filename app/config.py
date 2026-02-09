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
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:5174,http://localhost:3000"
    
    # Application settings
    APP_NAME: str = "Phishing URL Detection API"
    DEBUG: bool = False

    # JWT (SaaS)
    JWT_SECRET: str = "change-me-in-production-cybersentinel"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    
    # AI Integration settings
    GEMINI_API_KEY: str = ""
    GOOGLE_SAFE_BROWSING_KEY: str = ""
    
    # Cloudflare Turnstile settings
    CLOUDFLARE_SECRET_KEY: str = ""
    TURNSTILE_ENABLED: bool = True  # Toggle Turnstile verification
    
    # Captcha solver (FREE | 2CAPTCHA | CAPSOLVER)
    CAPTCHA_PROVIDER: Literal["FREE", "2CAPTCHA", "CAPSOLVER"] = "FREE"
    CAPTCHA_API_KEY: str = ""  # Required for 2CAPTCHA and CAPSOLVER
    
    # Vision Scanner proxy (e.g. residential proxy to avoid Cloudflare IP blocks)
    PROXY_SERVER: str = ""   # e.g. http://proxy.provider.com:8000
    PROXY_USERNAME: str = ""
    PROXY_PASSWORD: str = ""
    
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
