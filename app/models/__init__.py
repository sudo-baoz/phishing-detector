"""Database models"""

from app.database import Base
from app.models.user import User
from app.models.scan_history import ScanHistory

__all__ = ["Base", "User", "ScanHistory"]
