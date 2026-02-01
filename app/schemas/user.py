"""User schemas for request/response validation"""

from datetime import datetime
from pydantic import BaseModel, Field


class UserBase(BaseModel):
    """Base user schema"""
    username: str = Field(..., min_length=3, max_length=100)


class UserCreate(UserBase):
    """Schema for creating a new user"""
    password: str = Field(..., min_length=6)


class UserResponse(UserBase):
    """Schema for user response"""
    id: int
    created_at: datetime
    
    model_config = {"from_attributes": True}


class UserLogin(BaseModel):
    """Schema for user login"""
    username: str
    password: str
