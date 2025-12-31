from datetime import datetime
from typing import Optional

from beanie import Document
from pydantic import Field


class User(Document):
    """User model for MongoDB using Beanie ODM."""
    
    username: str = Field(..., unique=True)
    email: str = Field(..., unique=True)
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    display_name: Optional[str] = None
    avatar_url: Optional[str] = None
    bio: Optional[str] = None
    phone: Optional[str] = None
    hashed_password: str
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)

    class Settings:
        name = "users"
        indexes = [
            [("username", 1)],  # Single field index
            [("email", 1)],    # Single field index
        ]
