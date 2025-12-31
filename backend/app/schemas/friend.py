from pydantic import BaseModel, Field
from datetime import datetime


class FriendProfile(BaseModel):
    """Lightweight friend profile returned by /friends."""

    id: str = Field(..., alias="_id")
    username: str
    displayName: str | None = None
    avatarUrl: str | None = None

    model_config = {
        "populate_by_name": True,
        "extra": "ignore",
    }


class FriendRequestCreate(BaseModel):
    to_user: str
    message: str = ""  # Optional, default to empty string


class UserInfo(BaseModel):
    """User information in friend request."""

    id: str = Field(..., serialization_alias="_id")
    username: str
    displayName: str
    avatarUrl: str | None = None


class FriendRequestResponse(BaseModel):
    """Schema for friend request response with populated user info."""

    id: str = Field(..., serialization_alias="_id")
    from_: UserInfo | None = Field(
        None, alias="from", serialization_alias="from")
    to: UserInfo | None = None
    message: str
    createdAt: datetime
    updatedAt: datetime

    model_config = {
        "populate_by_name": True,
    }


class AllFriendRequestsResponse(BaseModel):
    """Schema for all friend requests (sent and received)."""

    sent: list[FriendRequestResponse]
    received: list[FriendRequestResponse]


class FriendResponse(BaseModel):
    """Schema for friend relationship response."""

    id: str
    userA: str
    userB: str
    timestamps: datetime
