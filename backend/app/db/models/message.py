from datetime import datetime, timezone
from typing import Optional

from beanie import Document
from beanie.odm.fields import PydanticObjectId
from pydantic import ConfigDict, Field


class Message(Document):
    """Message model for MongoDB using Beanie ODM."""

    conversation_id: PydanticObjectId = Field(...)
    sender_id: PydanticObjectId = Field(...)
    content: str = Field(..., min_length=1, trim_whitespace=True)
    imgUrl: Optional[str] = None
    timestamps: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc))
    # Version của group session key dùng để mã hóa message này (None = không dùng group key)
    key_version: Optional[int] = Field(default=None)
    # Counter cho anti-replay protection (chỉ dùng cho direct E2EE messages)
    counter: Optional[int] = Field(
        default=None, description="Message counter for anti-replay protection")

    class Settings:
        name = "messages"
        indexes = [
            [("conversation_id", 1)],
            [("sender_id", 1)],
            [("timestamps", -1)],
        ]

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        json_encoders={PydanticObjectId: str},
        populate_by_name=True,
    )
