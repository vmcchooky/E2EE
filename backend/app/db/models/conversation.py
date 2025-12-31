from datetime import datetime, timezone
from typing import Literal, List, Optional, Dict

from beanie import Document
from pydantic import Field, ConfigDict
from beanie.odm.fields import PydanticObjectId


# ==================== EMBEDDED MODELS ====================


class Participant(Document):
    user_id: PydanticObjectId = Field(..., description="ID người dùng")
    joined_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc))
    last_read_message_id: Optional[str] = None


class LastMessage(Document):
    message_id: str = Field(..., description="ID tin nhắn cuối")
    content: Optional[str] = Field(None, max_length=500)
    sender_id: PydanticObjectId = Field(..., description="Người gửi")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc))
    # E2EE fields
    counter: Optional[int] = None
    key_version: Optional[int] = None


class Group(Document):
    name: str = Field(..., min_length=1, max_length=100, strip_whitespace=True)
    avatar: Optional[str] = None
    created_by: PydanticObjectId = Field(..., description="Người tạo nhóm")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc))


# ==================== MAIN CONVERSATION DOCUMENT ====================


class Conversation(Document):
    type: Literal["direct",
                  "group"] = Field(..., description="direct hoặc group")
    participants: List[Participant] = Field(..., min_items=2)
    group: Optional[Group] = None
    last_message: Optional[LastMessage] = None
    last_message_at: Optional[datetime] = Field(
        None,
        description="Thời gian tin nhắn cuối – dùng để sort mới nhất",
    )
    unread_counts: Dict[PydanticObjectId, int] = Field(default_factory=dict)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc))
    # Current group key version for this conversation (0 = no group key yet)
    current_key_version: int = Field(default=0)

    class Settings:
        name = "conversations"
        indexes = [
            [("participants.user_id", 1), ("last_message_at", -1)],
            [("last_message_at", -1)],
            "type",
        ]
        use_state_management = True

    async def save(self, *args, **kwargs):
        self.updated_at = datetime.now(timezone.utc)
        return await super().save(*args, **kwargs)

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        json_encoders={PydanticObjectId: str},
    )
