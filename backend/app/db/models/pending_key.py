from datetime import datetime, timedelta
from typing import Optional
from beanie import Document
from beanie.odm.fields import PydanticObjectId
from pydantic import Field, ConfigDict


class PendingSessionKey(Document):
    """Stores encrypted session/group keys for offline delivery (per device)."""

    conversation_id: Optional[PydanticObjectId] = Field(
        default=None, description="Conversation ID if this is a group key"
    )
    recipient_user_id: PydanticObjectId = Field(
        ..., description="User who should receive this key"
    )
    recipient_device_id: Optional[str] = Field(
        default=None, description="Target device ID (if known)"
    )
    key_version: Optional[int] = Field(
        default=None, description="Group key version (if applicable)"
    )
    encrypted_session_key: str = Field(
        ..., description="Base64 encrypted AES session key"
    )
    sender_user_id: PydanticObjectId = Field(
        ..., description="User who sent this key"
    )
    signature: str = Field(
        ..., description="Base64 encoded RSA-PSS signature"
    )
    timestamp: int = Field(
        ..., description="Unix timestamp when key was signed"
    )
    created_at: datetime = Field(default_factory=datetime.utcnow)
    delivered: bool = Field(default=False)
    expires_at: datetime = Field(
        default_factory=lambda: datetime.utcnow() + timedelta(days=7),
        description="Auto-expire after 7 days",
    )

    class Settings:
        name = "pending_session_keys"

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        populate_by_name=True,
    )
