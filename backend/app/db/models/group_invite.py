from datetime import datetime, timezone, timedelta
from typing import Optional
from beanie import Document
from pydantic import Field, ConfigDict
from beanie.odm.fields import PydanticObjectId
import secrets


class GroupInvite(Document):
    """Model for group invite links."""

    conversation_id: PydanticObjectId = Field(
        ..., description="ID của group conversation")
    invite_code: str = Field(..., description="Mã invite duy nhất")
    created_by: PydanticObjectId = Field(...,
                                         description="User tạo invite link")
    expires_at: Optional[datetime] = Field(
        default=None,
        description="Thời gian hết hạn (None = không bao giờ hết hạn)"
    )
    max_uses: Optional[int] = Field(
        default=None,
        description="Số lần sử dụng tối đa (None = không giới hạn)"
    )
    used_count: int = Field(default=0, description="Số lần đã sử dụng")
    is_active: bool = Field(
        default=True, description="Invite link còn hoạt động không")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "group_invites"
        indexes = [
            "invite_code",  # Index để tìm nhanh qua invite_code
            "conversation_id",
            "created_by",
        ]

    @staticmethod
    def generate_invite_code() -> str:
        """Generate a unique invite code (8 characters, URL-safe)."""
        return secrets.token_urlsafe(6)  # ~8 characters

    def is_expired(self) -> bool:
        """Check if invite link is expired."""
        if not self.expires_at:
            return False
        # Ensure both datetimes are timezone-aware for comparison
        now = datetime.now(timezone.utc)
        expires = self.expires_at
        # If expires_at is naive, assume it's UTC
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return now > expires

    def is_max_uses_reached(self) -> bool:
        """Check if max uses limit is reached."""
        if self.max_uses is None:
            return False
        return self.used_count >= self.max_uses

    def can_be_used(self) -> bool:
        """Check if invite link can still be used."""
        return self.is_active and not self.is_expired() and not self.is_max_uses_reached()

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        populate_by_name=True,
    )
