from beanie import Document
from beanie.odm.fields import PydanticObjectId
from pydantic import ConfigDict, Field
from datetime import datetime, timezone
from pymongo import IndexModel


class FriendRequest(Document):
    """Friend request model for MongoDB using Beanie ODM."""

    from_user: PydanticObjectId = Field(...,
                                        description="Người gửi yêu cầu kết bạn")
    to_user: PydanticObjectId = Field(...,
                                      description="Người nhận yêu cầu kết bạn")
    message: str = Field(
        default="", description="Lời nhắn khi gửi yêu cầu kết bạn", max_length=255)
    timestamps: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "friend_requests"
        indexes = [
            IndexModel([("from_user", 1), ("to_user", 1)],
                       unique=True, name="unique_friend_request"),
            IndexModel([("from_user", 1)], name="from_user_idx"),
            IndexModel([("to_user", 1)], name="to_user_idx"),
        ]

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        json_encoders={PydanticObjectId: str},
        populate_by_name=True
    )
