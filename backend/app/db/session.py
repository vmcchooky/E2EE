from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie

from app.core.config import get_settings
from app.db.models.user import User
from app.db.models.friend import Friend
from app.db.models.friend_request import FriendRequest
from app.db.models.token import Token
from app.db.models.message import Message
from app.db.models.public_key import PublicKey
from app.db.models.conversation import (
    Conversation,
    Participant,
    Group,
    LastMessage,
)
from app.db.models.pending_key import PendingSessionKey
from app.db.models.group_invite import GroupInvite

settings = get_settings()


async def init_db() -> None:
    """Initialize MongoDB connection and Beanie ODM."""
    client = AsyncIOMotorClient(settings.database_url)
    database = client[settings.database_name]
    await init_beanie(
        database=database,
        document_models=[
            User,
            Friend,
            FriendRequest,
            Token,
            Message,
            PublicKey,
            Conversation,
            Participant,
            Group,
            LastMessage,
            PendingSessionKey,
            GroupInvite,
        ],
    )


async def close_db() -> None:
    """Close MongoDB connection."""
    # Motor client will be closed automatically when app shuts down
    pass
