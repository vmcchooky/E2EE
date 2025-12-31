from app.api import api_auth, api_chats, api_friend, api_message, api_users, api_conversations, api_e2ee
from app.core.config import get_settings
from fastapi import APIRouter

router = APIRouter()

api_prefix = get_settings().api_v1_prefix

router.include_router(
    api_auth.router, prefix=f"{api_prefix}/auth", tags=["auth"])
router.include_router(
    api_users.router, prefix=f"{api_prefix}/users", tags=["users"])
router.include_router(
    api_chats.router, prefix=f"{api_prefix}/chats", tags=["chats"])
router.include_router(
    api_friend.router, prefix=f"{api_prefix}/friends", tags=["friend"])
router.include_router(api_message.router,
                      prefix=f"{api_prefix}/messages", tags=["message"])
router.include_router(api_conversations.router,
                      prefix=f"{api_prefix}/conversations", tags=["conversations"])
router.include_router(
    api_e2ee.router, prefix=f"{api_prefix}/e2ee", tags=["e2ee"])
