from fastapi import APIRouter, Depends, Query, Request
import logging
from app.db.models import User
from app.schemas.chats import (
    ConversationCreate,
    ConversationResponse,
    AddMembersRequest,
    InviteLinkResponse,
    JoinGroupRequest,
)
from app.schemas.response import BaseResponse
from app.services.chat_service import ChatService
from app.dependencies.auth import get_current_user

router = APIRouter()
logger = logging.getLogger("uvicorn.error")


@router.post("/", response_model=ConversationResponse)
async def create_conversation(
    request: Request,
    payload: ConversationCreate,
    current_user: User = Depends(get_current_user),
    service: ChatService = Depends(ChatService),
) -> ConversationResponse:
    """Create a new secure conversation."""
    try:
        raw_body = await request.body()
        logger.info("create_conversation raw_body=%s", raw_body)
    except Exception:
        logger.exception("Failed to read raw body")
    logger.info("create_conversation payload=%s", payload.model_dump())
    return await service.create_conversation(payload, current_user)


@router.get("/", response_model=dict)
async def list_conversations(
    current_user: User = Depends(get_current_user),
    service: ChatService = Depends(ChatService),
) -> dict:
    """List all conversations for the current user."""
    conversations = await service.list_conversations(current_user)
    return {"conversations": conversations}


@router.get("/{conversation_id}/messages")
async def get_messages(
    conversation_id: str,
    limit: int = Query(default=50, ge=1, le=100,
                       description="Số lượng tin nhắn tối đa"),
    cursor: str | None = Query(
        default=None, description="Cursor để phân trang (ISO datetime)"),
    current_user: User = Depends(get_current_user),
    service: ChatService = Depends(ChatService),
) -> dict:
    """Get messages from a conversation with cursor-based pagination."""
    return await service.get_messages(conversation_id, current_user, limit, cursor)


@router.patch("/{conversation_id}/seen")
async def mark_as_seen(
    conversation_id: str,
    current_user: User = Depends(get_current_user),
    service: ChatService = Depends(ChatService),
) -> dict:
    """Mark messages in a conversation as seen."""
    return await service.mark_as_seen(conversation_id, current_user)


@router.delete("/{conversation_id}")
async def delete_conversation(
    conversation_id: str,
    current_user: User = Depends(get_current_user),
    service: ChatService = Depends(ChatService),
) -> dict:
    """Delete a conversation."""
    return await service.delete_conversation(conversation_id, current_user)


@router.post("/{conversation_id}/members")
async def add_members_to_group(
    conversation_id: str,
    payload: AddMembersRequest,
    current_user: User = Depends(get_current_user),
    service: ChatService = Depends(ChatService),
) -> BaseResponse[dict]:
    """Add members to a group conversation."""
    result = await service.add_members_to_group(conversation_id, payload, current_user)
    return BaseResponse(
        status_code=200,
        success=True,
        message=result.get("message", "Thêm thành viên thành công"),
        data=result,
    )


@router.post("/{conversation_id}/invite-link")
async def create_invite_link(
    conversation_id: str,
    expires_days: int | None = Query(
        default=7, ge=1, le=365, description="Số ngày hết hạn"),
    current_user: User = Depends(get_current_user),
    service: ChatService = Depends(ChatService),
) -> BaseResponse[InviteLinkResponse]:
    """Create an invite link for a group conversation."""
    invite_link = await service.create_invite_link(conversation_id, current_user, expires_days)
    return BaseResponse(
        status_code=200,
        success=True,
        message="Tạo invite link thành công",
        data=invite_link,
    )


@router.post("/join-group")
async def join_group_via_invite(
    payload: JoinGroupRequest,
    current_user: User = Depends(get_current_user),
    service: ChatService = Depends(ChatService),
) -> BaseResponse[ConversationResponse]:
    """Join a group conversation via invite code."""
    from bson import ObjectId
    from app.db.models.conversation import Conversation

    # Check if user is already a member before calling service
    from app.db.models.group_invite import GroupInvite
    invite = await GroupInvite.find_one({"invite_code": payload.invite_code})
    if invite:
        conversation = await Conversation.find_one({"_id": invite.conversation_id})
        if conversation:
            user_id = ObjectId(str(current_user.id))
            existing_participant_ids = {
                p.user_id for p in conversation.participants}
            if user_id in existing_participant_ids:
                # User is already a member
                result = await service.join_group_via_invite(payload, current_user)
                return BaseResponse(
                    status_code=200,
                    success=True,
                    message="Bạn đã là thành viên của nhóm này",
                    data=result,
                )

    # User is not a member, proceed with join
    conversation = await service.join_group_via_invite(payload, current_user)
    return BaseResponse(
        status_code=200,
        success=True,
        message="Tham gia nhóm thành công",
        data=conversation,
    )


@router.delete("/{conversation_id}/leave")
async def leave_group(
    conversation_id: str,
    current_user: User = Depends(get_current_user),
    service: ChatService = Depends(ChatService),
) -> BaseResponse[dict]:
    """Leave a group conversation."""
    result = await service.leave_group(conversation_id, current_user)
    return BaseResponse(
        status_code=200,
        success=True,
        message=result.get("message", "Rời nhóm thành công"),
        data=result,
    )
