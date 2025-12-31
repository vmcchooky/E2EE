from fastapi import APIRouter, Depends, HTTPException, status
from app.middleware import check_friendship
from app.schemas.response import BaseResponse
from app.schemas.chats import DirectMessagePayload, GroupMessagePayload
from app.services.message_service import MessageService
from app.dependencies.auth import get_current_user
from app.db.models import User
from beanie.odm.fields import PydanticObjectId
from app.middleware.message_middleware import check_group_membership

router = APIRouter()


@router.post(
    "/direct",
    response_model=BaseResponse[dict],
    status_code=status.HTTP_201_CREATED,
)
async def send_direct_message(
    payload: DirectMessagePayload,
    current_user: User = Depends(get_current_user),
    service: MessageService = Depends(MessageService),
    _: None = Depends(check_friendship),
) -> BaseResponse[dict]:
    """Send a direct message to a recipient."""
    return await service.send_direct_message(
        payload.recipient_id,
        payload.content,
        payload.conversation_id,
        PydanticObjectId(str(current_user.id)),
        payload.counter,  # Pass counter for anti-replay protection
    )


@router.post(
    "/group", response_model=BaseResponse[dict], status_code=status.HTTP_201_CREATED
)
async def send_group_message(
    payload: GroupMessagePayload,
    current_user: User = Depends(get_current_user),
    service: MessageService = Depends(MessageService),
    _: None = Depends(check_group_membership),
) -> BaseResponse[dict]:
    """Send a message to a group conversation."""
    return await service.send_group_message(
        payload.conversation_id,
        payload.content,
        PydanticObjectId(str(current_user.id)),
        payload.key_version,
    )
