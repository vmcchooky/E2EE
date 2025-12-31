from fastapi import APIRouter, Depends

from app.schemas.chats import MessagePayload
from app.services.message_service import MessageService

router = APIRouter()


@router.post("/{conversation_id}/messages", response_model=None)
async def store_message(
    conversation_id: str,
    payload: MessagePayload,
    service: MessageService = Depends(MessageService),
) -> None:
    """Persist ciphertext message metadata for out-of-band fan-out."""
    await service.store_message(conversation_id, payload)
