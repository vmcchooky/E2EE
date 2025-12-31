from datetime import datetime
from bson import ObjectId

from app.db.models.conversation import Conversation, LastMessage
from app.db.models.message import Message


async def update_conversation_after_create_message(
        conversation: Conversation,
        message: Message,
        sender_id: ObjectId) -> None:
    """Update conversation after a new message is sent."""
    # Update last_message
    conversation.last_message_at = message.timestamps
    conversation.last_message = LastMessage(
        message_id=str(message.id),
        sender_id=message.sender_id,
        content=message.content,
        created_at=message.timestamps,
        counter=message.counter,
        key_version=message.key_version
    )

    # Cập nhật unread_counts cho từng participant
    sender_id_str = str(sender_id)
    for participant in conversation.participants:
        member_id = str(participant.user_id)
        is_sender = member_id == sender_id_str

        # Lấy số tin nhắn chưa đọc hiện tại (mặc định là 0)
        pre_count = conversation.unread_counts.get(member_id, 0)

        # Nếu là người gửi thì reset về 0, ngược lại tăng lên 1
        conversation.unread_counts[member_id] = 0 if is_sender else pre_count + 1

    # Cập nhật updated_at
    conversation.updated_at = datetime.now()

    # Lưu vào database
    await conversation.save()
