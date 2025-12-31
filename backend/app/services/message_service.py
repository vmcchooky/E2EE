from datetime import datetime
from fastapi import status
from app.db.models.conversation import Conversation, Participant
from app.db.models.message import Message
from app.db.models.user import User
from app.utils.message_helper import update_conversation_after_create_message
from app.schemas.response import error_response, success_response
from app.ws.connection_manager import manager
from bson import ObjectId
import logging

logger = logging.getLogger("uvicorn.error")


class MessageService:
    """Service for storing encrypted messages."""

    def _format_message(self, message: Message) -> dict:
        """Format message for response/WebSocket."""
        return {
            "_id": str(message.id),
            "conversationId": str(message.conversation_id),
            "senderId": str(message.sender_id),
            "content": message.content,
            "imgUrl": message.imgUrl,
            "createdAt": message.timestamps.isoformat() if message.timestamps else None,
            "keyVersion": message.key_version,  # For E2EE group messages
            # For anti-replay protection (E2EE direct messages)
            "counter": message.counter,
        }

    async def _format_conversation_for_ws(self, conversation: Conversation, include_full: bool = False) -> dict:
        """Format conversation data for WebSocket emit."""
        result = {
            "_id": str(conversation.id),
            "type": conversation.type,
            "lastMessage": {
                "_id": str(conversation.last_message.message_id) if conversation.last_message else None,
                "content": conversation.last_message.content if conversation.last_message else None,
                "senderId": str(conversation.last_message.sender_id) if conversation.last_message else None,
                "createdAt": conversation.last_message.created_at.isoformat() if conversation.last_message else None,
                "counter": conversation.last_message.counter if conversation.last_message else None,
                "keyVersion": conversation.last_message.key_version if conversation.last_message else None,
                "sender": {
                    "_id": str(conversation.last_message.sender_id) if conversation.last_message else None,
                    "displayName": "",
                    "avatarUrl": None,
                } if conversation.last_message else None,
            } if conversation.last_message else None,
            "lastMessageAt": conversation.last_message_at.isoformat() if conversation.last_message_at else None,
            "createdAt": conversation.created_at.isoformat() if conversation.created_at else None,
            "updatedAt": conversation.updated_at.isoformat() if conversation.updated_at else None,
        }

        # Include participants data with user details for new conversations
        if include_full:
            participants_data = []
            for p in conversation.participants:
                user = await User.get(ObjectId(p.user_id) if isinstance(p.user_id, str) else p.user_id)
                participants_data.append({
                    "_id": str(p.user_id),
                    "username": user.username if user else None,
                    "displayName": user.display_name if user else None,
                    "avatarUrl": user.avatar_url if user else None,
                    "joinedAt": p.joined_at.isoformat() if p.joined_at else None,
                })
            result["participants"] = participants_data

            if conversation.group:
                result["group"] = {
                    "name": conversation.group.name,
                    "createdBy": str(conversation.group.created_by) if conversation.group.created_by else None,
                }

        return result

    async def send_direct_message(
        self, recipient_id: str, content: str, conversation_id: str | None, sender_id: str, counter: int | None = None
    ) -> dict:
        """Send a direct message to a recipient."""
        try:
            if not content:
                return error_response(
                    message="Nội dung tin nhắn không được để trống",
                    status_code=status.HTTP_400_BAD_REQUEST
                )

            conversation = None
            is_new_conversation = False

            if conversation_id:
                conversation = await Conversation.get(conversation_id)

            if not conversation:
                is_new_conversation = True
                conversation = Conversation(
                    type="direct",
                    participants=[
                        Participant(user_id=sender_id,
                                    joined_at=datetime.now()),
                        Participant(user_id=recipient_id,
                                    joined_at=datetime.now())
                    ],
                    last_message_at=datetime.now(),
                    unread_counts={}
                )
                await conversation.insert()

            # Create message
            message = Message(
                conversation_id=conversation.id,
                sender_id=sender_id,
                content=content,
                timestamps=datetime.now(),
                # For anti-replay protection (E2EE direct messages)
                counter=counter
            )
            await message.insert()

            # Update conversation
            await update_conversation_after_create_message(conversation, message, sender_id)

            # Get participant IDs for direct sending
            participant_ids = [sender_id, recipient_id]

            # Emit new message via WebSocket
            # include_full=True for new conversations so recipients get full participant data
            # Always pass participant_ids to ensure direct delivery
            await manager.emit_new_message(
                conversation_id=str(conversation.id),
                message=self._format_message(message),
                conversation_data=await self._format_conversation_for_ws(
                    conversation, include_full=is_new_conversation),
                unread_counts={
                    str(k): v for k, v in conversation.unread_counts.items()},
                participant_ids=participant_ids
            )

            return success_response(
                self._format_message(message),
                "Gửi tin nhắn thành công",
                status_code=status.HTTP_201_CREATED
            )
        except Exception as e:
            logger.error(f"Error sending direct message: {e}")
            return error_response(message=str(e), status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

    async def send_group_message(
        self,
        conversation_id: str | None,
        content: str,
        sender_id: str,
        key_version: int | None = None,
    ) -> dict:
        """Send a message to a group conversation."""
        try:
            if not content:
                return error_response(
                    message="Nội dung tin nhắn không được để trống",
                    status_code=status.HTTP_400_BAD_REQUEST
                )

            conversation = None
            if conversation_id:
                conversation = await Conversation.get(conversation_id)

            if not conversation:
                return error_response(
                    message="Conversation không tồn tại",
                    status_code=status.HTTP_404_NOT_FOUND,
                )

            # Validate key_version if provided
            if key_version is not None:
                if conversation.type != "group":
                    return error_response(
                        message="keyVersion chỉ dùng cho group conversation",
                        status_code=status.HTTP_400_BAD_REQUEST,
                    )

                # Allow key version to progress automatically
                if key_version > conversation.current_key_version:
                    logger.info(
                        f"[E2EE] Group {conversation_id} key version progressing from {conversation.current_key_version} to {key_version}")
                    conversation.current_key_version = key_version
                    await conversation.save()
                elif key_version < conversation.current_key_version:
                    return error_response(
                        message=f"Key version {key_version} is too old (current: {conversation.current_key_version})",
                        status_code=status.HTTP_400_BAD_REQUEST,
                    )

            # Create message
            message = Message(
                conversation_id=conversation.id,
                sender_id=sender_id,
                content=content,
                timestamps=datetime.now(),
                key_version=key_version,
            )
            await message.insert()

            # Update conversation
            await update_conversation_after_create_message(conversation, message, sender_id)

            # Get all participant IDs for direct sending
            participant_ids = [str(p.user_id)
                               for p in conversation.participants]

            # Emit new message via WebSocket
            await manager.emit_new_message(
                conversation_id=str(conversation.id),
                message=self._format_message(message),
                conversation_data=await self._format_conversation_for_ws(conversation),
                unread_counts={
                    str(k): v for k, v in conversation.unread_counts.items()},
                participant_ids=participant_ids
            )

            return success_response(
                self._format_message(message),
                "Gửi tin nhắn thành công",
                status_code=status.HTTP_201_CREATED
            )
        except Exception as e:
            logger.error(f"Error sending group message: {e}")
            return error_response(
                message="Gửi tin nhắn thất bại",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
