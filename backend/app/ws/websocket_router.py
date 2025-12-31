from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from bson import ObjectId
from datetime import datetime
import logging

from app.ws.connection_manager import manager
from app.ws.auth import authenticate_websocket
from app.services.chat_service import ChatService
from app.db.models.pending_key import PendingSessionKey
from app.db.models.user import User

logger = logging.getLogger("uvicorn.error")

router = APIRouter()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time communication."""
    user = None
    user_id = None

    try:
        # Authenticate user
        user = await authenticate_websocket(websocket)
        if not user:
            await websocket.close(code=4001, reason="Unauthorized")
            return

        user_id = str(user.id)

        # Connect user
        await manager.connect(user_id, websocket)

        # Broadcast online users
        await manager.broadcast_online_users()

        # Auto-join user's conversations
        chat_service = ChatService()
        conversation_ids = await chat_service.get_user_conversation_ids(user_id)
        manager.join_rooms(user_id, conversation_ids)

        # Join user's own room (for direct notifications)
        manager.join_room(user_id, user_id)

        logger.info(
            f"User {user_id} connected and joined {len(conversation_ids)} rooms")

        # Send pending session keys that were stored while user was offline
        await _send_pending_keys_to_user(user_id)

        # Listen for messages
        while True:
            data = await websocket.receive_json()
            event = data.get("event")
            payload = data.get("data", {})

            if event == "join-conversation":
                conversation_id = payload.get("conversationId")
                if conversation_id:
                    manager.join_room(user_id, conversation_id)
                    logger.info(
                        f"User {user_id} joined room {conversation_id}")

            elif event == "ping":
                await manager.send_to_user(user_id, "pong", {})

    except WebSocketDisconnect:
        logger.info(f"User {user_id} disconnected (WebSocketDisconnect)")
    except Exception as e:
        logger.error(f"WebSocket error for user {user_id}: {e}")
    finally:
        if user_id:
            manager.disconnect(user_id)
            await manager.broadcast_online_users()


async def _send_pending_keys_to_user(user_id: str) -> None:
    """Send pending session/group keys to user when they come online."""
    try:
        user_obj_id = ObjectId(user_id)

        # Query pending keys for this user (not expired, not delivered)
        pending_keys = await PendingSessionKey.find(
            PendingSessionKey.recipient_user_id == user_obj_id,
            PendingSessionKey.delivered == False,
            PendingSessionKey.expires_at > datetime.utcnow()
        ).to_list()

        if not pending_keys:
            return

        logger.info(
            f"[WS] Found {len(pending_keys)} pending keys for user {user_id}")

        # Get sender info for each key
        sent_count = 0
        failed_ids = []

        for pending in pending_keys:
            try:
                # Get sender user info
                sender = await User.get(pending.sender_user_id)
                if not sender:
                    logger.warning(
                        f"[WS] Sender {pending.sender_user_id} not found for pending key {pending.id}")
                    failed_ids.append(str(pending.id))
                    continue

                # Send via WebSocket (same format as session-key-exchange)
                sent = await manager.send_to_user(
                    user_id,
                    "session-key-exchange",
                    {
                        "senderId": str(pending.sender_user_id),
                        "senderUsername": sender.username,
                        "senderDisplayName": sender.display_name or sender.username,
                        "encryptedSessionKey": pending.encrypted_session_key,
                        "deviceId": pending.recipient_device_id,  # Target device ID
                        "recipientDeviceId": pending.recipient_device_id,
                        "conversationId": str(pending.conversation_id) if pending.conversation_id else None,
                        "keyVersion": pending.key_version,
                    },
                )

                if sent:
                    # Mark as delivered (but don't delete yet - let frontend ACK to delete)
                    # This prevents race condition where E2EE might not be initialized yet
                    pending.delivered = True
                    await pending.save()
                    sent_count += 1
                    logger.info(
                        f"[WS] Sent pending key {pending.id} to user {user_id} (marked as delivered, waiting for ACK)")
                else:
                    # User might have disconnected, keep pending
                    logger.warning(
                        f"[WS] Failed to send pending key {pending.id} to user {user_id} (user offline?)")
                    failed_ids.append(str(pending.id))
            except Exception as e:
                logger.error(
                    f"[WS] Error sending pending key {pending.id}: {e}")
                failed_ids.append(str(pending.id))

        if sent_count > 0:
            logger.info(
                f"[WS] Sent {sent_count} pending keys to user {user_id}")
        if failed_ids:
            logger.warning(
                f"[WS] Failed to send {len(failed_ids)} pending keys to user {user_id}")

    except Exception as e:
        logger.error(
            f"[WS] Error in _send_pending_keys_to_user for {user_id}: {e}")
