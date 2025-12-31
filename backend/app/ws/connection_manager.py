from typing import Dict, List, Set
from fastapi import WebSocket
import logging

logger = logging.getLogger("uvicorn.error")


class ConnectionManager:
    """Manages WebSocket connections for users."""

    def __init__(self):
        # Map user_id -> WebSocket
        self.online_users: Dict[str, WebSocket] = {}
        # Map room_id -> Set of user_ids (not WebSocket, to avoid duplicates)
        self.rooms: Dict[str, Set[str]] = {}
        # Map user_id -> Set of room_ids (for cleanup on disconnect)
        self.user_rooms: Dict[str, Set[str]] = {}

    async def connect(self, user_id: str, websocket: WebSocket) -> None:
        """Accept connection and register user."""
        await websocket.accept()
        self.online_users[user_id] = websocket
        self.user_rooms[user_id] = set()
        logger.info(f"User {user_id} connected")

    def disconnect(self, user_id: str) -> None:
        """Remove user from all rooms and online users."""
        # Remove from all rooms
        if user_id in self.user_rooms:
            for room_id in self.user_rooms[user_id]:
                if room_id in self.rooms:
                    self.rooms[room_id].discard(user_id)
            del self.user_rooms[user_id]

        # Remove from online users
        if user_id in self.online_users:
            del self.online_users[user_id]

        logger.info(f"User {user_id} disconnected")

    def join_room(self, user_id: str, room_id: str) -> None:
        """Add user to a room."""
        self.rooms.setdefault(room_id, set()).add(user_id)
        if user_id in self.user_rooms:
            self.user_rooms[user_id].add(room_id)
        logger.info(
            f"[WS] join_room: user={user_id}, room={room_id}, is_online={user_id in self.online_users}")

    def join_rooms(self, user_id: str, room_ids: List[str]) -> None:
        """Add user to multiple rooms."""
        for room_id in room_ids:
            self.join_room(user_id, room_id)

    def leave_room(self, user_id: str, room_id: str) -> None:
        """Remove user from a room."""
        if room_id in self.rooms:
            self.rooms[room_id].discard(user_id)
        if user_id in self.user_rooms:
            self.user_rooms[user_id].discard(room_id)

    def get_online_user_ids(self) -> List[str]:
        """Get list of online user IDs."""
        return list(self.online_users.keys())

    async def send_to_user(self, user_id: str, event: str, data: dict) -> bool:
        """Send message to a specific user. Returns True if sent."""
        if user_id in self.online_users:
            try:
                await self.online_users[user_id].send_json({
                    "event": event,
                    "data": data
                })
                return True
            except Exception as e:
                logger.error(f"Error sending to user {user_id}: {e}")
                return False
        return False

    async def broadcast_online_users(self) -> None:
        """Broadcast online users list to all connected users."""
        users = self.get_online_user_ids()
        for user_id in list(self.online_users.keys()):
            await self.send_to_user(user_id, "online-users", {"users": users})

    async def broadcast_to_room(self, room_id: str, event: str, data: dict) -> None:
        """Broadcast message to all users in a room."""
        logger.info(f"[WS] broadcast_to_room: room={room_id}, event={event}")
        logger.info(f"[WS] Current rooms: {list(self.rooms.keys())}")

        if room_id not in self.rooms:
            logger.warning(
                f"[WS] Room {room_id} not found! Available rooms: {list(self.rooms.keys())}")
            return

        users_in_room = list(self.rooms[room_id])
        logger.info(f"[WS] Users in room {room_id}: {users_in_room}")
        logger.info(f"[WS] Online users: {list(self.online_users.keys())}")

        for user_id in users_in_room:
            sent = await self.send_to_user(user_id, event, data)
            logger.info(f"[WS] Sent to {user_id}: {sent}")

    async def emit_new_message(
        self,
        conversation_id: str,
        message: dict,
        conversation_data: dict,
        unread_counts: dict,
        participant_ids: List[str] | None = None
    ) -> None:
        """Emit new message event to conversation room or directly to participants."""
        data = {
            "message": message,
            "conversation": conversation_data,
            "unreadCounts": unread_counts,
        }

        # If participant_ids provided, send directly to them (for new conversations)
        if participant_ids:
            logger.info(
                f"[WS] emit_new_message: sending directly to {participant_ids}")
            for user_id in participant_ids:
                # Also join them to the room for future messages
                self.join_room(user_id, conversation_id)
                await self.send_to_user(user_id, "new-message", data)
        else:
            # Broadcast to room (existing conversations)
            await self.broadcast_to_room(conversation_id, "new-message", data)

    async def emit_new_group(self, member_ids: List[str], conversation: dict) -> None:
        """Emit new group event to all members."""
        for user_id in member_ids:
            await self.send_to_user(user_id, "new-group", conversation)

    async def emit_read_message(
        self,
        conversation_id: str,
        conversation: dict,
        last_message: dict
    ) -> None:
        """Emit read message event to conversation room."""
        await self.broadcast_to_room(
            conversation_id,
            "read-message",
            {
                "conversation": conversation,
                "lastMessage": last_message,
            }
        )


# Singleton instance
manager = ConnectionManager()
