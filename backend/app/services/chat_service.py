from datetime import datetime, timezone
from fastapi import HTTPException, status
from bson import ObjectId
import logging

from app.db.models import User
from app.db.models.conversation import Conversation, Participant, Group
from app.db.models.message import Message
from app.db.models.group_invite import GroupInvite
from app.schemas.chats import ConversationCreate, ConversationResponse, AddMembersRequest, InviteLinkResponse, JoinGroupRequest
from app.ws.connection_manager import manager
from beanie import PydanticObjectId
from datetime import timedelta
from app.utils.message_helper import update_conversation_after_create_message


logger = logging.getLogger("uvicorn.error")


class ChatService:
    """Service for managing conversations."""

    async def create_conversation(
        self, payload: ConversationCreate, current_user: User
    ) -> ConversationResponse:
        """Create a new conversation with participants."""
        try:
            # Validate participant_ids
            if not payload.participant_ids:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Danh sách người tham gia không được để trống",
                )

            # Convert participant_ids to ObjectId and add current user
            participant_ids = set()
            try:
                for pid in payload.participant_ids:
                    participant_ids.add(ObjectId(pid))
                participant_ids.add(ObjectId(str(current_user.id)))
            except (ValueError, TypeError) as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"ID người tham gia không hợp lệ: {str(e)}",
                ) from e

            # Determine conversation type
            if len(participant_ids) == 2:
                conv_type = "direct"

                # Check if direct conversation already exists
                # Find conversations where all these participant_ids exist
                participant_list = list(participant_ids)
                existing_convos = await Conversation.find(
                    Conversation.type == "direct"
                ).to_list()

                for conv in existing_convos:
                    conv_participant_ids = {
                        p.user_id for p in conv.participants}
                    if conv_participant_ids == set(participant_list):
                        return ConversationResponse(
                            id=str(conv.id),
                            title=None,
                        )
            else:
                conv_type = "group"

            # Create participants list
            participants = [
                Participant(user_id=pid, joined_at=datetime.now(timezone.utc))
                for pid in participant_ids
            ]

            # Create conversation
            conversation = Conversation(
                type=conv_type,
                participants=participants,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )

            # Add group info if it's a group conversation
            if conv_type == "group" and payload.title:
                conversation.group = Group(
                    name=payload.title,
                    created_by=ObjectId(str(current_user.id)),
                    created_at=datetime.now(timezone.utc),
                )

            # Save to database
            await conversation.insert()

            # If group, emit new-group event to all members
            if conv_type == "group":
                # Prepare user info for participants (displayName / avatar / username)
                user_docs = await User.find(
                    {"_id": {"$in": list(participant_ids)}},
                    projection_model=None,
                ).to_list()
                user_map = {
                    str(u.id): {
                        "displayName": u.display_name,
                        "avatarUrl": u.avatar_url,
                        "username": u.username,
                    }
                    for u in user_docs
                }

                # Format conversation for WebSocket
                created_at = conversation.created_at
                formatted_conv = {
                    "_id": str(conversation.id),
                    "type": conversation.type,
                    "name": payload.title or (conversation.group.name if conversation.group else None),
                    "participants": [
                        {
                            "_id": str(p.user_id),
                            "displayName": user_map.get(str(p.user_id), {}).get("displayName"),
                            "avatarUrl": user_map.get(str(p.user_id), {}).get("avatarUrl"),
                            "username": user_map.get(str(p.user_id), {}).get("username"),
                            "joinedAt": (
                                p.joined_at.isoformat() if p.joined_at else None
                            ),
                        }
                        for p in conversation.participants
                    ],
                    "group": (
                        {
                            "name": (
                                conversation.group.name if conversation.group else None
                            ),
                            "createdBy": (
                                str(conversation.group.created_by)
                                if conversation.group
                                else None
                            ),
                        }
                        if conversation.group
                        else None
                    ),
                    "createdAt": (
                        created_at.isoformat()
                        if isinstance(created_at, datetime)
                        else None
                    ),
                }

                # Emit to all members except current user
                member_ids = [
                    str(pid)
                    for pid in participant_ids
                    if str(pid) != str(current_user.id)
                ]
                await manager.emit_new_group(member_ids, formatted_conv)

                # Join all members to the conversation room
                for pid in participant_ids:
                    manager.join_room(str(pid), str(conversation.id))

            return ConversationResponse(
                id=str(conversation.id),
                title=(
                    payload.title
                    if payload.title
                    else (conversation.group.name if conversation.group else None)
                ),
            )
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Lỗi khi tạo cuộc trò chuyện: {str(e)}",
            )

    async def list_conversations(self, current_user: User) -> list[dict]:
        try:
            user_id = ObjectId(str(current_user.id))

            pipeline = [
                {"$match": {"participants.user_id": user_id}},
                {"$sort": {"updated_at": -1}},
                {
                    "$lookup": {
                        "from": "users",
                        "localField": "participants.user_id",
                        "foreignField": "_id",
                        "as": "participant_users",
                        "pipeline": [
                            {
                                "$project": {
                                    "display_name": 1,
                                    "avatar_url": 1,
                                    "username": 1,
                                }
                            }
                        ],
                    }
                },
                {
                    "$lookup": {
                        "from": "users",
                        "localField": "last_message.sender_id",
                        "foreignField": "_id",
                        "as": "sender_user",
                        "pipeline": [
                            {"$project": {"display_name": 1, "avatar_url": 1}}
                        ],
                    }
                },
                {
                    "$unwind": {
                        "path": "$sender_user",
                        "preserveNullAndEmptyArrays": True,
                    }
                },
            ]

            # Get pymongo collection and run aggregate
            collection = Conversation.get_pymongo_collection()
            cursor = collection.aggregate(pipeline)
            conversations = await cursor.to_list(length=None)

            result = []
            for conv in conversations:
                last_msg = conv.get("last_message")
                grp = conv.get("group")

                # Build user map from both participant_users and sender_user
                user_map = {
                    str(u["_id"]): {
                        "displayName": u.get("display_name"),
                        "avatarUrl": u.get("avatar_url"),
                        "username": u.get("username"),
                    }
                    for u in conv.get("participant_users", [])
                }

                if conv.get("sender_user"):
                    sender_id = str(conv["sender_user"]["_id"])
                    user_map[sender_id] = {
                        "displayName": conv["sender_user"].get("display_name"),
                        "avatarUrl": conv["sender_user"].get("avatar_url"),
                    }

                # Transform participants
                participants = [
                    {
                        "_id": str(p["user_id"]),
                        **user_map.get(str(p["user_id"]), {}),
                        "avatarUrl": user_map.get(str(p["user_id"]), {}).get(
                            "avatarUrl"
                        ),
                        "displayName": user_map.get(str(p["user_id"]), {}).get(
                            "displayName"
                        ),
                        "joinedAt": p.get("joined_at"),
                    }
                    for p in conv.get("participants", [])
                ]

                # Format last_message to match frontend interface
                last_message_formatted = None
                if last_msg:
                    sender_id_str = (
                        str(last_msg.get("sender_id"))
                        if last_msg.get("sender_id")
                        else None
                    )
                    sender_info = (
                        user_map.get(sender_id_str, {}
                                     ) if sender_id_str else {}
                    )

                    last_message_formatted = {
                        "_id": (
                            str(last_msg.get("message_id"))
                            if last_msg.get("message_id")
                            else None
                        ),
                        "content": last_msg.get("content"),
                        "createdAt": (
                            last_msg.get("created_at").isoformat()
                            if last_msg.get("created_at")
                            else None
                        ),
                        "sender": (
                            {
                                "_id": sender_id_str,
                                "displayName": sender_info.get("displayName"),
                                "avatarUrl": sender_info.get("avatarUrl"),
                            }
                            if sender_id_str
                            else None
                        ),
                        "counter": last_msg.get("counter"),
                        "keyVersion": last_msg.get("key_version"),
                    }

                # Convert group ObjectIds to strings (H3 fix)
                group_formatted = None
                if grp:
                    group_formatted = {
                        "name": grp.get("name"),
                        "avatar": grp.get("avatar"),
                        "createdBy": (
                            str(grp.get("created_by"))
                            if grp.get("created_by")
                            else None
                        ),
                        "createdAt": grp.get("created_at"),
                    }

                # Format unreadCount - convert ObjectId keys to strings
                raw_unread = conv.get("unread_counts", {})
                unread_count = {}
                if raw_unread:
                    for k, v in raw_unread.items():
                        unread_count[str(k)] = v

                # Format seenBy
                seen_by = []
                for seen_user_id in conv.get("seen_by", []):
                    seen_id_str = str(seen_user_id)
                    seen_info = user_map.get(seen_id_str, {})
                    seen_by.append(
                        {
                            "_id": seen_id_str,
                            "displayName": seen_info.get("displayName"),
                            "avatarUrl": seen_info.get("avatarUrl"),
                        }
                    )

                # Format dates
                created_at = conv.get("created_at")
                updated_at = conv.get("updated_at")
                last_message_at = conv.get("last_message_at")

                result.append(
                    {
                        "_id": str(conv["_id"]),
                        "type": conv.get("type"),
                        "participants": participants,
                        "lastMessage": last_message_formatted,
                        "lastMessageAt": (
                            last_message_at.isoformat() if last_message_at else None
                        ),
                        "seenBy": seen_by,
                        "unreadCount": unread_count,
                        "createdAt": created_at.isoformat() if created_at else None,
                        "updatedAt": updated_at.isoformat() if updated_at else None,
                        "group": group_formatted,
                    }
                )

            return result

        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Lỗi khi lấy danh sách cuộc trò chuyện: {str(e)}",
            ) from e

    async def get_messages(
        self,
        conversation_id: str,
        current_user: User,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict:
        """Get messages from a conversation with cursor-based pagination."""
        try:
            user_id = ObjectId(str(current_user.id))
            conv_id = ObjectId(conversation_id)

            # Verify user is a participant
            conversation = await Conversation.find_one(
                {"_id": conv_id, "participants.user_id": user_id}
            )
            if not conversation:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Cuộc trò chuyện không tồn tại hoặc bạn không có quyền truy cập",
                )

            # Build query
            query = {"conversation_id": conv_id}
            if cursor:
                try:
                    cursor_datetime = datetime.fromisoformat(
                        cursor.replace("Z", "+00:00")
                    )
                    query["timestamps"] = {"$lt": cursor_datetime}
                except ValueError:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Cursor không hợp lệ",
                    )

            # Fetch messages + 1 to check if there's more
            messages = (
                await Message.find(query).sort("-timestamps").limit(limit + 1).to_list()
            )

            # Determine next cursor BEFORE reversing
            next_cursor = None
            if len(messages) > limit:
                # Last message (oldest) after desc sort
                next_message = messages[-1]
                next_cursor = next_message.timestamps.isoformat()
                messages.pop()  # Remove the extra message

            # Reverse to get chronological order
            messages.reverse()

            # Format messages
            formatted_messages = [
                {
                    "_id": str(msg.id),
                    "conversationId": str(msg.conversation_id),
                    "senderId": str(msg.sender_id),
                    "content": msg.content,
                    "imgUrl": msg.imgUrl,
                    "createdAt": msg.timestamps.isoformat() if msg.timestamps else None,
                    "keyVersion": msg.key_version,  # For E2EE group messages
                    # For anti-replay protection (E2EE direct messages)
                    "counter": msg.counter,
                }
                for msg in messages
            ]

            return {
                "messages": formatted_messages,
                "nextCursor": next_cursor,
            }

        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Lỗi khi lấy tin nhắn: {str(e)}",
            ) from e

    async def mark_as_seen(self, conversation_id: str, current_user: User) -> dict:
        """Mark messages in a conversation as seen by the current user."""
        try:
            user_id = ObjectId(str(current_user.id))
            conv_id = ObjectId(conversation_id)

            # Find conversation
            conversation = await Conversation.find_one(
                {"_id": conv_id, "participants.user_id": user_id}
            )
            if not conversation:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Cuộc trò chuyện không tồn tại",
                )

            # Check if there's a last message
            if not conversation.last_message:
                return {"message": "Không có tin nhắn để đánh dấu đã đọc"}

            # Don't mark as seen if the current user is the sender
            if conversation.last_message.sender_id == user_id:
                return {"message": "Sender không cần đánh dấu đã đọc"}

            # Update unread count for current user to 0
            user_id_str = str(user_id)
            if conversation.unread_counts is None:
                conversation.unread_counts = {}

            conversation.unread_counts[user_id] = 0
            await conversation.save()

            # Emit read-message event via WebSocket
            await manager.emit_read_message(
                conversation_id=conversation_id,
                conversation={
                    "_id": str(conversation.id),
                    "unreadCounts": {
                        str(k): v for k, v in conversation.unread_counts.items()
                    },
                },
                last_message=(
                    {
                        "_id": str(conversation.last_message.message_id),
                        "content": conversation.last_message.content,
                        "createdAt": (
                            conversation.last_message.created_at.isoformat()
                            if conversation.last_message.created_at
                            else None
                        ),
                        "sender": {
                            "_id": str(conversation.last_message.sender_id),
                        },
                        "counter": conversation.last_message.counter,
                        "keyVersion": conversation.last_message.key_version,
                    }
                    if conversation.last_message
                    else None
                ),
            )

            return {
                "message": "Đã đánh dấu đã đọc",
                "conversationId": str(conversation.id),
                "unreadCount": 0,
            }
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Lỗi khi đánh dấu đã đọc: {str(e)}",
            ) from e

    async def delete_conversation(
        self, conversation_id: str, current_user: User
    ) -> dict:
        """Delete a conversation for the current user."""
        try:
            if not ObjectId.is_valid(conversation_id):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="ID cuộc trò chuyện không hợp lệ",
                )

            conv_id = ObjectId(conversation_id)
            conversation = await Conversation.get(conv_id)

            if not conversation:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Cuộc trò chuyện không tồn tại",
                )

            # Check if user is a participant
            user_id = ObjectId(str(current_user.id))
            is_participant = any(
                p.user_id == user_id for p in conversation.participants
            )

            if not is_participant:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Bạn không có quyền xóa cuộc trò chuyện này",
                )

            # Delete conversation
            await conversation.delete()

            # Delete all messages in the conversation
            await Message.find(Message.conversation_id == conv_id).delete()

            return {
                "message": "Đã xóa cuộc trò chuyện",
                "conversationId": conversation_id,
            }
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Lỗi khi xóa cuộc trò chuyện: {str(e)}",
            ) from e

    async def get_user_conversation_ids(self, user_id: str) -> list[str]:
        """Get all conversation IDs for a user (for WebSocket room joining)."""
        try:
            uid = ObjectId(user_id)
            conversations = await Conversation.find(
                {"participants.user_id": uid}, projection_model=None
            ).to_list()

            return [str(conv.id) for conv in conversations]
        except Exception as e:
            # Don't raise, just return empty list for WebSocket
            return []

    async def add_members_to_group(
        self, conversation_id: str, payload: AddMembersRequest, current_user: User
    ) -> dict:
        """Add members to an existing group conversation."""
        try:
            user_id = ObjectId(str(current_user.id))
            conv_id = ObjectId(conversation_id)

            # Find conversation
            conversation = await Conversation.find_one(
                {"_id": conv_id, "participants.user_id": user_id}
            )
            if not conversation:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Cuộc trò chuyện không tồn tại",
                )

            # Check if it's a group conversation
            if conversation.type != "group":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Chỉ có thể thêm thành viên vào group chat",
                )

            # Check if current user is the group owner
            if not conversation.group or not conversation.group.created_by:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Nhóm không hợp lệ",
                )

            if conversation.group.created_by != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Chỉ chủ nhóm mới có thể thêm thành viên",
                )

            # Convert member_ids to ObjectId
            new_member_ids = set()
            try:
                for mid in payload.member_ids:
                    new_member_ids.add(ObjectId(mid))
            except (ValueError, TypeError) as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"ID thành viên không hợp lệ: {str(e)}",
                ) from e

            # Get existing participant IDs
            existing_participant_ids = {
                p.user_id for p in conversation.participants}

            # Filter out users who are already members
            users_to_add = new_member_ids - existing_participant_ids
            users_already_members = new_member_ids & existing_participant_ids

            if not users_to_add:
                already_member_list = []
                if users_already_members:
                    already_users = await User.find(
                        {"_id": {"$in": list(users_already_members)}},
                        projection_model=None,
                    ).to_list()
                    already_member_list = [str(u.id) for u in already_users]

                return {
                    "message": "Tất cả người dùng đã là thành viên của nhóm",
                    "added_count": 0,
                    "already_members": already_member_list,
                }

            # Verify users exist
            existing_users = await User.find(
                {"_id": {"$in": list(users_to_add)}},
                projection_model=None,
            ).to_list()

            if len(existing_users) != len(users_to_add):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Một số người dùng không tồn tại",
                )

            # Add new participants
            new_participants = [
                Participant(user_id=uid, joined_at=datetime.now(timezone.utc))
                for uid in users_to_add
            ]
            conversation.participants.extend(new_participants)

            # Initialize unread_counts for new members
            if conversation.unread_counts is None:
                conversation.unread_counts = {}
            for uid in users_to_add:
                conversation.unread_counts[uid] = 0

            await conversation.save()

            # Join new members to WebSocket room
            for uid in users_to_add:
                manager.join_room(str(uid), str(conversation.id))

            # Emit event to notify new members
            member_ids = [str(uid) for uid in users_to_add]
            formatted_conv = {
                "_id": str(conversation.id),
                "type": conversation.type,
                "group": {
                    "name": conversation.group.name if conversation.group else None,
                } if conversation.group else None,
                "createdAt": conversation.created_at.isoformat(),
            }
            await manager.emit_new_group(member_ids, formatted_conv)

            # Emit update event to existing members
            existing_member_ids = [str(pid)
                                   for pid in existing_participant_ids]
            await manager.broadcast_to_room(
                str(conversation.id),
                "group-members-added",
                {
                    "conversationId": str(conversation.id),
                    "newMembers": [
                        {
                            "_id": str(u.id),
                            "displayName": u.display_name,
                            "username": u.username,
                            "avatarUrl": u.avatar_url,
                        }
                        for u in existing_users
                    ],
                },
            )

            # Get info about users who were already members (if any)
            already_member_list = []
            if users_already_members:
                already_users = await User.find(
                    {"_id": {"$in": list(users_already_members)}},
                    projection_model=None,
                ).to_list()
                already_member_list = [str(u.id) for u in already_users]

            message = f"Đã thêm {len(users_to_add)} thành viên vào nhóm"
            if users_already_members:
                message += f" ({len(users_already_members)} người đã là thành viên)"

            return {
                "message": message,
                "added_count": len(users_to_add),
                "already_members_count": len(users_already_members),
                "already_members": already_member_list,
                "conversationId": str(conversation.id),
            }
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Lỗi khi thêm thành viên: {str(e)}",
            ) from e

    async def create_invite_link(
        self, conversation_id: str, current_user: User, expires_days: int | None = 7
    ) -> InviteLinkResponse:
        """Create an invite link for a group conversation."""
        try:
            user_id = ObjectId(str(current_user.id))
            conv_id = ObjectId(conversation_id)

            # Find conversation and verify user is a member
            conversation = await Conversation.find_one(
                {"_id": conv_id, "participants.user_id": user_id}
            )
            if not conversation:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Cuộc trò chuyện không tồn tại",
                )

            # Check if it's a group conversation
            if conversation.type != "group":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Chỉ có thể tạo invite link cho group chat",
                )

            # Check if current user is the group owner
            if not conversation.group or not conversation.group.created_by:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Nhóm không hợp lệ",
                )

            if conversation.group.created_by != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Chỉ chủ nhóm mới có thể tạo invite link",
                )

            # Generate unique invite code
            invite_code = GroupInvite.generate_invite_code()

            # Ensure uniqueness - use dict query for Beanie
            while await GroupInvite.find_one({"invite_code": invite_code}):
                invite_code = GroupInvite.generate_invite_code()

            # Calculate expiration - ensure timezone-aware
            expires_at = None
            if expires_days:
                expires_at = datetime.now(
                    timezone.utc) + timedelta(days=expires_days)

            # Create invite link
            invite = GroupInvite(
                conversation_id=conv_id,
                invite_code=invite_code,
                created_by=user_id,
                expires_at=expires_at,
                max_uses=None,  # No limit by default
                is_active=True,
            )
            await invite.insert()

            # Generate invite URL (frontend will handle the full URL)
            invite_url = f"/join-group/{invite_code}"

            return InviteLinkResponse(
                invite_code=invite_code,
                invite_url=invite_url,
                expires_at=expires_at.isoformat() if expires_at else None,
            )
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Lỗi khi tạo invite link: {str(e)}",
            ) from e

    async def join_group_via_invite(
        self, payload: JoinGroupRequest, current_user: User
    ) -> ConversationResponse:
        """Join a group conversation via invite code."""
        try:
            user_id = ObjectId(str(current_user.id))
            logger.info(
                f"[JoinGroup] User {user_id} attempting to join with invite code: {payload.invite_code}")

            # Find invite link - use dict query for Beanie
            invite = await GroupInvite.find_one(
                {"invite_code": payload.invite_code}
            )
            if not invite:
                logger.warning(
                    f"[JoinGroup] Invite code not found: {payload.invite_code}")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Mã invite không hợp lệ",
                )

            # Check if invite can be used
            if not invite.can_be_used():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Mã invite đã hết hạn hoặc không còn hoạt động",
                )

            # Find conversation - use dict query for Beanie
            conversation = await Conversation.find_one(
                {"_id": invite.conversation_id}
            )
            if not conversation:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Group không tồn tại",
                )

            # Check if user is already a member
            existing_participant_ids = {
                p.user_id for p in conversation.participants}
            if user_id in existing_participant_ids:
                logger.info(
                    f"[JoinGroup] User {user_id} is already a member of group {conversation.id}")
                # Return conversation info but indicate user is already a member
                # Frontend will handle this case
                return ConversationResponse(
                    id=str(conversation.id),
                    title=conversation.group.name if conversation.group else None,
                )

            # Add user as participant
            new_participant = Participant(
                user_id=user_id, joined_at=datetime.now(timezone.utc)
            )
            conversation.participants.append(new_participant)

            # Initialize unread count
            if conversation.unread_counts is None:
                conversation.unread_counts = {}
            conversation.unread_counts[user_id] = 0

            await conversation.save()

            # Update invite usage
            try:
                invite.used_count += 1
                await invite.save()
            except Exception as e:
                logger.error(f"Error updating invite usage: {e}")

            # Join WebSocket room
            try:
                manager.join_room(str(user_id), str(conversation.id))
            except Exception as e:
                logger.error(f"Error joining WebSocket room: {e}")

            # Emit new-group event to notify user
            try:
                formatted_conv = {
                    "_id": str(conversation.id),
                    "type": conversation.type,
                    "group": {
                        "name": conversation.group.name if conversation.group else None,
                    } if conversation.group else None,
                    "createdAt": conversation.created_at.isoformat(),
                }
                await manager.emit_new_group([str(user_id)], formatted_conv)
            except Exception as e:
                logger.error(f"Error emitting new-group event: {e}")

            # Notify existing members
            try:
                existing_member_ids = [str(pid)
                                       for pid in existing_participant_ids]
                user_doc = await User.get(user_id)
                if user_doc:
                    await manager.broadcast_to_room(
                        str(conversation.id),
                        "group-members-added",
                        {
                            "conversationId": str(conversation.id),
                            "newMembers": [
                                {
                                    "_id": str(user_doc.id),
                                    "displayName": user_doc.display_name,
                                    "username": user_doc.username,
                                    "avatarUrl": user_doc.avatar_url,
                                }
                            ],
                        },
                    )
            except Exception as e:
                logger.error(f"Error broadcasting to room: {e}")

            return ConversationResponse(
                id=str(conversation.id),
                title=conversation.group.name if conversation.group else None,
            )
        except HTTPException:
            raise
        except Exception as e:
            logger.error(
                f"[JoinGroup] Error joining group: {e}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Lỗi khi join group: {str(e)}",
            ) from e

    async def leave_group(
        self, conversation_id: str, current_user: User
    ) -> dict:
        """Leave a group conversation."""
        try:
            user_id = ObjectId(str(current_user.id))
            conv_id = ObjectId(conversation_id)

            # Find conversation
            conversation = await Conversation.find_one(
                {"_id": conv_id}
            )
            if not conversation:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Cuộc trò chuyện không tồn tại",
                )

            # Check if it's a group conversation
            if conversation.type != "group":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Chỉ có thể rời group chat",
                )

            # Check if user is a member
            existing_participant_ids = {
                p.user_id for p in conversation.participants}
            if user_id not in existing_participant_ids:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Bạn không phải thành viên của nhóm này",
                )

            # Check if user is the group owner
            is_owner = (
                conversation.group
                and conversation.group.created_by
                and conversation.group.created_by == user_id
            )

            # Remove user from participants
            conversation.participants = [
                p for p in conversation.participants if p.user_id != user_id
            ]

            # Remove unread count
            if conversation.unread_counts and user_id in conversation.unread_counts:
                del conversation.unread_counts[user_id]

            await conversation.save()

            # Leave WebSocket room
            try:
                manager.leave_room(str(user_id), str(conversation.id))
            except Exception as e:
                logger.error(f"Error leaving WebSocket room: {e}")

            # Create system message to notify remaining members
            try:
                remaining_member_ids = [
                    str(pid) for pid in existing_participant_ids if pid != user_id]
                user_doc = await User.get(user_id)
                if user_doc and remaining_member_ids:
                    # Import MessageService here to avoid circular import
                    from app.services.message_service import MessageService
                    message_service = MessageService()

                    # Use special format for system messages
                    system_content = f"SYSTEM:user_left:{str(user_doc.id)}:{user_doc.display_name or user_doc.username}"

                    # Create message with sender_id = user_id (for tracking) but mark as system
                    system_message = Message(
                        conversation_id=conversation.id,
                        sender_id=user_id,  # Keep sender_id for reference
                        content=system_content,
                        timestamps=datetime.now(timezone.utc),
                    )
                    await system_message.insert()

                    # Update conversation last_message
                    await update_conversation_after_create_message(
                        conversation, system_message, user_id
                    )

                    # Format conversation with updated participants count
                    formatted_conv = await message_service._format_conversation_for_ws(conversation)

                    # Emit system message and updated conversation
                    await manager.emit_new_message(
                        conversation_id=str(conversation.id),
                        message=message_service._format_message(
                            system_message),
                        conversation_data=formatted_conv,
                        unread_counts={
                            str(k): v for k, v in conversation.unread_counts.items()},
                        participant_ids=None  # Broadcast to room
                    )

                    # Also emit group-members-removed event for UI updates
                    await manager.broadcast_to_room(
                        str(conversation.id),
                        "group-members-removed",
                        {
                            "conversationId": str(conversation.id),
                            "removedMembers": [
                                {
                                    "_id": str(user_doc.id),
                                    "displayName": user_doc.display_name,
                                    "username": user_doc.username,
                                    "avatarUrl": user_doc.avatar_url,
                                }
                            ],
                        },
                    )
            except Exception as e:
                logger.error(
                    f"Error creating system message and broadcasting: {e}")

            return {
                "message": "Đã rời nhóm thành công",
                "conversationId": str(conversation.id),
                "wasOwner": is_owner,
            }
        except HTTPException:
            raise
        except Exception as e:
            logger.error(
                f"[LeaveGroup] Error leaving group: {e}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Lỗi khi rời nhóm: {str(e)}",
            ) from e
