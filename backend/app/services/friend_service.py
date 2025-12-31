from fastapi import HTTPException, status
from bson import ObjectId
from bson.errors import InvalidId
from typing import List
from beanie.operators import In

from app.schemas.friend import (
    FriendRequestCreate,
    FriendRequestResponse,
    FriendProfile,
    UserInfo,
)
from app.db.models.friend import Friend
from app.db.models.friend_request import FriendRequest
from app.db.models.user import User
from app.db.repositories.user_repository import UserRepository
import logging

import asyncio

logger = logging.getLogger("uvicorn.error")


class FriendService:
    """Service for managing friends."""

    def __init__(self):
        self.user_repository = UserRepository()

    async def send_friend_request(
        self, from_user_id: str, payload: FriendRequestCreate
    ) -> None:
        """Send a friend request from one user to another."""
        try:
            from_id = ObjectId(from_user_id)
            to_user = ObjectId(payload.to_user)

            if from_id == to_user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Không thể gửi yêu cầu kết bạn cho chính mình",
                )

            # userA < userB
            userA, userB = (
                (from_id, to_user) if from_id < to_user else (to_user, from_id)
            )

            # Run parallel checks
            user_obj, is_friend, request_obj = await asyncio.gather(
                self.user_repository.get_by_id(str(to_user)),
                Friend.find(
                    Friend.userA == userA, Friend.userB == userB
                ).first_or_none(),
                FriendRequest.find_one(
                    FriendRequest.from_user == from_id,
                    FriendRequest.to_user == to_user,
                ),
            )

            # Check if to_user exists
            if user_obj is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Người dùng không tồn tại",
                )

            # Check if already friends
            if is_friend:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail="Đã là bạn bè"
                )

            # Check if request already exists
            if request_obj is not None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Đã gửi yêu cầu kết bạn truớc đó",
                )

            # Create friend request
            friend_request = FriendRequest(
                from_user=from_id, to_user=to_user, message=payload.message
            )

            await friend_request.insert()

        except (TypeError, InvalidId) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"ID người dùng không hợp lệ: {str(exc)}",
            ) from exc
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Error sending friend request: %s", str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Lỗi server khi gửi yêu cầu kết bạn: {str(e)}",
            ) from e

    async def accept_friend_request(
        self, request_id: str, current_user_id: str
    ) -> None:
        """Accept a friend request."""
        try:
            req_id = ObjectId(request_id)
            user_id = ObjectId(current_user_id)

            # Find the request
            request = await FriendRequest.get(req_id)
            if not request:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Không tìm thấy yêu cầu kết bạn",
                )

            # Verify the request is for current user
            if request.to_user != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Không có quyền chấp nhận yêu cầu này",
                )

            # Create friendship (normalized order)
            friend = Friend(userA=request.from_user, userB=request.to_user)
            await friend.insert()

            # Delete the request
            await request.delete()
        except (TypeError, InvalidId):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="ID không hợp lệ",
            )
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Lỗi khi chấp nhận yêu cầu kết bạn: {str(e)}",
            ) from e

    async def decline_friend_request(
        self, request_id: str, current_user_id: str
    ) -> None:
        """Decline a friend request."""
        try:
            req_id = ObjectId(request_id)
            user_id = ObjectId(current_user_id)

            request = await FriendRequest.get(req_id)
            if not request:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Không tìm thấy yêu cầu kết bạn",
                )

            if request.to_user != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Không có quyền từ chối yêu cầu này",
                )

            await request.delete()
        except (TypeError, InvalidId) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"ID không hợp lệ: {str(exc)}",
            ) from exc
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
            ) from e

    async def get_all_friends(self, user_id: str) -> List[FriendProfile]:
        """Get all friends of a user. Returns profile info for each friend."""
        try:
            uid = ObjectId(user_id)

            # Find all friendships where user is either userA or userB in parallel
            friends_as_a, friends_as_b = await asyncio.gather(
                Friend.find(Friend.userA == uid).to_list(),
                Friend.find(Friend.userB == uid).to_list(),
            )

            friend_ids: list[ObjectId] = []
            for friend in friends_as_a:
                friend_ids.append(friend.userB)
            for friend in friends_as_b:
                friend_ids.append(friend.userA)

            if not friend_ids:
                return []

            # Fetch user profiles in one query
            users = await User.find(In(User.id, friend_ids)).to_list()
            profiles = [
                FriendProfile(
                    id=str(u.id),
                    username=u.username,
                    displayName=u.display_name,
                    avatarUrl=u.avatar_url,
                )
                for u in users
            ]
            return profiles
        except (TypeError, InvalidId) as exc:
            logger.error(exc)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"ID người dùng không hợp lệ: {str(exc)}",
            ) from exc
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
            ) from e

    async def get_friends_request(
        self, user_id: str
    ) -> dict[str, List[FriendRequestResponse]]:
        """Get all friend requests for a user (both sent and received)."""
        try:
            uid = ObjectId(user_id)

            # Fetch both sent and received requests
            sent_requests, received_requests = await asyncio.gather(
                FriendRequest.find(FriendRequest.from_user == uid).to_list(),
                FriendRequest.find(FriendRequest.to_user == uid).to_list(),
            )

            # Collect all unique user IDs
            user_ids = set()
            for req in sent_requests:
                user_ids.add(req.to_user)
            for req in received_requests:
                user_ids.add(req.from_user)

            # Fetch all users in one query if there are any user IDs
            users_map = {}
            if user_ids:
                users_list = await User.find(In(User.id, list(user_ids))).to_list()
                users_map = {user.id: user for user in users_list}

            # Build sent requests with user info
            sent = []
            for req in sent_requests:
                to_user = users_map.get(req.to_user)
                if to_user:
                    sent.append(
                        FriendRequestResponse(
                            id=str(req.id),
                            from_=None,
                            to=UserInfo(
                                id=str(to_user.id),
                                username=to_user.username,
                                displayName=to_user.display_name or to_user.username,
                                avatarUrl=to_user.avatar_url,
                            ),
                            message=req.message,
                            createdAt=req.timestamps,
                            updatedAt=req.timestamps,
                        )
                    )

            # Build received requests with user info
            received = []
            for req in received_requests:
                from_user = users_map.get(req.from_user)
                if from_user:
                    received.append(
                        FriendRequestResponse(
                            id=str(req.id),
                            from_=UserInfo(
                                id=str(from_user.id),
                                username=from_user.username,
                                displayName=from_user.display_name or from_user.username,
                                avatarUrl=from_user.avatar_url,
                            ),
                            to=None,
                            message=req.message,
                            createdAt=req.timestamps,
                            updatedAt=req.timestamps,
                        )
                    )

            return {"sent": sent, "received": received}

        except (TypeError, InvalidId) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"ID người dùng không hợp lệ: {str(exc)}",
            ) from exc
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Error getting friend requests: %s", str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Lỗi khi lấy danh sách yêu cầu kết bạn: {str(e)}",
            ) from e
