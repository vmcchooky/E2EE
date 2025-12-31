from typing import List
from fastapi import APIRouter, Depends, status

from app.dependencies.auth import get_current_user
from app.db.models import User
from app.schemas.friend import (
    FriendRequestCreate,
    FriendRequestResponse,
    FriendProfile,
    AllFriendRequestsResponse,
)
from app.schemas.response import BaseResponse
from app.services.friend_service import FriendService

router = APIRouter()


@router.post(
    "/requests", response_model=BaseResponse[None], status_code=status.HTTP_201_CREATED
)
async def send_friend_request(
    payload: FriendRequestCreate,
    current_user: User = Depends(get_current_user),
    service: FriendService = Depends(FriendService),
) -> BaseResponse[None]:
    """Send a friend request to another user."""
    await service.send_friend_request(str(current_user.id), payload)
    return BaseResponse(
        status_code=status.HTTP_201_CREATED,
        success=True,
        message="Đã gửi yêu cầu kết bạn thành công",
        data=None,
    )


@router.post(
    "/requests/{request_id}/accept",
    response_model=BaseResponse[None],
    status_code=status.HTTP_200_OK,
)
async def accept_friend_request(
    request_id: str,
    current_user: User = Depends(get_current_user),
    service: FriendService = Depends(FriendService),
) -> BaseResponse[None]:
    """Accept a friend request."""
    await service.accept_friend_request(request_id, str(current_user.id))
    return BaseResponse(
        status_code=status.HTTP_200_OK,
        success=True,
        message="Đã chấp nhận yêu cầu kết bạn",
        data=None,
    )


@router.post(
    "/requests/{request_id}/decline",
    response_model=BaseResponse[None],
    status_code=status.HTTP_200_OK,
)
async def decline_friend_request(
    request_id: str,
    current_user: User = Depends(get_current_user),
    service: FriendService = Depends(FriendService),
) -> BaseResponse[None]:
    """Decline a friend request."""
    await service.decline_friend_request(request_id, str(current_user.id))
    return BaseResponse(
        status_code=status.HTTP_200_OK,
        success=True,
        message="Đã từ chối yêu cầu kết bạn",
        data=None,
    )


@router.get(
    "/",
    response_model=BaseResponse[List[FriendProfile]],
    status_code=status.HTTP_200_OK,
)
async def get_all_friends(
    current_user: User = Depends(get_current_user),
    service: FriendService = Depends(FriendService),
) -> BaseResponse[List[FriendProfile]]:
    """Get all friends of the current user with basic profile info."""
    friends = await service.get_all_friends(str(current_user.id))
    return BaseResponse(
        status_code=status.HTTP_200_OK,
        success=True,
        message="Lấy danh sách bạn bè thành công",
        data=friends,
    )


@router.get(
    "/requests",
    response_model=BaseResponse[AllFriendRequestsResponse],
    status_code=status.HTTP_200_OK,
    response_model_by_alias=True,
)
async def get_friends_request(
    current_user: User = Depends(get_current_user),
    service: FriendService = Depends(FriendService),
) -> BaseResponse[AllFriendRequestsResponse]:
    """Get all friend requests for the current user (both sent and received)."""
    requests = await service.get_friends_request(str(current_user.id))
    return BaseResponse(
        status_code=status.HTTP_200_OK,
        success=True,
        message="Lấy danh sách yêu cầu kết bạn thành công",
        data=AllFriendRequestsResponse(**requests),
    )
