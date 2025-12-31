from fastapi import APIRouter, Depends, Query

from app.dependencies.auth import get_current_user
from app.db.models import User
from app.services.user_service import UserService

router = APIRouter()


@router.get("/me")
async def get_current_user_info(
    current_user: User = Depends(get_current_user),
    service: UserService = Depends(UserService),
) -> dict:
    """Get current authenticated user information."""
    return await service.get_user_profile(current_user)


@router.get("/search")
async def search_user_by_username(
    username: str = Query(..., min_length=1,
                          description="Username để tìm kiếm"),
    # Required for authentication
    _current_user: User = Depends(get_current_user),
    service: UserService = Depends(UserService),
) -> dict:
    """Search for a user by username."""
    return await service.search_by_username(username)
