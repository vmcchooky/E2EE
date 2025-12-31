from fastapi import HTTPException, status

from app.db.models import User


class UserService:
    """Service for user-related business logic."""

    async def get_user_profile(self, user: User) -> dict:
        """Get user profile information."""
        user_id = str(user.id) if hasattr(user, 'id') else str(user._id)
        return {
            "user": {
                "_id": user_id,
                "username": user.username,
                "email": user.email,
                "firstname": user.first_name,
                "lastname": user.last_name,
                "displayName": user.display_name,
                "avatarUrl": user.avatar_url,
                "bio": user.bio,
                "phone": user.phone,
                "createdAt": user.created_at.isoformat() if user.created_at else None,
                "updatedAt": user.updated_at.isoformat() if user.updated_at else None,
            }
        }

    async def search_by_username(self, username: str) -> dict:
        """Search for a user by username."""
        if not username or username.strip() == "":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cần cung cấp username trong query.",
            )

        user = await User.find_one(User.username == username.strip().lower())

        if not user:
            return {"user": None}

        return {
            "user": {
                "_id": str(user.id),
                "username": user.username,
                "displayName": user.display_name,
                "avatarUrl": user.avatar_url,
            }
        }
