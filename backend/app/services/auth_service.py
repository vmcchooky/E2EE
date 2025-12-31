from fastapi import HTTPException, status
from datetime import datetime, timezone
import logging

from app.core.security import create_access_token, create_refresh_token
from app.db.models.user import User
from app.db.repositories.user_repository import UserRepository
from app.schemas.auth import RegisterRequest, Token, LoginRequest
from app.utils.hashing import hash_password
from app.db.repositories.token_repository import TokenRepository
from app.utils.hashing import verify_password
from app.services.token_service import TokenService

logger = logging.getLogger("uvicorn.error")


class AuthService:

    def __init__(self):
        self.user_repository = UserRepository()
        self.token_repository = TokenRepository()
        self.token_service = TokenService()

    async def register(self, request: RegisterRequest) -> None:
        try:
            user = await self.user_repository.get_by_username(request.username)
            if user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username đã tồn tại",
                )

            user = await self.user_repository.get_by_email(request.email)
            if user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email đã tồn tại"
                )

            hashed_password = hash_password(request.password)

            # Generate display_name từ firstname và lastname
            display_name = f"{request.firstname} {request.lastname}".strip()
            if not display_name:
                display_name = request.username

            user = User(
                username=request.username,
                email=request.email,
                hashed_password=hashed_password,
                first_name=request.firstname,
                last_name=request.lastname,
                display_name=display_name,
            )

            await self.user_repository.save(user)
            return None
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Error registering user: %s", str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(
                    e)
            ) from e

    async def login(self, request: LoginRequest) -> tuple[Token, str]:
        """Login user and return access token and refresh token."""
        try:
            user = await self.user_repository.get_by_username(request.username)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username hoặc mật khẩu không chính xác",
                )
            if not verify_password(request.password, user.hashed_password):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Username hoặc mật khẩu không chính xác",
                )

            access_token = create_access_token(str(user.id))
            refresh_token = create_refresh_token(str(user.id))

            await self.token_service.store_token(user.id, refresh_token)

            return Token(access_token=access_token), refresh_token
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Error logging in user: %s", str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(
                    e)
            ) from e

    def validate_refresh_token_exists(self, refresh_token: str | None) -> str:
        """Validate that refresh token exists in request. Returns the token if valid."""
        if not refresh_token:
            logger.warning("Refresh token missing from request cookies")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing refresh token. Please login again.",
            )
        return refresh_token

    async def refresh_token(self, refresh_token: str | None) -> tuple[Token, str]:
        """Refresh access token using refresh token. Returns new access token and new refresh token."""
        try:
            # Validate refresh token exists
            token = self.validate_refresh_token_exists(refresh_token)

            # validate refresh token in DB
            token_doc = await self.token_repository.get_by_refresh_token(token)
            if not token_doc:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid refresh token",
                )
            expires_at = token_doc.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

            if expires_at < datetime.now(timezone.utc):
                raise HTTPException(401, "Refresh token expired")

            # decode to get user_id
            user_id = self.token_service.verify_refresh_token(token)

            # ensure user exists
            user = await self.user_repository.get_by_id(user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
                )

            # rotate tokens
            new_access_token = create_access_token(str(user_id))
            new_refresh_token = create_refresh_token(str(user_id))

            await self.token_service.revoke_token(token)
            await self.token_service.store_token(user.id, new_refresh_token)

            return Token(access_token=new_access_token), new_refresh_token
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Error refreshing token: %s", str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(
                    e)
            ) from e

    async def logout(self, refresh_token: str | None) -> None:
        """Logout user by revoking refresh token."""
        try:
            # Validate refresh token exists
            token = self.validate_refresh_token_exists(refresh_token)
            await self.token_service.revoke_token(token)
            return None
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Error logging out user: %s", str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(
                    e)
            ) from e

    @staticmethod
    def to_utc(dt):
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt
