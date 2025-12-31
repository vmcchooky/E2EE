from datetime import datetime, timedelta, timezone
import logging
from typing import Any


from beanie.odm.fields import PydanticObjectId
from fastapi import HTTPException, status
from jose import JWTError, jwt

from app.db.repositories.token_repository import TokenRepository
from app.db.models.token import Token
import app.core.security as security
from app.core.config import get_settings

logger = logging.getLogger("uvicorn.error")

class TokenService:

    def __init__(self):
        self.token_repository = TokenRepository()
        self.settings = get_settings()

    async def store_token(self, user_id: PydanticObjectId, refresh_token: str) -> None:
        """Persist/replace refresh token for a user."""
        try:
            # chỉ giữ một refresh token/phiên cho mỗi user để dễ revoke
            await self.token_repository.delete_all_tokens(user_id)
            token = Token(
                user_id=user_id,
                refresh_token=refresh_token,
                expires_at=datetime.now(timezone.utc)
                + timedelta(days=self.settings.refresh_token_expire_days),
                revoked=False,
            )
            await self.token_repository.save(token)
        except Exception as e:
            logger.error("Error storing token: %s", str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(
                    e)
            ) from e

    async def revoke_token(self, refresh_token: str) -> bool:
        try:
            token = await self.token_repository.get_by_refresh_token(refresh_token)
            if not token:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
            token.revoked = True
            await self.token_repository.save(token)
            return True
        except Exception as e:
            logger.error("Error revoking token: %s", str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)) from e

    def verify_refresh_token(self, refresh_token: str) -> str:
        """Decode refresh token and return user_id (sub)."""
        try:
            return security.verify_access_token(refresh_token)
        except ValueError as exc:
            logger.error("Error verifying refresh token: %s", str(exc))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
            ) from exc
