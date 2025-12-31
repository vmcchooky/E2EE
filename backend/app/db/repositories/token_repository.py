from app.db.models import Token
from beanie.odm.fields import PydanticObjectId
from fastapi import HTTPException
from beanie.operators import Eq


class TokenRepository:
    """Repository for token operations."""

    async def get_by_refresh_token(self, refresh_token: str) -> Token | None:
        
        return await Token.find_one(
            Eq(Token.refresh_token, refresh_token),
            Eq(Token.revoked, False),
        )

    async def get_by_user_id(self, user_id: PydanticObjectId) -> Token | None:
        return await Token.find_one(Token.user_id == user_id)

    async def save(self, token: Token) -> Token:
        return await token.save()

    async def delete_all_tokens(self, user_id: PydanticObjectId) -> None:
        """Delete all tokens for a user (used on logout)."""
        await Token.find(Token.user_id == user_id).delete()
