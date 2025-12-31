from fastapi import WebSocket
from app.core.security import verify_access_token
from app.db.models import User
import logging

logger = logging.getLogger("uvicorn.error")


async def authenticate_websocket(websocket: WebSocket) -> User | None:
    """
    Authenticate WebSocket connection using token from query params or auth header.
    Returns User object if authenticated, None otherwise.
    """
    # Try to get token from query params first, then from headers
    token = websocket.query_params.get("token")

    if not token:
        # Try Authorization header
        auth_header = websocket.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]

    if not token:
        logger.warning("WebSocket auth failed: No token provided")
        return None

    try:
        # Verify token and get user_id
        user_id = verify_access_token(token)

        if not user_id:
            logger.warning("WebSocket auth failed: Invalid token")
            return None

        # Get user from database
        user = await User.get(user_id)

        if not user:
            logger.warning(f"WebSocket auth failed: User {user_id} not found")
            return None

        return user

    except ValueError as e:
        logger.warning(f"WebSocket auth failed: {e}")
        return None
    except Exception as e:
        logger.error(f"WebSocket auth error: {e}")
        return None
