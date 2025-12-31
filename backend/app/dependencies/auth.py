from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.core.security import verify_access_token
from app.db.models.user import User

credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)

security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> User:
    """Get current authenticated user from JWT token."""
    try:
        # Extract token from credentials
        token = credentials.credentials

        # Verify token and get user_id
        user_id = verify_access_token(token)

        if not user_id:
            raise credentials_exception

        # Get user from database using Beanie
        user = await User.get(user_id)

        if user is None:
            raise credentials_exception

        return user
    except ValueError:
        # Invalid token
        raise credentials_exception
    except Exception as e:
        raise credentials_exception
