from datetime import datetime, timedelta, timezone
from typing import Any

from jose import JWTError, jwt

from app.core.config import get_settings


def create_access_token(subject: str, expires_delta: timedelta | None = None) -> str:
    """Create an access token for a given subject."""
    settings = get_settings()
    expire = datetime.now(
        timezone.utc) + (expires_delta or timedelta(minutes=settings.access_token_expire_minutes))
    to_encode: dict[str, Any] = {"sub": subject, "exp": expire}
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def verify_access_token(token: str) -> str:
    """Verify an access token and return the encoded subject."""
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.secret_key,
                             algorithms=[settings.algorithm])
        return str(payload["sub"])
    except (KeyError, JWTError) as exc:  # pragma: no cover - thin wrapper
        raise ValueError("Invalid authentication token") from exc


def get_refresh_token(token: str) -> str:
    """Generate a refresh token from an access token."""
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.secret_key,
                             algorithms=[settings.algorithm])
        subject = str(payload["sub"])
        expire = datetime.now(timezone.utc) + \
            timedelta(days=settings.refresh_token_expire_days)
        to_encode: dict[str, Any] = {"sub": subject, "exp": expire}
        return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    except (KeyError, JWTError) as exc:  # pragma: no cover - thin wrapper
        raise ValueError("Invalid authentication token") from exc

def create_refresh_token(subject: str, expires_delta: timedelta | None = None) -> str:
    """Create a refresh token for a given subject."""
    settings = get_settings()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(days=settings.refresh_token_expire_days))
    to_encode: dict[str, Any] = {"sub": subject, "exp": expire}
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)