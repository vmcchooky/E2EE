from fastapi import APIRouter, Depends, Response, Request, status

from app.schemas.auth import RegisterRequest, Token, LoginRequest
from app.schemas.response import BaseResponse
from app.services.auth_service import AuthService
from app.core.config import get_settings

router = APIRouter()
settings = get_settings()


def _set_refresh_cookie(response: Response, refresh_token: str) -> None:
    """Helper to set refresh token cookie."""
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=settings.environment == "production",
        max_age=settings.refresh_token_expire_days * 24 * 60 * 60,
        samesite="lax",
        path="/",
    )


@router.post("/signup")
async def signup(
    payload: RegisterRequest,
    service: AuthService = Depends(),
) -> BaseResponse[None]:
    """Register a new user."""
    await service.register(payload)
    return BaseResponse(
        status_code=status.HTTP_200_OK,
        success=True,
        message="Đăng ký thành công",
        data=None,
    )


@router.post("/signin")
async def signin(
    payload: LoginRequest,
    response: Response,
    service: AuthService = Depends(),
) -> BaseResponse[Token]:
    """Login and receive access token."""
    token_data, refresh_token = await service.login(payload)
    _set_refresh_cookie(response, refresh_token)
    return BaseResponse[Token](
        status_code=status.HTTP_200_OK,
        success=True,
        message="Đăng nhập thành công",
        data=token_data,
    )


@router.post("/refresh-token")
async def get_new_access_token(
    request: Request,
    response: Response,
    service: AuthService = Depends(),
) -> BaseResponse[Token]:
    """Get new access token using refresh token."""
    refresh_token = request.cookies.get("refresh_token")

    # Log for debugging (don't log the actual token value for security)
    if not refresh_token:
        # Log available cookies for debugging (without sensitive values)
        available_cookies = list(request.cookies.keys())
        print(
            f"[Auth] Refresh token missing. Available cookies: {available_cookies}")
        print(f"[Auth] Request origin: {request.headers.get('origin')}")
        print(f"[Auth] Request referer: {request.headers.get('referer')}")

    new_access_token, new_refresh_token = await service.refresh_token(refresh_token)
    _set_refresh_cookie(response, new_refresh_token)
    return BaseResponse[Token](
        status_code=status.HTTP_200_OK,
        success=True,
        message="Refresh token thành công",
        data=new_access_token,
    )


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    service: AuthService = Depends(),
) -> BaseResponse:
    """Logout and revoke refresh token."""
    await service.logout(request.cookies.get("refresh_token"))
    response.delete_cookie("refresh_token", path="/")
    return BaseResponse(
        status_code=status.HTTP_200_OK,
        success=True,
        message="Đăng xuất thành công",
    )
