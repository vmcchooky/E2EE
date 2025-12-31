"""
Middleware để xử lý authentication (ví dụ).
Có thể dùng để check token, log user activity, etc.
"""
from typing import Callable, Awaitable

from fastapi import Request, Response, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware


class AuthMiddleware(BaseHTTPMiddleware):
    public_paths = [
        "/",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/api/auth/login",
        "/api/auth/register",
        "/api/auth/refresh-token",
        "/api/auth/refresh",
        "/api/auth/logout",  # Thêm logout vào public paths
        "/api/health",
        "/health",
        "/api/favicon.ico",
    ]

    def __init__(self, app, exclude_paths: list[str] = None):
        super().__init__(app)
        self.exclude_paths = exclude_paths or self.public_paths

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        """Kiểm tra authentication trước khi xử lý request."""
       
        if request.method == "OPTIONS":
            return await call_next(request)

        path = request.url.path.rstrip("/") 

        is_public = False
        for public_path in self.exclude_paths:
            public_path_clean = public_path.rstrip("/")
            if path == public_path_clean or path.startswith(public_path_clean + "/"):
                is_public = True
                break


        if path.startswith("/api/auth"):
            is_public = True

        if is_public:
            return await call_next(request)

        authorization = request.headers.get("Authorization")
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or invalid authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        return await call_next(request)
