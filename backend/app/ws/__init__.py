"""WebSocket module for real-time communication."""

from .connection_manager import manager, ConnectionManager
from .auth import authenticate_websocket
from .websocket_router import router as ws_router

__all__ = ["manager", "ConnectionManager",
           "authenticate_websocket", "ws_router"]
