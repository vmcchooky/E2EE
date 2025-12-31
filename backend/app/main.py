from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.api_router import router
from app.ws.websocket_router import router as ws_router
from app.db.session import close_db, init_db
from app.middleware import AuthMiddleware
from app.core.exception import register_global_exceptions


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await init_db()
    yield
    await close_db()


def create_application() -> FastAPI:
    application = FastAPI(title="E2EE Chat API",
                          version="0.1.0", lifespan=lifespan)

    # Include AuthMiddleware before CORS so it's inner to CORS
    application.add_middleware(AuthMiddleware)

    # CORS configuration (Outermost)
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    register_global_exceptions(application)

    # Include routers
    application.include_router(router)
    application.include_router(ws_router, tags=["websocket"])

    return application


app = create_application()
