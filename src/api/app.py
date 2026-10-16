"""FastAPI application for Developer Sandbox Bootstrapper.

Zero cloud infrastructure, strictly local, bound to 127.0.0.1 by default.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.errors import register_error_handlers
from src.api.routes.requests import router as requests_router
from src.api.routes.tokens import router as tokens_router
from src.core.config import get_settings
from src.storage.db_init import initialize_database


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan manager.
    Initializes database tables safely without provisioning sandboxes or seeding data.
    """
    settings = get_settings()
    # Ensure database schema exists (idempotent, does NOT wipe data or create sandboxes)
    initialize_database(settings.database_path)
    yield


def create_app() -> FastAPI:
    """Factory creating configured FastAPI application."""
    app = FastAPI(
        title="Developer Sandbox Bootstrapper API",
        version="1.3.0",
        description="Local Developer Sandbox Bootstrapper REST API. Strictly local mock environment.",
        lifespan=lifespan,
    )

    # Restrict CORS to localhost only
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:8501",
            "http://127.0.0.1:8501",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ],
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # Register error handlers
    register_error_handlers(app)

    # Mount API routers under /api/v1
    app.include_router(requests_router, prefix="/api/v1")
    app.include_router(tokens_router, prefix="/api/v1")

    @app.get(
        "/",
        tags=["Meta"],
        summary="Service root metadata",
    )
    def root() -> dict[str, Any]:
        return {
            "name": "Developer Sandbox Bootstrapper API",
            "version": "1.3.0",
            "environment_label": "MOCK / LOCAL ONLY",
            "status": "online",
            "docs_url": "/docs",
            "local_only": True,
        }

    @app.get(
        "/health",
        tags=["Meta"],
        summary="Health check endpoint",
    )
    @app.get(
        "/api/v1/health",
        tags=["Meta"],
        summary="Health check endpoint (API v1 alias)",
    )
    def health_check() -> dict[str, Any]:
        return {
            "status": "healthy",
            "environment_label": "MOCK / LOCAL ONLY",
            "mock_only": True,
            "cloud_provisioning": False,
        }

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    # Strictly enforce 127.0.0.1 binding
    uvicorn.run("src.api.app:app", host="127.0.0.1", port=8000, reload=False)
