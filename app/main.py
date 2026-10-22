from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.auth import router as auth_router
from app.config import get_settings
from app.db import ensure_db_ready
from app.routers.patients_api import router as patients_api_router
from app.routers.portal import router as portal_router

STATIC_DIR = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Create the schema and seed synthetic data on startup so a fresh DB needs no manual step."""
    ensure_db_ready()
    yield


def create_app() -> FastAPI:
    app = FastAPI(title="Patient Portal (demo fixture)", lifespan=lifespan)

    app.add_middleware(
        SessionMiddleware,
        secret_key=get_settings().SESSION_SECRET,
        same_site="lax",
        https_only=get_settings().APP_BASE_URL.startswith("https://"),
    )
    app.include_router(auth_router)
    app.include_router(patients_api_router)
    app.include_router(portal_router)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
