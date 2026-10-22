from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.auth import router as auth_router
from app.config import get_settings
from app.routers.patients_api import router as patients_api_router
from app.routers.portal import router as portal_router

STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app() -> FastAPI:
    app = FastAPI(title="Patient Portal (demo fixture)")

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
