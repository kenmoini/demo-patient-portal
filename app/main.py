from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from app.auth import router as auth_router
from app.config import get_settings
from app.routers.patients_api import router as patients_api_router


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

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
