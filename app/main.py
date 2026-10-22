from fastapi import FastAPI


def create_app() -> FastAPI:
    app = FastAPI(title="Patient Portal (demo fixture)")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
