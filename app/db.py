from collections.abc import Iterator

from sqlalchemy import create_engine, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings
from app.models import Base, Patient
from app.seed import seed

_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    """Lazily build the engine from Settings.DATABASE_URL."""
    global _engine, _SessionLocal
    if _engine is None:
        url = get_settings().DATABASE_URL
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        _engine = create_engine(url, connect_args=connect_args)
        _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def init_db() -> None:
    """Create all tables (idempotent)."""
    Base.metadata.create_all(get_engine())


def ensure_db_ready() -> None:
    """Create the schema and load the synthetic seed data if the DB is empty.

    Idempotent: safe to run on every startup. A populated DB is left untouched.
    """
    init_db()
    assert _SessionLocal is not None
    with _SessionLocal() as session:
        if session.scalar(select(func.count()).select_from(Patient)) == 0:
            seed(session)


def get_session() -> Iterator[Session]:
    """Yield a session bound to Settings.DATABASE_URL (usable as a FastAPI dependency)."""
    get_engine()
    assert _SessionLocal is not None
    session = _SessionLocal()
    try:
        yield session
    finally:
        session.close()
