import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base


def _fresh_session():
    """Return a session bound to a brand-new isolated in-memory SQLite DB."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


@pytest.fixture
def session():
    s = _fresh_session()
    try:
        yield s
    finally:
        s.close()


@pytest.fixture
def session_factory():
    """Callable producing fresh, independent isolated sessions (for A/B runs)."""
    made = []

    def make():
        s = _fresh_session()
        made.append(s)
        return s

    yield make
    for s in made:
        s.close()
