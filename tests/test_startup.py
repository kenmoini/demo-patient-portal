from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session

from app.models import Patient
from app.seed import CANARY_MRN


def _start_app_once():
    from app.main import create_app

    with TestClient(create_app()):
        pass


def _patients(url):
    with Session(create_engine(url)) as s:
        return s.scalar(select(func.count()).select_from(Patient)), s.scalar(
            select(Patient).where(Patient.mrn == CANARY_MRN)
        )


def test_startup_creates_schema_and_seeds_empty_db(oidc_env):
    from app.config import get_settings

    url = get_settings().DATABASE_URL
    _start_app_once()
    count, canary = _patients(url)
    assert count == 101  # 100 synthetic patients + canary
    assert canary is not None


def test_startup_does_not_reseed_existing_data(oidc_env):
    from app.config import get_settings

    url = get_settings().DATABASE_URL
    _start_app_once()
    _start_app_once()
    count, _ = _patients(url)
    assert count == 101
