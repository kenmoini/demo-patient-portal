from datetime import date

from sqlalchemy import select

from app.models import Patient
from app.seed import seed

_COLUMNS = [c.name for c in Patient.__table__.columns if c.name != "id"]


def _rows(session) -> list[tuple]:
    patients = session.scalars(select(Patient).order_by(Patient.id)).all()
    return [tuple(getattr(p, c) for c in _COLUMNS) for p in patients]


def _first(session) -> Patient:
    return session.scalars(select(Patient).order_by(Patient.id)).first()


def test_seed_is_deterministic(session_factory):
    a, b = session_factory(), session_factory()
    seed(a, n=100, seed=1337)
    seed(b, n=100, seed=1337)

    # Golden values: pins the output so any date/clock dependence is caught.
    first = _first(a)
    assert first.full_name == "Eric Gay"
    assert first.dob == date(1945, 12, 26)
    assert _first(b).full_name == first.full_name
    assert _first(b).dob == first.dob

    # Every column except id is identical across two fresh seedings.
    assert _rows(a) == _rows(b)
    assert len(_rows(a)) == 101  # 100 + canary


def test_different_seed_differs(session_factory):
    a, b = session_factory(), session_factory()
    seed(a, n=100, seed=1337)
    seed(b, n=100, seed=1338)
    assert _rows(a) != _rows(b)
    assert (_first(a).full_name, _first(a).dob) != (_first(b).full_name, _first(b).dob)


def test_canary_present(session):
    seed(session)
    rows = session.scalars(select(Patient).where(Patient.mrn == "ZZZ-CANARY-0001")).all()
    assert len(rows) == 1
    assert rows[0].full_name == "Canary Testpatient"
