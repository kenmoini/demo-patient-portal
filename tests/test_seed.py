from sqlalchemy import select

from app.models import Patient
from app.seed import seed


def _first_name(session) -> str:
    return session.scalars(select(Patient).order_by(Patient.id)).first().full_name


def test_seed_is_deterministic(session_factory):
    a, b = session_factory(), session_factory()
    seed(a, n=100, seed=1337)
    seed(b, n=100, seed=1337)
    assert _first_name(a) == _first_name(b)
    rows_a = [(p.mrn, p.full_name, p.dob) for p in a.scalars(select(Patient).order_by(Patient.id))]
    rows_b = [(p.mrn, p.full_name, p.dob) for p in b.scalars(select(Patient).order_by(Patient.id))]
    assert rows_a == rows_b


def test_canary_present(session):
    seed(session)
    rows = session.scalars(select(Patient).where(Patient.mrn == "ZZZ-CANARY-0001")).all()
    assert len(rows) == 1
    assert rows[0].full_name == "Canary Testpatient"
