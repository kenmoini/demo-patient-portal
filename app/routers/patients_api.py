"""Patients API: a safe, paginated list endpoint and a deliberately-vulnerable search endpoint.

The search endpoint is the fixture's "hero" vulnerability (see EXPECTED_FINDINGS #1):
it builds SQL by raw f-string interpolation of user input instead of a bound
parameter, so it is a real, exploitable SQL injection. This is intentional for
this demo fixture and must not be fixed, suppressed, or softened here.
"""

from fastapi import APIRouter, Depends
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.auth import require_bearer
from app.db import get_session
from app.models import Patient

router = APIRouter(prefix="/api/patients", tags=["patients"])


def _row_to_dict(row) -> dict:
    return {
        "id": row.id,
        "mrn": row.mrn,
        "full_name": row.full_name,
        "dob": row.dob.isoformat(),
        "sex": row.sex,
        "primary_condition": row.primary_condition,
        "attending_provider": row.attending_provider,
    }


@router.get("")
def list_patients(
    limit: int = 50,
    offset: int = 0,
    session: Session = Depends(get_session),
    claims: dict = Depends(require_bearer),
) -> list[dict]:
    """SAFE: parameterized/ORM query, paginated."""
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    rows = session.scalars(
        select(Patient).order_by(Patient.id).limit(limit).offset(offset)
    ).all()
    return [_row_to_dict(r) for r in rows]


def run_vulnerable_search(session: Session, q: str) -> list[dict]:
    """VULNERABLE: builds SQL via raw f-string interpolation of `q` (no bound
    parameter). This is a deliberate SQL injection — see EXPECTED_FINDINGS #1.
    Do NOT parameterize, sanitize, or suppress this; it is the intended
    "hero" finding for this fixture.

    This is the ONE SQL-injection sink in the app: both the API endpoint below
    and the portal UI's `/search` partial call this function. Do not add a
    second raw-SQL query anywhere.
    """
    query = text(  # planted vuln #1 (see docs/EXPECTED_FINDINGS.md) — intentional SQL injection, do not remove or suppress
        f"SELECT id, mrn, full_name, dob, sex, primary_condition, attending_provider "
        f"FROM patients WHERE full_name LIKE '%{q}%'"
    )
    rows = session.execute(query).all()
    return [
        {
            "id": r.id,
            "mrn": r.mrn,
            "full_name": r.full_name,
            "dob": r.dob if isinstance(r.dob, str) else r.dob.isoformat(),
            "sex": r.sex,
            "primary_condition": r.primary_condition,
            "attending_provider": r.attending_provider,
        }
        for r in rows
    ]


@router.get("/search")
def search_patients(
    q: str,
    session: Session = Depends(get_session),
    claims: dict = Depends(require_bearer),
) -> list[dict]:
    """Search endpoint; delegates to the single vulnerable search function."""
    return run_vulnerable_search(session, q)
