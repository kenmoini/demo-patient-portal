"""Portal UI: server-rendered Jinja2 pages with an HTMX live-search partial.

Every portal route (except the public landing page at `/`) sits behind
`require_session`. The patient list and detail pages use safe ORM queries. The
live search deliberately reuses the one vulnerable search function from
`patients_api` (the "hero" SQLi) — there is no second raw-SQL query here.
"""

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.auth import SESSION_CLAIMS_KEY, require_session
from app.db import get_session
from app.models import Patient
from app.routers.patients_api import run_vulnerable_search

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

router = APIRouter(tags=["portal"])

LIST_LIMIT = 200


def _fhir_patient(p: Patient) -> dict:
    """A FHIR R4 Patient-shaped view of the record, for display only."""
    return {
        "resourceType": "Patient",
        "id": str(p.id),
        "identifier": [{"system": "urn:portal:mrn", "value": p.mrn}],
        "name": [{"text": p.full_name}],
        "gender": p.sex.lower(),
        "birthDate": p.dob.isoformat(),
        "generalPractitioner": [{"display": p.attending_provider}],
        "extension": [{"url": "primaryCondition", "valueString": p.primary_condition}],
    }


@router.get("/", response_class=HTMLResponse)
def landing(request: Request):
    """Public landing page: 'Sign in' for visitors, 'Open patient records' once signed in."""
    user = request.session.get(SESSION_CLAIMS_KEY)
    return templates.TemplateResponse(request, "landing.html", {"user": user})


@router.get("/signin", include_in_schema=False)
def signin() -> RedirectResponse:
    """Former sign-in page; the landing page at / now serves that purpose."""
    return RedirectResponse("/", status_code=307)


@router.get("/patients", response_class=HTMLResponse)
def patients_list(
    request: Request,
    session: Session = Depends(get_session),
    claims: dict = Depends(require_session),
):
    patients = session.scalars(select(Patient).order_by(Patient.id).limit(LIST_LIMIT)).all()
    return templates.TemplateResponse(
        request,
        "patients_list.html",
        {"user": claims, "patients": patients, "q": ""},
    )


@router.get("/patients/{patient_id}", response_class=HTMLResponse)
def patient_detail(
    request: Request,
    patient_id: int,
    session: Session = Depends(get_session),
    claims: dict = Depends(require_session),
):
    patient = session.get(Patient, patient_id)
    if patient is None:
        raise HTTPException(status_code=404, detail="patient not found")
    return templates.TemplateResponse(
        request,
        "patient_detail.html",
        {"user": claims, "p": patient, "fhir": _fhir_patient(patient)},
    )


@router.get("/search", response_class=HTMLResponse)
def search(
    request: Request,
    q: str = "",
    session: Session = Depends(get_session),
    claims: dict = Depends(require_session),
):
    """HTMX partial: table fragment of patients matching `q`.

    Calls the single shared (vulnerable) search function from the patients API.
    """
    error = False
    try:
        patients = run_vulnerable_search(session, q)
    except SQLAlchemyError:
        patients, error = [], True
    return templates.TemplateResponse(
        request,
        "_search_results.html",
        {"patients": patients, "q": q, "error": error},
    )
