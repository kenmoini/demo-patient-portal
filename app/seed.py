import random
from datetime import datetime

from faker import Faker
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Patient

CANARY_MRN = "ZZZ-CANARY-0001"
CANARY_NAME = "Canary Testpatient"

CONDITIONS = [
    "Type 2 diabetes mellitus",
    "Essential hypertension",
    "Asthma",
    "Chronic kidney disease",
    "Congestive heart failure",
    "COPD",
    "Major depressive disorder",
    "Hyperlipidemia",
    "Osteoarthritis",
    "Atrial fibrillation",
]
SEXES = ["Female", "Male"]

# Fixed timestamp so created_at is identical across runs.
_SEED_TIMESTAMP = datetime(2026, 1, 1, 0, 0, 0)


def seed(session: Session, n: int = 100, seed: int = 1337) -> None:
    """Insert n deterministic synthetic patients plus one canary row.

    The same ``seed`` always yields identical rows (in insertion/id order).
    """
    fake = Faker()
    fake.seed_instance(seed)
    rng = random.Random(seed)

    providers = [f"Dr. {fake.last_name()}" for _ in range(8)]

    patients = []
    for i in range(1, n + 1):
        sex = rng.choice(SEXES)
        name = fake.name_female() if sex == "Female" else fake.name_male()
        patients.append(
            Patient(
                mrn=f"MRN-{i:06d}",
                full_name=name,
                dob=fake.date_of_birth(minimum_age=1, maximum_age=95),
                sex=sex,
                primary_condition=rng.choice(CONDITIONS),
                attending_provider=rng.choice(providers),
                created_at=_SEED_TIMESTAMP,
            )
        )

    canary_exists = session.scalar(select(Patient.id).where(Patient.mrn == CANARY_MRN))
    if canary_exists is None:
        patients.append(
            Patient(
                mrn=CANARY_MRN,
                full_name=CANARY_NAME,
                dob=datetime(1980, 1, 1).date(),
                sex="Female",
                primary_condition="Canary condition (synthetic)",
                attending_provider="Dr. Canary",
                created_at=_SEED_TIMESTAMP,
            )
        )

    session.add_all(patients)
    session.commit()
