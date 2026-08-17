from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.database import SessionLocal
from backend.models import Finding


router = APIRouter(
    prefix="/findings",
    tags=["Findings"]
)


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


@router.get("/")
def get_findings(
    db: Session = Depends(get_db)
):
    return db.query(Finding).all()


@router.get("/{finding_id}")
def get_finding(
    finding_id: int,
    db: Session = Depends(get_db)
):
    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id)
        .first()
    )

    if not finding:
        return {
            "message": "Finding not found"
        }

    return finding