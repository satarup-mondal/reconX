from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database import SessionLocal
from backend.models import Scan, ScanResult, Target
from backend.queue import QUEUE_NAME, redis_client


router = APIRouter(
    prefix="/scans",
    tags=["Scans"]
)


class ScanRequest(BaseModel):
    target_id: int


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


@router.post("/")
def create_scan(
    scan_request: ScanRequest,
    db: Session = Depends(get_db)
):
    # Check whether the target exists
    target = db.query(Target).filter(
        Target.id == scan_request.target_id
    ).first()

    if not target:
        return {
            "message": "Target not found"
        }

    # Create a new scan
    new_scan = Scan(
        target_id=target.id
    )

    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    # Add scan ID to Valkey queue
    redis_client.rpush(
        QUEUE_NAME,
        str(new_scan.id)
    )

    return {
        "message": "Scan queued",
        "id": new_scan.id,
        "target_id": new_scan.target_id,
        "status": new_scan.status
    }


@router.get("/")
def get_scans(
    db: Session = Depends(get_db)
):
    scans = db.query(Scan).all()

    return scans


@router.get("/{scan_id}")
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db)
):
    scan = db.query(Scan).filter(
        Scan.id == scan_id
    ).first()

    if not scan:
        return {
            "message": "Scan not found"
        }

    return {
        "id": scan.id,
        "target_id": scan.target_id,
        "status": scan.status,
        "created_at": scan.created_at
    }


@router.get("/{scan_id}/results")
def get_scan_results(
    scan_id: int,
    db: Session = Depends(get_db)
):
    # First check that the scan exists
    scan = db.query(Scan).filter(
        Scan.id == scan_id
    ).first()

    if not scan:
        return {
            "message": "Scan not found"
        }

    # Fetch all results belonging to this scan
    results = db.query(ScanResult).filter(
        ScanResult.scan_id == scan_id
    ).all()

    return results