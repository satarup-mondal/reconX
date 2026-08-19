
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.asset_service import build_asset_map
from backend.database import SessionLocal
from backend.finding_service import get_finding_summary
from backend.models import (
    Finding,
    Scan,
    ScanResult,
    Target,
)
from backend.queue import QUEUE_NAME, redis_client
from backend.recon.registry import SCAN_PROFILES


router = APIRouter(
    prefix="/scans",
    tags=["Scans"],
)


class ScanRequest(BaseModel):
    target_id: int
    profile: str = "basic"


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


@router.post("/")
def create_scan(
    scan_request: ScanRequest,
    db: Session = Depends(get_db),
):
    # ----------------------------------------
    # Check target
    # ----------------------------------------

    target = (
        db.query(Target)
        .filter(
            Target.id == scan_request.target_id
        )
        .first()
    )

    if not target:
        return {
            "message": "Target not found"
        }

    # ----------------------------------------
    # Validate profile
    # ----------------------------------------

    if scan_request.profile not in SCAN_PROFILES:
        return {
            "message": "Invalid scan profile",
            "available_profiles": list(
                SCAN_PROFILES.keys()
            ),
        }

    # ----------------------------------------
    # Create scan
    # ----------------------------------------

    new_scan = Scan(
        target_id=target.id,
        profile=scan_request.profile,
    )

    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    # ----------------------------------------
    # Queue scan
    # ----------------------------------------

    redis_client.rpush(
        QUEUE_NAME,
        str(new_scan.id),
    )

    return {
        "message": "Scan queued",
        "id": new_scan.id,
        "target_id": new_scan.target_id,
        "profile": new_scan.profile,
        "status": new_scan.status,
    }


@router.get("/")
def get_scans(
    db: Session = Depends(get_db),
):
    scans = db.query(Scan).all()

    return scans


@router.get("/{scan_id}")
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
):
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )

    if not scan:
        return {
            "message": "Scan not found"
        }

    return {
        "id": scan.id,
        "target_id": scan.target_id,
        "profile": scan.profile,
        "status": scan.status,
        "created_at": scan.created_at,
    }


@router.get("/{scan_id}/results")
def get_scan_results(
    scan_id: int,
    db: Session = Depends(get_db),
):
    # ----------------------------------------
    # Check scan
    # ----------------------------------------

    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )

    if not scan:
        return {
            "message": "Scan not found"
        }

    # ----------------------------------------
    # Get results
    # ----------------------------------------

    results = (
        db.query(ScanResult)
        .filter(
            ScanResult.scan_id == scan_id
        )
        .all()
    )

    return results


@router.get("/{scan_id}/assets")
def get_scan_assets(
    scan_id: int,
    db: Session = Depends(get_db),
):
    # ----------------------------------------
    # Check scan
    # ----------------------------------------

    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )

    if not scan:
        return {
            "message": "Scan not found"
        }

    # ----------------------------------------
    # Build asset map
    # ----------------------------------------

    return build_asset_map(
        db=db,
        scan_id=scan_id,
    )


@router.get("/{scan_id}/findings")
def get_scan_findings(
    scan_id: int,
    db: Session = Depends(get_db),
):
    # ----------------------------------------
    # Check scan
    # ----------------------------------------

    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )

    if not scan:
        return {
            "message": "Scan not found"
        }

    # ----------------------------------------
    # Get findings
    # ----------------------------------------

    findings = (
        db.query(Finding)
        .filter(
            Finding.scan_id == scan_id
        )
        .order_by(Finding.id.asc())
        .all()
    )

    # ----------------------------------------
    # Severity summary
    # ----------------------------------------

    summary = get_finding_summary(
        findings
    )

    return {
        "scan_id": scan_id,
        "summary": summary,
        "findings": findings,
    }
