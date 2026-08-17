from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database import SessionLocal
from backend.models import Target


router = APIRouter(
    prefix="/targets",
    tags=["Targets"]
)


class TargetRequest(BaseModel):
    domain: str
    port: int | None = None


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


@router.post("/")
def create_target(
    target_request: TargetRequest,
    db: Session = Depends(get_db)
):
    new_target = Target(
        domain=target_request.domain,
        port=target_request.port
    )

    db.add(new_target)
    db.commit()
    db.refresh(new_target)

    return {
        "id": new_target.id,
        "domain": new_target.domain,
        "port": new_target.port
    }


@router.get("/")
def get_targets(
    db: Session = Depends(get_db)
):
    return db.query(Target).all()


@router.get("/{target_id}")
def get_target(
    target_id: int,
    db: Session = Depends(get_db)
):
    target = db.query(Target).filter(
        Target.id == target_id
    ).first()

    if not target:
        return {
            "message": "Target not found"
        }

    return target


@router.delete("/{target_id}")
def delete_target(
    target_id: int,
    db: Session = Depends(get_db)
):
    target = db.query(Target).filter(
        Target.id == target_id
    ).first()

    if not target:
        return {
            "message": "Target not found"
        }

    db.delete(target)
    db.commit()

    return {
        "message": "Target deleted",
        "id": target_id
    }