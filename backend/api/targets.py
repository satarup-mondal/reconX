from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel

from backend.database import SessionLocal
from backend.models import Target


router = APIRouter(
    prefix="/targets",
    tags=["Targets"]
)


class TargetRequest(BaseModel):
    domain: str


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


@router.post("/")
def create_target(
    target: TargetRequest,
    db: Session = Depends(get_db)
):
    new_target = Target(
        domain=target.domain
    )

    db.add(new_target)
    db.commit()
    db.refresh(new_target)

    return {
        "message": "Target created",
        "id": new_target.id,
        "domain": new_target.domain
    } 

@router.get("/")
def get_targets(db: Session = Depends(get_db)):

    targets = db.query(Target).all()

    return targets

@router.get("/{target_id}")
def get_target(target_id: int, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()

    if not target:
        return {
            "message": "Target not found"
        }

    return {
        "id": target.id,
        "domain": target.domain
    } 

@router.delete("/{target_id}")
def delete_target(target_id: int, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()

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