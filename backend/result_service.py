from sqlalchemy.orm import Session

from backend.models import ScanResult


def save_result(
    db: Session,
    scan_id: int,
    result_type: str,
    value: str
):
    result = ScanResult(
        scan_id=scan_id,
        result_type=result_type,
        value=value
    )

    db.add(result)
    db.commit()
    db.refresh(result)

    return result