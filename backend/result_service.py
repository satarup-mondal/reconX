from sqlalchemy.orm import Session

from backend.models import ScanResult


def save_result(
    db: Session,
    scan_id: int,
    module: str,
    result_type: str,
    value: str,
    metadata: dict | None = None
):
    existing = (
        db.query(ScanResult)
        .filter(
            ScanResult.scan_id == scan_id,
            ScanResult.module == module,
            ScanResult.result_type == result_type,
            ScanResult.value == value
        )
        .first()
    )

    if existing:
        return existing

    result = ScanResult(
        scan_id=scan_id,
        module=module,
        result_type=result_type,
        value=value,
        result_metadata=metadata
    )

    db.add(result)
    db.commit()
    db.refresh(result)

    return result