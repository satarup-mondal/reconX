from sqlalchemy.orm import Session

from backend.models import Finding


VALID_SEVERITIES = {
    "info",
    "low",
    "medium",
    "high",
    "critical",
}


def save_finding(
    db: Session,
    scan_id: int,
    title: str,
    severity: str,
    description: str,
    evidence: str | None = None,
    asset: str | None = None,
    remediation: str | None = None,
):
    severity = severity.lower().strip()

    if severity not in VALID_SEVERITIES:
        raise ValueError(
            f"Invalid severity: {severity}"
        )

    existing = (
        db.query(Finding)
        .filter(
            Finding.scan_id == scan_id,
            Finding.title == title,
            Finding.asset == asset,
        )
        .first()
    )

    if existing:
        return existing

    finding = Finding(
        scan_id=scan_id,
        title=title,
        severity=severity,
        description=description,
        evidence=evidence,
        asset=asset,
        remediation=remediation,
    )

    db.add(finding)
    db.commit()
    db.refresh(finding)

    return finding