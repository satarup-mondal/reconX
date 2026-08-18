from sqlalchemy.orm import Session

from backend.finding_service import save_finding
from backend.models import ScanResult


SECURITY_HEADERS = {
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "content-security-policy": "Content-Security-Policy",
}


def check_security_headers(
    db: Session,
    scan_id: int,
    result: ScanResult,
    findings: list
):
    headers = {}

    if result.result_metadata:
        headers = result.result_metadata.get(
            "headers",
            {}
        )

    if not headers:
        return

    target = None

    if result.result_metadata:
        target = result.result_metadata.get(
            "target"
        )

    for header_key, header_name in SECURITY_HEADERS.items():

        if header_key not in headers:

            finding = save_finding(
                db=db,
                scan_id=scan_id,
                title=f"Missing HTTP security header: {header_name}",
                severity="low",
                description=(
                    f"The HTTP response does not include "
                    f"the {header_name} security header."
                ),
                evidence=(
                    f"Missing header: {header_name}"
                ),
                asset=target,
                remediation=(
                    f"Review the application and enable "
                    f"{header_name} where appropriate."
                ),
            )

            findings.append(finding)


def detect_findings(
    db: Session,
    scan_id: int
):
    results = (
        db.query(ScanResult)
        .filter(ScanResult.scan_id == scan_id)
        .all()
    )

    findings = []

    for result in results:

        # ==============================================
        # Rule 1 — HTTP service detected
        # ==============================================

        if (
            result.module == "http"
            and result.result_type == "status_code"
        ):
            target = None

            if result.result_metadata:
                target = result.result_metadata.get(
                    "target"
                )

            finding = save_finding(
                db=db,
                scan_id=scan_id,
                title="HTTP service detected",
                severity="info",
                description=(
                    "An HTTP service was observed on "
                    "the target."
                ),
                evidence=(
                    f"HTTP status {result.value}"
                    + (
                        f" from {target}"
                        if target
                        else ""
                    )
                ),
                asset=target,
                remediation=(
                    "Review the exposed HTTP service "
                    "and verify that it is intended."
                ),
            )

            findings.append(finding)

            # Also inspect security headers
            check_security_headers(
                db=db,
                scan_id=scan_id,
                result=result,
                findings=findings
            )

    return findings