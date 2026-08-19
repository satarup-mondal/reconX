from sqlalchemy.orm import Session

from backend.finding_service import save_finding
from backend.models import ScanResult


# ============================================================
# Finding Rule IDs
# ============================================================

RULE_HTTP_SERVICE_DETECTED = (
    "HTTP_SERVICE_DETECTED"
)

RULE_MISSING_X_CONTENT_TYPE_OPTIONS = (
    "MISSING_X_CONTENT_TYPE_OPTIONS"
)

RULE_MISSING_X_FRAME_OPTIONS = (
    "MISSING_X_FRAME_OPTIONS"
)

RULE_MISSING_CSP = (
    "MISSING_CSP"
)

RULE_HTTP_SERVER_DISCLOSURE = (
    "HTTP_SERVER_DISCLOSURE"
)

RULE_MISSING_HSTS = (
    "MISSING_HSTS"
)

RULE_INSECURE_HTTP_SERVICE = (
    "INSECURE_HTTP_SERVICE"
)


# ============================================================
# Security Headers
# ============================================================

SECURITY_HEADERS = {
    "x-content-type-options": (
        "X-Content-Type-Options",
        RULE_MISSING_X_CONTENT_TYPE_OPTIONS,
    ),
    "x-frame-options": (
        "X-Frame-Options",
        RULE_MISSING_X_FRAME_OPTIONS,
    ),
    "content-security-policy": (
        "Content-Security-Policy",
        RULE_MISSING_CSP,
    ),
}


def get_result_metadata(
    result: ScanResult,
) -> dict:
    """
    Safely return HTTP result metadata.
    """

    if not result.result_metadata:
        return {}

    if not isinstance(
        result.result_metadata,
        dict,
    ):
        return {}

    return result.result_metadata


def get_result_target(
    result: ScanResult,
) -> str | None:
    """
    Return the target associated with a scan result.
    """

    metadata = get_result_metadata(result)

    target = metadata.get("target")

    if target is None:
        return None

    target = str(target).strip()

    return target or None


def get_result_headers(
    result: ScanResult,
) -> dict:
    """
    Return normalized HTTP response headers.
    """

    metadata = get_result_metadata(result)

    headers = metadata.get(
        "headers",
        {},
    )

    if not isinstance(headers, dict):
        return {}

    return {
        str(key).strip().lower(): value
        for key, value in headers.items()
    }


def get_final_url(
    result: ScanResult,
) -> str | None:
    """
    Return the final URL observed by the HTTP probe.
    """

    metadata = get_result_metadata(result)

    final_url = metadata.get(
        "final_url"
    )

    if final_url is None:
        return None

    final_url = str(final_url).strip()

    return final_url or None


# ============================================================
# Existing Security Header Detection
# ============================================================

def check_security_headers(
    db: Session,
    scan_id: int,
    result: ScanResult,
    findings: list,
):
    """
    Check required HTTP security headers.
    """

    headers = get_result_headers(result)

    if not headers:
        return

    target = get_result_target(result)

    for header_key, (
        header_name,
        rule_id,
    ) in SECURITY_HEADERS.items():

        if header_key in headers:
            continue

        finding = save_finding(
            db=db,
            scan_id=scan_id,
            rule_id=rule_id,
            title=(
                f"Missing HTTP security header: "
                f"{header_name}"
            ),
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


# ============================================================
# Server Header Disclosure
# ============================================================

def check_server_disclosure(
    db: Session,
    scan_id: int,
    result: ScanResult,
    findings: list,
):
    """
    Detect disclosure of the HTTP Server header.
    """

    headers = get_result_headers(result)

    if not headers:
        return

    server_value = headers.get("server")

    if server_value is None:
        return

    server_value = str(
        server_value
    ).strip()

    if not server_value:
        return

    target = get_result_target(result)

    finding = save_finding(
        db=db,
        scan_id=scan_id,
        rule_id=RULE_HTTP_SERVER_DISCLOSURE,
        title="HTTP server information disclosed",
        severity="low",
        description=(
            "The HTTP response exposes a Server header "
            "that may disclose server or software information."
        ),
        evidence=(
            f"Server header: {server_value}"
        ),
        asset=target,
        remediation=(
            "Review whether the Server header is necessary "
            "and minimize unnecessary software or version "
            "disclosure where possible."
        ),
    )

    findings.append(finding)


# ============================================================
# HSTS Detection
# ============================================================

def check_hsts(
    db: Session,
    scan_id: int,
    result: ScanResult,
    findings: list,
):
    """
    Detect missing HTTP Strict Transport Security (HSTS)
    on HTTPS responses.
    """

    final_url = get_final_url(result)

    if not final_url:
        return

    if not final_url.lower().startswith(
        "https://"
    ):
        return

    headers = get_result_headers(result)

    if "strict-transport-security" in headers:
        return

    target = get_result_target(result)

    finding = save_finding(
        db=db,
        scan_id=scan_id,
        rule_id=RULE_MISSING_HSTS,
        title="Missing HSTS header",
        severity="low",
        description=(
            "The HTTPS response does not include the "
            "Strict-Transport-Security header."
        ),
        evidence=(
            "Missing header: Strict-Transport-Security"
        ),
        asset=target,
        remediation=(
            "Configure the Strict-Transport-Security "
            "header after confirming HTTPS is correctly "
            "deployed across the application."
        ),
    )

    findings.append(finding)


# ============================================================
# Insecure HTTP Detection
# ============================================================

def check_insecure_http(
    db: Session,
    scan_id: int,
    result: ScanResult,
    findings: list,
):
    """
    Detect services responding over plain HTTP.
    """

    final_url = get_final_url(result)

    if not final_url:
        return

    if not final_url.lower().startswith(
        "http://"
    ):
        return

    target = get_result_target(result)

    finding = save_finding(
        db=db,
        scan_id=scan_id,
        rule_id=RULE_INSECURE_HTTP_SERVICE,
        title="HTTP service is not using TLS",
        severity="low",
        description=(
            "The discovered HTTP service is reachable "
            "without transport encryption."
        ),
        evidence=(
            f"Observed URL: {final_url}"
        ),
        asset=target,
        remediation=(
            "Prefer HTTPS with a valid TLS configuration "
            "and redirect HTTP traffic to HTTPS where "
            "appropriate."
        ),
    )

    findings.append(finding)


# ============================================================
# Main Finding Detection
# ============================================================

def detect_findings(
    db: Session,
    scan_id: int,
):
    """
    Evaluate normalized scan results and persist
    findings generated by the detection rules.
    """

    results = (
        db.query(ScanResult)
        .filter(
            ScanResult.scan_id == scan_id
        )
        .all()
    )

    findings = []

    for result in results:

        # ====================================================
        # HTTP detection rules
        # ====================================================

        if (
            result.module == "http"
            and result.result_type == "status_code"
        ):

            target = get_result_target(
                result
            )

            # ------------------------------------------------
            # HTTP service detected
            # ------------------------------------------------

            finding = save_finding(
                db=db,
                scan_id=scan_id,
                rule_id=RULE_HTTP_SERVICE_DETECTED,
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

            # ------------------------------------------------
            # Existing security header rules
            # ------------------------------------------------

            check_security_headers(
                db=db,
                scan_id=scan_id,
                result=result,
                findings=findings,
            )

            # ------------------------------------------------
            # New detection rules
            # ------------------------------------------------

            check_server_disclosure(
                db=db,
                scan_id=scan_id,
                result=result,
                findings=findings,
            )

            check_hsts(
                db=db,
                scan_id=scan_id,
                result=result,
                findings=findings,
            )

            check_insecure_http(
                db=db,
                scan_id=scan_id,
                result=result,
                findings=findings,
            )

    return findings