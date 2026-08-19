
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy.orm import Session

from backend.models import Finding


VALID_SEVERITIES = {
    "info",
    "low",
    "medium",
    "high",
    "critical",
}


def normalize_asset(asset: str | None) -> str | None:
    """
    Normalize an asset so logically equivalent assets
    can be compared consistently during deduplication.
    """

    if asset is None:
        return None

    asset = asset.strip()

    if not asset:
        return None

    # Normalize URL-style assets.
    if "://" in asset:
        parsed = urlsplit(asset)

        scheme = parsed.scheme.lower()

        hostname = (
            parsed.hostname.lower()
            if parsed.hostname
            else ""
        )

        port = parsed.port

        netloc = hostname

        if port:
            default_port = (
                (scheme == "http" and port == 80)
                or (scheme == "https" and port == 443)
            )

            if not default_port:
                netloc = f"{hostname}:{port}"

        path = parsed.path.rstrip("/")

        return urlunsplit(
            (
                scheme,
                netloc,
                path,
                parsed.query,
                "",
            )
        )

    # Normalize hostname / hostname:port assets.
    return asset.rstrip("/").lower()


def save_finding(
    db: Session,
    scan_id: int,
    rule_id: str,
    title: str,
    severity: str,
    description: str,
    evidence: str | None = None,
    asset: str | None = None,
    remediation: str | None = None,
):
    """
    Persist a finding if the same rule has not already
    produced a finding for the same normalized asset
    within the same scan.
    """

    rule_id = rule_id.strip().upper()

    if not rule_id:
        raise ValueError(
            "rule_id cannot be empty"
        )

    severity = severity.lower().strip()

    if severity not in VALID_SEVERITIES:
        raise ValueError(
            f"Invalid severity: {severity}"
        )

    normalized_asset = normalize_asset(asset)

    # -------------------------------------------------
    # Finding deduplication
    # -------------------------------------------------
    #
    # Stable finding identity:
    #
    # scan_id + rule_id + normalized_asset
    #
    # This prevents duplicate findings when:
    # - the same rule runs more than once
    # - asset formatting differs
    # - URL trailing slashes differ
    # - hostname casing differs
    # -------------------------------------------------

    existing = (
        db.query(Finding)
        .filter(
            Finding.scan_id == scan_id,
            Finding.rule_id == rule_id,
            Finding.asset == normalized_asset,
        )
        .first()
    )

    if existing:
        return existing

    # -------------------------------------------------
    # Create finding
    # -------------------------------------------------

    finding = Finding(
        scan_id=scan_id,
        rule_id=rule_id,
        title=title,
        severity=severity,
        description=description,
        evidence=evidence,
        asset=normalized_asset,
        remediation=remediation,
    )

    db.add(finding)
    db.commit()
    db.refresh(finding)

    return finding


def get_finding_summary(
    findings: list[Finding],
) -> dict:
    """
    Aggregate findings by severity.
    """

    summary = {
        "total": len(findings),
        "info": 0,
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
    }

    for finding in findings:
        severity = (
            finding.severity.lower()
        )

        if severity in summary:
            summary[severity] += 1

    return summary

