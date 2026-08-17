import socket
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from backend.models import Scan, ScanResult, Target


def resolve_target_ips(target: str) -> list[str]:
    """
    Resolve a target such as:

        recon.local
        recon.local:9000
        http://recon.local:9000
        127.0.0.1:9000

    into IP addresses.
    """

    if not target:
        return []

    target = target.strip()

    if "://" not in target:
        parsed = urlsplit(f"//{target}")
    else:
        parsed = urlsplit(target)

    hostname = parsed.hostname

    if not hostname:
        return []

    try:
        addresses = socket.gethostbyname_ex(hostname)[2]
    except socket.gaierror:
        return []

    return list(dict.fromkeys(addresses))


def extract_target_port(target: str) -> int | None:
    """
    Extract port from a target/URL.
    """

    if not target:
        return None

    try:
        if "://" not in target:
            parsed = urlsplit(f"//{target}")
        else:
            parsed = urlsplit(target)

        return parsed.port

    except ValueError:
        return None


def build_asset_map(
    db: Session,
    scan_id: int
) -> dict:
    """
    Build correlated assets from normalized scan results.
    """

    results = (
        db.query(ScanResult)
        .filter(ScanResult.scan_id == scan_id)
        .all()
    )

    # ---------------------------------------------------------
    # Find scan + target for fallback metadata
    # ---------------------------------------------------------

    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )

    scan_target = None

    if scan:
        target = (
            db.query(Target)
            .filter(Target.id == scan.target_id)
            .first()
        )

        if target:
            scan_target = target.domain

            if target.port:
                scan_target = f"{target.domain}:{target.port}"

    # ---------------------------------------------------------
    # Asset storage
    # ---------------------------------------------------------

    assets = {}

    def get_asset(ip: str) -> dict:
        if ip not in assets:
            assets[ip] = {
                "ip": ip,
                "hostnames": [],
                "ports": [],
                "services": [],
                "technologies": [],
                "subdomains": [],
            }

        return assets[ip]

    # ---------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------

    def add_hostname(
        ip: str,
        hostname: str
    ):
        asset = get_asset(ip)

        if (
            hostname
            and hostname not in asset["hostnames"]
        ):
            asset["hostnames"].append(hostname)

    def add_port(
        ip: str,
        port: str
    ):
        asset = get_asset(ip)

        if port not in asset["ports"]:
            asset["ports"].append(port)

    def get_service(
        ip: str,
        port: str,
        protocol: str = "tcp",
        service_name: str = "unknown"
    ) -> dict:

        asset = get_asset(ip)

        for service in asset["services"]:
            if (
                service["port"] == port
                and service["protocol"] == protocol
            ):
                if (
                    service_name
                    and service["service"] == "unknown"
                ):
                    service["service"] = service_name

                return service

        service = {
            "port": port,
            "protocol": protocol,
            "service": service_name or "unknown",
        }

        asset["services"].append(service)

        return service

    def add_technology(
        ip: str,
        technology: str
    ):
        asset = get_asset(ip)

        if (
            technology
            and technology not in asset["technologies"]
        ):
            asset["technologies"].append(technology)

    def add_subdomain(
        ip: str,
        subdomain: str
    ):
        asset = get_asset(ip)

        if (
            subdomain
            and subdomain not in asset["subdomains"]
        ):
            asset["subdomains"].append(subdomain)

        if (
            subdomain
            and subdomain not in asset["hostnames"]
        ):
            asset["hostnames"].append(subdomain)

    # =========================================================
    # PASS 1
    # DNS -> IP + hostname
    # =========================================================

    for result in results:

        if (
            result.module == "dns"
            and result.result_type == "address"
        ):
            ip = result.value

            get_asset(ip)

            hostname = None

            if result.result_metadata:
                hostname = result.result_metadata.get(
                    "hostname"
                )

            if hostname:
                add_hostname(
                    ip=ip,
                    hostname=hostname
                )

    # =========================================================
    # PASS 2
    # Correlate all remaining modules
    # =========================================================

    for result in results:

        module = result.module
        result_type = result.result_type
        value = result.value

        # -----------------------------------------------------
        # PORTS
        # -----------------------------------------------------

        if (
            module == "ports"
            and result_type == "open_port"
        ):
            target_value = None
            protocol = "tcp"

            if result.result_metadata:
                target_value = result.result_metadata.get(
                    "target"
                )

                protocol = result.result_metadata.get(
                    "protocol",
                    "tcp"
                )

            if not target_value:
                target_value = scan_target

            if not target_value:
                continue

            target_ips = resolve_target_ips(
                target_value
            )

            for ip in target_ips:

                add_port(
                    ip=ip,
                    port=value
                )

                get_service(
                    ip=ip,
                    port=value,
                    protocol=protocol,
                    service_name="unknown"
                )

        # -----------------------------------------------------
        # HTTP
        # -----------------------------------------------------

        elif (
            module == "http"
            and result_type in (
                "status_code",
                "content_type",
                "server",
                "final_url",
            )
        ):
            target_value = None

            if result.result_metadata:
                target_value = result.result_metadata.get(
                    "target"
                )

            # Fallback because some HTTP results don't
            # currently contain target metadata.
            if not target_value:
                target_value = scan_target

            if not target_value:
                continue

            target_ips = resolve_target_ips(
                target_value
            )

            target_port = extract_target_port(
                target_value
            )

            if target_port is None:
                if target_value.startswith(
                    "https://"
                ):
                    target_port = 443
                else:
                    target_port = 80

            target_port = str(target_port)

            for ip in target_ips:

                service = get_service(
                    ip=ip,
                    port=target_port,
                    protocol="tcp",
                    service_name="http"
                )

                if result_type == "status_code":
                    service["status_code"] = value

                elif result_type == "content_type":
                    service["content_type"] = value

                elif result_type == "server":
                    service["server"] = value

                elif result_type == "final_url":
                    service["final_url"] = value

        # -----------------------------------------------------
        # TECHNOLOGY
        # -----------------------------------------------------

        elif (
            module == "technology"
            and result_type == "technology"
        ):
            target_value = None

            if result.result_metadata:
                target_value = result.result_metadata.get(
                    "target"
                )

            if not target_value:
                target_value = scan_target

            if not target_value:
                continue

            target_ips = resolve_target_ips(
                target_value
            )

            for ip in target_ips:

                add_technology(
                    ip=ip,
                    technology=value
                )

        # -----------------------------------------------------
        # SUBDOMAINS
        # -----------------------------------------------------

        elif (
            module == "subdomain"
            and result_type == "subdomain"
        ):
            addresses = []

            if result.result_metadata:
                addresses = result.result_metadata.get(
                    "addresses",
                    []
                )

            for ip in addresses:

                add_subdomain(
                    ip=ip,
                    subdomain=value
                )

    # ---------------------------------------------------------
    # Final response
    # ---------------------------------------------------------

    return {
        "scan_id": scan_id,
        "assets": list(assets.values())
    }