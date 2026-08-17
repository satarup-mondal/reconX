import socket
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from backend.models import ScanResult


def resolve_target_ips(target: str) -> list[str]:
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
    if not target:
        return None

    if "://" not in target:
        parsed = urlsplit(f"//{target}")
    else:
        parsed = urlsplit(target)

    return parsed.port


def build_asset_map(
    db: Session,
    scan_id: int
) -> dict:

    results = (
        db.query(ScanResult)
        .filter(ScanResult.scan_id == scan_id)
        .all()
    )

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

    def add_hostname(ip: str, hostname: str):
        asset = get_asset(ip)

        if hostname and hostname not in asset["hostnames"]:
            asset["hostnames"].append(hostname)

    def add_port(ip: str, port: str):
        asset = get_asset(ip)

        if port not in asset["ports"]:
            asset["ports"].append(port)

    def add_service(
        ip: str,
        port: str,
        protocol: str,
        service: str | None = None
    ):
        asset = get_asset(ip)

        for existing in asset["services"]:
            if (
                existing["port"] == port
                and existing["protocol"] == protocol
            ):
                # Upgrade unknown service when we later
                # observe a concrete service.
                if (
                    service
                    and existing["service"] in (None, "unknown")
                ):
                    existing["service"] = service

                return

        asset["services"].append({
            "port": port,
            "protocol": protocol,
            "service": service or "unknown",
        })

    def add_technology(ip: str, technology: str):
        asset = get_asset(ip)

        if technology not in asset["technologies"]:
            asset["technologies"].append(technology)

    def add_subdomain(ip: str, subdomain: str):
        asset = get_asset(ip)

        if subdomain not in asset["subdomains"]:
            asset["subdomains"].append(subdomain)

        if subdomain not in asset["hostnames"]:
            asset["hostnames"].append(subdomain)

    # =========================================================
    # PASS 1 — DNS → IP + hostname
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
                add_hostname(ip, hostname)

    # =========================================================
    # PASS 2 — correlate results
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
            target = None
            protocol = "tcp"

            if result.result_metadata:
                target = result.result_metadata.get("target")
                protocol = result.result_metadata.get(
                    "protocol",
                    "tcp"
                )

            if not target:
                continue

            target_ips = resolve_target_ips(target)

            for ip in target_ips:

                add_port(ip, value)

                add_service(
                    ip=ip,
                    port=value,
                    protocol=protocol,
                    service=None
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
            target = None

            if result.result_metadata:
                target = result.result_metadata.get(
                    "target"
                )

            if not target:
                continue

            target_ips = resolve_target_ips(target)

            target_port = extract_target_port(target)

            if target_port is None:
                target_port = (
                    443
                    if target.startswith("https://")
                    else 80
                )

            for ip in target_ips:

                asset = get_asset(ip)

                service = None

                for existing in asset["services"]:
                    if (
                        existing["port"]
                        == str(target_port)
                        and existing["protocol"]
                        == "tcp"
                    ):
                        service = existing
                        break

                if service is None:
                    service = {
                        "port": str(target_port),
                        "protocol": "tcp",
                        "service": "http",
                    }

                    asset["services"].append(service)

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
            target = None

            if result.result_metadata:
                target = result.result_metadata.get(
                    "target"
                )

            if not target:
                continue

            target_ips = resolve_target_ips(target)

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

    return {
        "scan_id": scan_id,
        "assets": list(assets.values())
    } 

