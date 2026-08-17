import socket
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from backend.models import ScanResult


def resolve_target_ips(target: str) -> list[str]:
    """
    Convert a target such as:

        recon.local
        recon.local:9000
        http://recon.local:9000
        127.0.0.1:9000

    into resolved IP addresses.
    """

    if not target:
        return []

    target = target.strip()

    # Add // so urlsplit treats the value as netloc
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
    # PASS 1
    # DNS results create the initial IP -> hostname mapping
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
    # Correlate ports, technologies and subdomains
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

            if result.result_metadata:
                target = result.result_metadata.get("target")

            if not target:
                continue

            target_ips = resolve_target_ips(target)

            for ip in target_ips:
                add_port(
                    ip=ip,
                    port=value
                )

        # -----------------------------------------------------
        # TECHNOLOGY
        # -----------------------------------------------------

        elif (
            module == "technology"
            and result_type == "technology"
        ):
            target = None

            if result.result_metadata:
                target = result.result_metadata.get("target")

            if not target:
                continue

            target_ips = resolve_target_ips(target)

            for ip in target_ips:
                add_technology(
                    ip=ip,
                    technology=value
                )

        # -----------------------------------------------------
        # SUBDOMAIN
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