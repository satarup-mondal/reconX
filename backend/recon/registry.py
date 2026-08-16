from backend.recon.http_probe import probe_http
from backend.recon.dns_probe import probe_dns
from backend.recon.port_probe import probe_ports
from backend.recon.tech_probe import probe_technology


def run_http(module, target, save_result, db, scan_id):
    result = module(target)

    if result["status"] == "success":
        save_result(
            db=db,
            scan_id=scan_id,
            result_type="http_status",
            value=str(result["status_code"])
        )

        if result.get("content_type"):
            save_result(
                db=db,
                scan_id=scan_id,
                result_type="content_type",
                value=result["content_type"]
            )

        if result.get("server"):
            save_result(
                db=db,
                scan_id=scan_id,
                result_type="server",
                value=result["server"]
            )

        save_result(
            db=db,
            scan_id=scan_id,
            result_type="final_url",
            value=result["final_url"]
        )
    else:
        save_result(
            db=db,
            scan_id=scan_id,
            result_type=result["status"],
            value=str(result.get("error", result))
        )


def run_dns(module, target, save_result, db, scan_id):
    result = module(target)

    if result["status"] == "success":
        for address in result["addresses"]:
            save_result(
                db=db,
                scan_id=scan_id,
                result_type="dns",
                value=address
            )
    else:
        save_result(
            db=db,
            scan_id=scan_id,
            result_type="dns_error",
            value=result["error"]
        )


def run_ports(module, target, save_result, db, scan_id):
    result = module(target)

    if result["status"] == "success":
        for port in result["open_ports"]:
            save_result(
                db=db,
                scan_id=scan_id,
                result_type="open_port",
                value=str(port)
            )
    else:
        save_result(
            db=db,
            scan_id=scan_id,
            result_type="port_error",
            value=str(result)
        )


def run_technology(module, target, save_result, db, scan_id):
    result = module(target)

    if result["status"] == "success":
        for technology in result["technologies"]:
            save_result(
                db=db,
                scan_id=scan_id,
                result_type="technology",
                value=technology
            )
    else:
        save_result(
            db=db,
            scan_id=scan_id,
            result_type="technology_error",
            value=str(result.get("error", result))
        )


RECON_MODULES = {
    "http": {
        "function": probe_http,
        "handler": run_http,
        "target": "domain",
    },
    "dns": {
        "function": probe_dns,
        "handler": run_dns,
        "target": "host",
    },
    "ports": {
        "function": probe_ports,
        "handler": run_ports,
        "target": "host",
    },
    "technology": {
        "function": probe_technology,
        "handler": run_technology,
        "target": "domain",
    },
}


SCAN_PROFILES = {
    "basic": [
        "http",
        "dns",
        "ports",
    ],
    "web": [
        "http",
        "dns",
        "technology",
    ],
    "network": [
        "dns",
        "ports",
    ],
}