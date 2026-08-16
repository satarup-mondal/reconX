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
            module="http",
            result_type="status_code",
            value=str(result["status_code"]),
            metadata={
                "target": target
            }
        )

        if result.get("content_type"):
            save_result(
                db=db,
                scan_id=scan_id,
                module="http",
                result_type="content_type",
                value=result["content_type"],
                metadata=None
            )

        if result.get("server"):
            save_result(
                db=db,
                scan_id=scan_id,
                module="http",
                result_type="server",
                value=result["server"],
                metadata=None
            )

        save_result(
            db=db,
            scan_id=scan_id,
            module="http",
            result_type="final_url",
            value=result["final_url"],
            metadata=None
        )

    else:
        save_result(
            db=db,
            scan_id=scan_id,
            module="http",
            result_type="error",
            value=str(result.get("error", result)),
            metadata={
                "status": result["status"]
            }
        )


def run_dns(module, target, save_result, db, scan_id):
    result = module(target)

    if result["status"] == "success":
        for address in result["addresses"]:
            save_result(
                db=db,
                scan_id=scan_id,
                module="dns",
                result_type="address",
                value=address,
                metadata={
                    "hostname": result["hostname"]
                }
            )

    else:
        save_result(
            db=db,
            scan_id=scan_id,
            module="dns",
            result_type="error",
            value=str(result.get("error", result)),
            metadata={
                "hostname": target,
                "status": result["status"]
            }
        )


def run_ports(module, target, save_result, db, scan_id):
    result = module(target)

    if result["status"] == "success":
        for port in result["open_ports"]:
            save_result(
                db=db,
                scan_id=scan_id,
                module="ports",
                result_type="open_port",
                value=str(port),
                metadata={
                    "protocol": "tcp"
                }
            )

    else:
        save_result(
            db=db,
            scan_id=scan_id,
            module="ports",
            result_type="error",
            value=str(result),
            metadata={
                "target": target
            }
        )


def run_technology(module, target, save_result, db, scan_id):
    result = module(target)

    if result["status"] == "success":
        for technology in result["technologies"]:
            save_result(
                db=db,
                scan_id=scan_id,
                module="technology",
                result_type="technology",
                value=technology,
                metadata={
                    "target": target
                }
            )

    else:
        save_result(
            db=db,
            scan_id=scan_id,
            module="technology",
            result_type="error",
            value=str(result.get("error", result)),
            metadata={
                "status": result["status"],
                "target": target
            }
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