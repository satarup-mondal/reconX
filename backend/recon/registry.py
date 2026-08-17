from backend.recon.http_probe import probe_http
from backend.recon.dns_probe import probe_dns
from backend.recon.port_probe import probe_ports
from backend.recon.tech_probe import probe_technology
from backend.recon.subdomain_probe import probe_subdomains


# =========================================================
# HTTP
# =========================================================

def run_http(module, target, save_result, db, scan_id):
    result = module(target)

    if result["status"] == "success":

        metadata = {
            "target": target
        }

        save_result(
            db=db,
            scan_id=scan_id,
            module="http",
            result_type="status_code",
            value=str(result["status_code"]),
            metadata=metadata
        )

        if result.get("content_type"):
            save_result(
                db=db,
                scan_id=scan_id,
                module="http",
                result_type="content_type",
                value=result["content_type"],
                metadata=metadata
            )

        if result.get("server"):
            save_result(
                db=db,
                scan_id=scan_id,
                module="http",
                result_type="server",
                value=result["server"],
                metadata=metadata
            )

        if result.get("final_url"):
            save_result(
                db=db,
                scan_id=scan_id,
                module="http",
                result_type="final_url",
                value=result["final_url"],
                metadata=metadata
            )

    else:
        save_result(
            db=db,
            scan_id=scan_id,
            module="http",
            result_type="error",
            value=str(result.get("error", result)),
            metadata={
                "target": target,
                "status": result.get("status")
            }
        )


# =========================================================
# DNS
# =========================================================

def run_dns(module, target, save_result, db, scan_id):
    result = module(target)

    if result["status"] == "success":

        for address in result.get("addresses", []):
            save_result(
                db=db,
                scan_id=scan_id,
                module="dns",
                result_type="address",
                value=address,
                metadata={
                    "hostname": result.get(
                        "hostname",
                        target
                    )
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
                "hostname": target
            }
        )


# =========================================================
# PORTS
# =========================================================

def run_ports(module, target, save_result, db, scan_id):
    result = module(target)

    if result["status"] == "success":

        for port in result.get("open_ports", []):
            save_result(
                db=db,
                scan_id=scan_id,
                module="ports",
                result_type="open_port",
                value=str(port),
                metadata={
                    "target": target,
                    "protocol": "tcp"
                }
            )

    else:
        save_result(
            db=db,
            scan_id=scan_id,
            module="ports",
            result_type="error",
            value=str(result.get("error", result)),
            metadata={
                "target": target
            }
        )


# =========================================================
# TECHNOLOGY
# =========================================================

def run_technology(module, target, save_result, db, scan_id):
    result = module(target)

    if result["status"] == "success":

        for technology in result.get(
            "technologies",
            []
        ):
            save_result(
                db=db,
                scan_id=scan_id,
                module="technology",
                result_type="technology",
                value=str(technology),
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
                "target": target
            }
        )


# =========================================================
# SUBDOMAINS
# =========================================================

def run_subdomain(module, target, save_result, db, scan_id):
    result = module(target)

    if result["status"] == "success":

        for item in result.get(
            "subdomains",
            []
        ):
            save_result(
                db=db,
                scan_id=scan_id,
                module="subdomain",
                result_type="subdomain",
                value=item["subdomain"],
                metadata={
                    "addresses": item.get(
                        "addresses",
                        []
                    )
                }
            )

    else:
        save_result(
            db=db,
            scan_id=scan_id,
            module="subdomain",
            result_type="error",
            value=str(result.get("error", result)),
            metadata={
                "target": target
            }
        )


# =========================================================
# MODULE REGISTRY
# =========================================================

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

    "subdomain": {
        "function": probe_subdomains,
        "handler": run_subdomain,
        "target": "host",
    },
}


# =========================================================
# SCAN PROFILES
# =========================================================

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

    "full": [
        "http",
        "dns",
        "ports",
        "technology",
        "subdomain",
    ],
}