import socket


COMMON_SUBDOMAINS = [
    "www",
    "api",
    "app",
    "dev",
    "test",
    "staging",
    "mail",
]


def probe_subdomains(domain: str) -> dict:
    domain = domain.strip().lower()

    # Remove scheme if one was provided
    domain = domain.replace("https://", "")
    domain = domain.replace("http://", "")

    # Remove path
    domain = domain.split("/", 1)[0]

    # Remove port
    domain = domain.split(":", 1)[0]

    discovered = []

    for prefix in COMMON_SUBDOMAINS:
        hostname = f"{prefix}.{domain}"

        try:
            addresses = socket.gethostbyname_ex(hostname)[2]

            if addresses:
                discovered.append({
                    "subdomain": hostname,
                    "addresses": addresses,
                })

        except socket.gaierror:
            continue

    return {
        "status": "success",
        "domain": domain,
        "subdomains": discovered,
    }