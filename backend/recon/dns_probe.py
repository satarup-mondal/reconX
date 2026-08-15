import socket


def probe_dns(target: str) -> dict:
    hostname = target.strip()

    try:
        addresses = socket.gethostbyname_ex(hostname)[2]

        return {
            "status": "success",
            "hostname": hostname,
            "addresses": addresses
        }

    except socket.gaierror as error:
        return {
            "status": "dns_error",
            "hostname": hostname,
            "error": str(error)
        }