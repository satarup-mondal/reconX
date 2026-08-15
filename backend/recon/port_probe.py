import socket


DEFAULT_PORTS = [
    22,
    80,
    443,
    8000,
    8080,
    9000,
]


def probe_ports(
    target: str,
    ports: list[int] | None = None,
    timeout: float = 1.0
) -> dict:
    """
    Check a small, explicit set of TCP ports on an authorized target.
    """

    ports = ports or DEFAULT_PORTS
    open_ports = []

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            result = sock.connect_ex((target, port))

            if result == 0:
                open_ports.append(port)

        except OSError:
            pass

        finally:
            sock.close()

    return {
        "status": "success",
        "target": target,
        "open_ports": open_ports
    }