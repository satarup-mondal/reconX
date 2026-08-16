from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


def probe_technology(target: str) -> dict:
    """
    Identify basic technology/server hints from an HTTP response.
    Use only against authorized targets.
    """

    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    request = Request(
        target,
        headers={
            "User-Agent": "ReconX/0.1"
        }
    )

    try:
        with urlopen(request, timeout=5) as response:
            headers = response.headers

            technologies = []

            server = headers.get("Server", "")
            powered_by = headers.get("X-Powered-By", "")

            if server:
                technologies.append(f"server:{server}")

            if powered_by:
                technologies.append(
                    f"powered_by:{powered_by}"
                )

            return {
                "status": "success",
                "target": target,
                "technologies": technologies
            }

    except HTTPError as error:
        return {
            "status": "http_error",
            "target": target,
            "error": str(error)
        }

    except URLError as error:
        return {
            "status": "connection_error",
            "target": target,
            "error": str(error.reason)
        }

    except TimeoutError:
        return {
            "status": "timeout",
            "target": target
        }