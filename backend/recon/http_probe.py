from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def probe_http(target: str) -> dict:
    """
    Fetch HTTP metadata and response headers
    from an authorized target.
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

            headers = {
                key.lower(): value
                for key, value in response.headers.items()
            }

            return {
                "status": "success",
                "status_code": response.status,
                "content_type": response.headers.get(
                    "Content-Type"
                ),
                "server": response.headers.get(
                    "Server"
                ),
                "final_url": response.geturl(),
                "headers": headers,
            }

    except HTTPError as error:

        headers = {
            key.lower(): value
            for key, value in error.headers.items()
        }

        return {
            "status": "http_error",
            "status_code": error.code,
            "content_type": error.headers.get(
                "Content-Type"
            ),
            "server": error.headers.get(
                "Server"
            ),
            "final_url": error.geturl(),
            "headers": headers,
        }

    except URLError as error:

        return {
            "status": "connection_error",
            "error": str(error.reason),
            "headers": {},
        }

    except TimeoutError:

        return {
            "status": "timeout",
            "headers": {},
        }