"""Small HTTP client used by the terminal workflow to call the PTAS API."""

from __future__ import annotations

import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from Backend.config import settings


class PTASApiError(RuntimeError):
    """Signal that PTASApi could not complete safely.

    Callers catch this specific error to present a controlled failure instead of
    continuing with invalid state.
    """


def default_api_url() -> str:
    """Return a client-safe URL for the host and port used by start.sh."""

    configured = os.getenv("PTAS_API_URL", "").strip().rstrip("/")
    if configured:
        return configured
    host = settings.api_host
    if host in {"0.0.0.0", "::"}:
        host = "127.0.0.1"
    return f"http://{host}:{settings.api_port}"


class PTASApiClient:
    """Coordinate the responsibilities of PTASApiClient.

    Its public methods provide the supported interface used by the rest of PTAS.
    """

    def __init__(self, base_url: str | None = None):
        """Initialize the object with the dependencies required by its public operations.

        Dependencies are stored once so each call uses the same request-scoped
        collaborators.
        """
        self.base_url = (base_url or default_api_url()).rstrip("/")
        self.access_token: str | None = None

    def get(
        self,
        path: str,
        *,
        query: dict | None = None,
        timeout: float = 15,
    ):
        """Perform the get operation for PTASApiClient.

        The type hints describe accepted inputs and the value returned to the caller.
        """

        return self._request("GET", path, query=query, timeout=timeout)

    def post(
        self,
        path: str,
        payload: dict | None = None,
        *,
        query: dict | None = None,
        timeout: float = 15,
    ):
        """Perform the post operation for PTASApiClient.

        The type hints describe accepted inputs and the value returned to the caller.
        """

        return self._request(
            "POST",
            path,
            payload=payload,
            query=query,
            timeout=timeout,
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: dict | None = None,
        query: dict | None = None,
        timeout: float,
    ):
        """Implement the internal request step used by this module's public workflow.

        It remains private so callers depend on the supported public interface.
        """

        url = f"{self.base_url}{path}"
        if query:
            url = f"{url}?{urlencode(query)}"
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"

        request = Request(url, data=body, headers=headers, method=method)
        try:
            with urlopen(request, timeout=timeout) as response:
                content = response.read().decode("utf-8")
        except HTTPError as exc:
            detail = self._error_detail(exc)
            raise PTASApiError(f"API returned HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            reason = getattr(exc, "reason", exc)
            raise PTASApiError(
                f"Cannot connect to PTAS API at {self.base_url}: {reason}. "
                "Start ./start.sh in the VS Code terminal first."
            ) from exc

        if not content:
            return None
        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            raise PTASApiError("PTAS API returned an invalid JSON response") from exc

    @staticmethod
    def _error_detail(error: HTTPError) -> str:
        """Implement the internal error detail step used by this module's public workflow.

        It remains private so callers depend on the supported public interface.
        """

        try:
            payload = json.loads(error.read().decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return error.reason
        detail = payload.get("detail", error.reason)
        if isinstance(detail, list):
            messages = [
                item.get("msg", str(item)) if isinstance(item, dict) else str(item)
                for item in detail
            ]
            return "; ".join(messages)
        return str(detail)
