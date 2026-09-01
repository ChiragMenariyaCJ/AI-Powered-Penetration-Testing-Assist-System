
# This file handles api client.
from __future__ import annotations

import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from Backend.config import settings


# Handle the ptas API error.
class PTASApiError(RuntimeError):
    pass


# Work with default API URL.
def default_api_url() -> str:

    configured = os.getenv("PTAS_API_URL", "").strip().rstrip("/")
    if configured:
        return configured
    host = settings.api_host
    if host in {"0.0.0.0", "::"}:
        host = "127.0.0.1"
    return f"http://{host}:{settings.api_port}"


# Handle the ptas API client.
class PTASApiClient:

    # Set up this object.
    def __init__(self, base_url: str | None = None):
        self.base_url = (base_url or default_api_url()).rstrip("/")
        self.access_token: str | None = None

    # Get get.
    def get(
        self,
        path: str,
        *,
        query: dict | None = None,
        timeout: float = 15,
    ):

        return self._request("GET", path, query=query, timeout=timeout)

    # Send a POST request to the API.
    def post(
        self,
        path: str,
        payload: dict | None = None,
        *,
        query: dict | None = None,
        timeout: float = 15,
    ):

        return self._request(
            "POST",
            path,
            payload=payload,
            query=query,
            timeout=timeout,
        )

    # Request request.
    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: dict | None = None,
        query: dict | None = None,
        timeout: float,
    ):

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

    # Work with error detail.
    @staticmethod
    def _error_detail(error: HTTPError) -> str:

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
