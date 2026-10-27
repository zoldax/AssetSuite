"""
client.py

Minimal QRadar REST API client: authentication, TLS, retries on transient
errors, Range-based pagination and readable error messages.

Copyright 2026 Pascal Weber (zoldax) / Abakus Sécurité
Licensed under the Apache License, Version 2.0 (see LICENSE).
"""

from __future__ import annotations

import logging
import re
from typing import Any, Iterator, Mapping, Optional

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from assetsuite.config import Config

logger = logging.getLogger(__name__)

_CONTENT_RANGE = re.compile(r"items\s+(\d+)-(\d+)/(\d+)")

_STATUS_HINTS = {
    401: " - check the SEC token",
    403: " - the token's security profile or user role lacks this permission",
    404: " - not found (unknown object, or endpoint missing from this api_version)",
}


class QRadarAPIError(Exception):
    """Any failure talking to QRadar: network, TLS, HTTP error or unexpected payload."""

    def __init__(self, message: str, status: Optional[int] = None, code: Optional[int] = None):
        super().__init__(message)
        self.status = status
        self.code = code


class QRadarClient:
    def __init__(self, config: Config, session: Optional[requests.Session] = None):
        self.config = config
        self.base_url = f"https://{config.host}/api"
        self.session = session or self._build_session()

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        # Only GET is retried: a replayed POST could apply a change twice.
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=(429, 502, 503, 504),
            allowed_methods=frozenset({"GET"}),
            raise_on_status=False,
        )
        session.mount("https://", HTTPAdapter(max_retries=retry))
        session.headers.update({"SEC": self.config.token, "Accept": "application/json"})
        if self.config.api_version:
            session.headers["Version"] = self.config.api_version
        session.verify = self.config.verify
        if not self.config.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning("TLS verification is disabled for %s", self.config.host)
        return session

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Mapping[str, Any]] = None,
        json_body: Any = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> requests.Response:
        url = f"{self.base_url}/{path.lstrip('/')}"
        logger.debug("%s %s params=%s", method, url, params)
        try:
            response = self.session.request(
                method, url, params=params, json=json_body, headers=headers, timeout=self.config.timeout
            )
        except requests.exceptions.SSLError as e:
            raise QRadarAPIError(f"TLS verification failed for {self.config.host}: {e}") from e
        except requests.RequestException as e:
            raise QRadarAPIError(f"Cannot reach {self.config.host}: {e}") from e

        if response.status_code >= 400:
            raise self._error_from(method, path, response)
        return response

    def get(self, path: str, params: Optional[Mapping[str, Any]] = None) -> Any:
        return self._json(self.request("GET", path, params=params), path)

    def post(self, path: str, json_body: Any = None, params: Optional[Mapping[str, Any]] = None) -> Any:
        return self._json(self.request("POST", path, params=params, json_body=json_body), path)

    def iter_pages(
        self, path: str, params: Optional[Mapping[str, Any]] = None, page_size: Optional[int] = None
    ) -> Iterator[Any]:
        """Yield every item of a list endpoint, fetching it page by page with the Range header."""
        size = page_size or self.config.page_size
        start = 0
        while True:
            end = start + size - 1
            response = self.request("GET", path, params=params, headers={"Range": f"items={start}-{end}"})
            items = self._json(response, path)
            if not isinstance(items, list):
                raise QRadarAPIError(f"Expected a list from {path}, got {type(items).__name__}")
            yield from items

            # More items than requested means the Range header was ignored and everything came back.
            if not items or len(items) > size:
                return
            match = _CONTENT_RANGE.search(response.headers.get("Content-Range", ""))
            if match:
                if end + 1 >= int(match.group(3)):
                    return
            elif len(items) < size:
                return
            start = end + 1

    def get_all(self, path: str, params: Optional[Mapping[str, Any]] = None) -> list:
        return list(self.iter_pages(path, params=params))

    @staticmethod
    def _json(response: requests.Response, path: str) -> Any:
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError as e:
            raise QRadarAPIError(f"Invalid JSON returned by {path}") from e

    @staticmethod
    def _error_from(method: str, path: str, response: requests.Response) -> QRadarAPIError:
        status = response.status_code
        code = None
        message = response.reason or "error"
        try:
            body = response.json()
        except ValueError:
            body = None
        if isinstance(body, dict):
            # QRadar errors look like {"code": 1002, "message": "...", "description": "...", ...}
            message = body.get("message") or body.get("description") or message
            code = body.get("code")
        hint = _STATUS_HINTS.get(status, "")
        return QRadarAPIError(f"HTTP {status} on {method} /{path.lstrip('/')}: {message}{hint}", status, code)
