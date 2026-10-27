"""
capabilities.py

Detects which API versions and asset model endpoints the target QRadar
exposes, and whether the token may use them. Creating and deleting assets
are recent API features, so AssetSuite reads /api/help/endpoints instead of
assuming a feature from a version number.

Observed on QRadar 7.6.0 FP1 (API 4.0 -> 29.0):
  POST   /asset_model/assets             create one asset          API 24.0+
  DELETE /asset_model/assets/{asset_id}  delete one asset          API 26.0+
  PATCH  /asset_model/assets             bulk create/delete, async API 29.0+
  GET    /asset_model/asset_bulk_tasks/{id}  bulk task status      API 29.0+

Copyright 2026 Pascal Weber (zoldax) / Abakus Sécurité
Licensed under the Apache License, Version 2.0 (see LICENSE).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from assetsuite.client import QRadarAPIError, QRadarClient

ASSET_MODEL_PREFIX = "/asset_model"
ENDPOINT_FIELDS = "http_method,path,version,deprecated,caller_has_access"


@dataclass(frozen=True)
class Feature:
    label: str
    endpoints: Tuple[Tuple[str, str], ...]


READ_ASSETS = Feature("Read assets", (("GET", "/asset_model/assets"),))
UPDATE_ASSET = Feature("Update asset properties", (("POST", "/asset_model/assets/{asset_id}"),))
CREATE_ASSET = Feature("Create missing assets", (("POST", "/asset_model/assets"),))
DELETE_ASSET = Feature("Delete assets", (("DELETE", "/asset_model/assets/{asset_id}"),))
BULK_ASSETS = Feature(
    "Bulk create/delete (async)",
    (("PATCH", "/asset_model/assets"), ("GET", "/asset_model/asset_bulk_tasks/{id}")),
)
FEATURES = (READ_ASSETS, UPDATE_ASSET, CREATE_ASSET, DELETE_ASSET, BULK_ASSETS)


def version_key(version: str) -> Tuple[int, ...]:
    """Sort key for API versions such as '9.1', '15.0', '20.0'."""
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError:
        return (0,)


@dataclass
class Endpoint:
    method: str
    path: str
    versions: List[str] = field(default_factory=list)
    access: Dict[str, bool] = field(default_factory=dict)  # version -> caller_has_access
    deprecated: Dict[str, bool] = field(default_factory=dict)  # version -> deprecated

    @property
    def version_range(self) -> str:
        if not self.versions:
            return "-"
        if len(self.versions) == 1:
            return self.versions[0]
        return f"{self.versions[0]} -> {self.versions[-1]}"


@dataclass
class Capabilities:
    api_versions: List[str]
    asset_endpoints: Dict[Tuple[str, str], Endpoint]
    configured_version: Optional[str] = None

    @property
    def latest_version(self) -> Optional[str]:
        return self.api_versions[-1] if self.api_versions else None

    @property
    def effective_version(self) -> Optional[str]:
        return self.configured_version or self.latest_version

    def check(self, feature: Feature) -> Tuple[bool, str]:
        """(available, reason) for a feature, with the API version AssetSuite will actually use."""
        version = self.effective_version
        for method, path in feature.endpoints:
            endpoint = self.asset_endpoints.get((method, path))
            if endpoint is None:
                return False, f"{method} {path} is not offered by this QRadar"
            if version not in endpoint.versions:
                return False, f"{method} {path} exists in API {endpoint.version_range}, API {version} is used"
            if not endpoint.access.get(version, True):
                return False, f"the token is not allowed to call {method} {path}"
        return True, ""

    @property
    def can_read_assets(self) -> bool:
        return self.check(READ_ASSETS)[0]

    @property
    def can_update_assets(self) -> bool:
        return self.check(UPDATE_ASSET)[0]

    @property
    def can_create_assets(self) -> bool:
        return self.check(CREATE_ASSET)[0]

    @property
    def can_delete_assets(self) -> bool:
        return self.check(DELETE_ASSET)[0]

    @property
    def can_bulk_assets(self) -> bool:
        return self.check(BULK_ASSETS)[0]


def _fetch_asset_endpoints(client: QRadarClient) -> list:
    try:
        return client.get_all(
            "help/endpoints",
            params={"fields": ENDPOINT_FIELDS, "filter": f'path ILIKE "{ASSET_MODEL_PREFIX}%"'},
        )
    except QRadarAPIError as e:
        # Older releases may not accept ILIKE on this resource: filter locally instead.
        if e.status in (401, 403) or e.status is None:
            raise
        return [
            endpoint
            for endpoint in client.get_all("help/endpoints", params={"fields": ENDPOINT_FIELDS})
            if str(endpoint.get("path", "")).startswith(ASSET_MODEL_PREFIX)
        ]


def detect_capabilities(client: QRadarClient) -> Capabilities:
    versions = sorted(
        {str(v["version"]) for v in client.get_all("help/versions") if v.get("version") and not v.get("removed")},
        key=version_key,
    )
    live = set(versions)

    endpoints: Dict[Tuple[str, str], Endpoint] = {}
    for raw in _fetch_asset_endpoints(client):
        version = str(raw.get("version"))
        if version not in live:  # endpoint of a removed API version
            continue
        method = str(raw.get("http_method", "")).upper()
        path = str(raw.get("path", ""))
        endpoint = endpoints.setdefault((method, path), Endpoint(method, path))
        endpoint.versions.append(version)
        endpoint.access[version] = bool(raw.get("caller_has_access", True))
        endpoint.deprecated[version] = bool(raw.get("deprecated", False))
    for endpoint in endpoints.values():
        endpoint.versions = sorted(set(endpoint.versions), key=version_key)

    return Capabilities(
        api_versions=versions,
        asset_endpoints=dict(sorted(endpoints.items(), key=lambda item: (item[0][1], item[0][0]))),
        configured_version=client.config.api_version,
    )
