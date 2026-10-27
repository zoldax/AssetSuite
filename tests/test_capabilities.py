from dataclasses import replace

import responses

from assetsuite.capabilities import BULK_ASSETS, CREATE_ASSET, detect_capabilities
from assetsuite.client import QRadarClient
from tests.conftest import BASE

# Shape of /help/versions and /help/endpoints as returned by QRadar 7.6.0 FP1.
VERSIONS = [
    {"id": 1, "version": "0.1", "removed": True, "deprecated": False},
    {"id": 30, "version": "24.0", "removed": False, "deprecated": False},
    {"id": 35, "version": "29.0", "removed": False, "deprecated": False},
    {"id": 10, "version": "9.1", "removed": False, "deprecated": True},
]


def endpoint(method, path, version, access=True, deprecated=False):
    return {
        "http_method": method,
        "path": path,
        "version": version,
        "caller_has_access": access,
        "deprecated": deprecated,
    }


BASE_ENDPOINTS = [
    endpoint("GET", "/asset_model/assets", "9.1"),
    endpoint("GET", "/asset_model/assets", "24.0"),
    endpoint("GET", "/asset_model/assets", "29.0"),
    endpoint("POST", "/asset_model/assets/{asset_id}", "24.0"),
    endpoint("POST", "/asset_model/assets/{asset_id}", "29.0"),
    endpoint("POST", "/asset_model/assets", "24.0"),
    endpoint("POST", "/asset_model/assets", "29.0"),
    endpoint("PATCH", "/asset_model/assets", "29.0"),
    endpoint("GET", "/asset_model/asset_bulk_tasks/{id}", "29.0"),
]


def mock_api(endpoints, filter_supported=True):
    responses.get(f"{BASE}/help/versions", json=VERSIONS)
    if filter_supported:
        responses.get(f"{BASE}/help/endpoints", json=endpoints)
    else:
        responses.get(
            f"{BASE}/help/endpoints",
            status=422,
            json={"message": "Invalid filter"},
            match=[
                responses.matchers.query_param_matcher({"filter": 'path ILIKE "/asset_model%"'}, strict_match=False)
            ],
        )
        responses.get(f"{BASE}/help/endpoints", json=endpoints + [endpoint("GET", "/siem/offenses", "29.0")])


def caps_for(config, api_version, endpoints=BASE_ENDPOINTS):
    mock_api(endpoints)
    return detect_capabilities(QRadarClient(replace(config, api_version=api_version)))


@responses.activate
def test_versions_sorted_and_removed_ignored(client):
    mock_api(BASE_ENDPOINTS)
    caps = detect_capabilities(client)
    assert caps.api_versions == ["9.1", "24.0", "29.0"]
    assert caps.latest_version == "29.0"


@responses.activate
def test_endpoints_grouped_by_method_and_path(client):
    mock_api(BASE_ENDPOINTS)
    caps = detect_capabilities(client)
    update = caps.asset_endpoints[("POST", "/asset_model/assets/{asset_id}")]
    assert update.versions == ["24.0", "29.0"]
    assert update.version_range == "24.0 -> 29.0"


@responses.activate
def test_latest_version_used_when_not_pinned(config):
    caps = caps_for(config, None)
    assert caps.effective_version == "29.0"
    assert caps.can_read_assets and caps.can_update_assets and caps.can_create_assets and caps.can_bulk_assets


@responses.activate
def test_create_needs_api_24(config):
    caps = caps_for(config, "9.1")
    assert caps.can_read_assets
    assert not caps.can_create_assets
    available, reason = caps.check(CREATE_ASSET)
    assert not available
    assert "24.0 -> 29.0" in reason and "API 9.1 is used" in reason


@responses.activate
def test_bulk_needs_api_29(config):
    caps = caps_for(config, "24.0")
    assert caps.can_create_assets
    assert not caps.can_bulk_assets


@responses.activate
def test_bulk_needs_task_endpoint_too(config):
    without_task = [e for e in BASE_ENDPOINTS if e["path"] != "/asset_model/asset_bulk_tasks/{id}"]
    caps = caps_for(config, "29.0", without_task)
    available, reason = caps.check(BULK_ASSETS)
    assert not available
    assert "asset_bulk_tasks" in reason


@responses.activate
def test_delete_not_offered(config):
    caps = caps_for(config, "29.0")
    assert not caps.can_delete_assets


@responses.activate
def test_token_without_access(config):
    endpoints = [e for e in BASE_ENDPOINTS if not (e["http_method"] == "POST" and e["path"] == "/asset_model/assets")]
    endpoints.append(endpoint("POST", "/asset_model/assets", "29.0", access=False))
    caps = caps_for(config, "29.0", endpoints)
    available, reason = caps.check(CREATE_ASSET)
    assert not available
    assert "not allowed" in reason


@responses.activate
def test_endpoint_of_removed_version_ignored(client):
    mock_api(BASE_ENDPOINTS + [endpoint("DELETE", "/asset_model/assets/{asset_id}", "0.1")])
    caps = detect_capabilities(client)
    assert ("DELETE", "/asset_model/assets/{asset_id}") not in caps.asset_endpoints


@responses.activate
def test_fallback_when_filter_rejected(config):
    mock_api(BASE_ENDPOINTS, filter_supported=False)
    caps = detect_capabilities(QRadarClient(replace(config, api_version=None)))
    assert ("GET", "/siem/offenses") not in caps.asset_endpoints
    assert caps.can_update_assets
