import pytest
import requests
import responses
from responses import matchers

from assetsuite.client import QRadarAPIError
from tests.conftest import BASE, TOKEN


@responses.activate
def test_headers_sent(client):
    responses.get(
        f"{BASE}/system/about",
        json={"release_name": "7.5.0"},
        match=[matchers.header_matcher({"SEC": TOKEN, "Version": "20.0", "Accept": "application/json"})],
    )
    assert client.get("system/about") == {"release_name": "7.5.0"}


@responses.activate
def test_pagination_follows_content_range(small_page_client):
    url = f"{BASE}/asset_model/assets"
    pages = {
        "items=0-1": ([{"id": 1}, {"id": 2}], "items 0-1/5"),
        "items=2-3": ([{"id": 3}, {"id": 4}], "items 2-3/5"),
        "items=4-5": ([{"id": 5}], "items 4-4/5"),
    }
    for range_header, (body, content_range) in pages.items():
        responses.get(
            url,
            json=body,
            headers={"Content-Range": content_range},
            match=[matchers.header_matcher({"Range": range_header})],
        )
    assert [a["id"] for a in small_page_client.get_all("asset_model/assets")] == [1, 2, 3, 4, 5]
    assert len(responses.calls) == 3


@responses.activate
def test_pagination_without_content_range_stops_on_short_page(small_page_client):
    url = f"{BASE}/config/domain_management/domains"
    responses.get(url, json=[{"id": 0}, {"id": 1}], match=[matchers.header_matcher({"Range": "items=0-1"})])
    responses.get(url, json=[{"id": 2}], match=[matchers.header_matcher({"Range": "items=2-3"})])
    assert len(small_page_client.get_all("config/domain_management/domains")) == 3


@responses.activate
def test_pagination_empty_result(small_page_client):
    responses.get(f"{BASE}/asset_model/assets", json=[], headers={"Content-Range": "items 0--1/0"})
    assert small_page_client.get_all("asset_model/assets") == []


@responses.activate
def test_qradar_error_message_and_hint(client):
    responses.get(
        f"{BASE}/system/about",
        status=401,
        json={"code": 26, "message": "No SEC header present in request", "http_response": {"code": 401}},
    )
    with pytest.raises(QRadarAPIError) as excinfo:
        client.get("system/about")
    error = excinfo.value
    assert error.status == 401
    assert error.code == 26
    assert "No SEC header present" in str(error)
    assert "check the SEC token" in str(error)
    assert TOKEN not in str(error)


@responses.activate
def test_non_json_error(client):
    responses.get(f"{BASE}/system/about", status=500, body="<html>boom</html>")
    with pytest.raises(QRadarAPIError, match="HTTP 500"):
        client.get("system/about")


@responses.activate
def test_network_error(client):
    responses.get(f"{BASE}/system/about", body=requests.ConnectionError("refused"))
    with pytest.raises(QRadarAPIError, match="Cannot reach"):
        client.get("system/about")


@responses.activate
def test_list_expected(client):
    responses.get(f"{BASE}/asset_model/assets", json={"not": "a list"})
    with pytest.raises(QRadarAPIError, match="Expected a list"):
        client.get_all("asset_model/assets")


def test_session_verify_follows_config(client):
    assert client.session.verify is True


@responses.activate
def test_pagination_stops_when_range_ignored(small_page_client):
    # page_size is 2: a server returning 3 items ignored the Range header and sent everything.
    responses.get(f"{BASE}/help/versions", json=[{"v": 1}, {"v": 2}, {"v": 3}])
    assert len(small_page_client.get_all("help/versions")) == 3
    assert len(responses.calls) == 1
