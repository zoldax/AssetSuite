import ipaddress

import pytest
import responses
from responses import matchers

from assetsuite.assets import (
    AssetFilter,
    LookupFailed,
    asset_rows,
    export_columns,
    fetch_assets,
    find_saved_search,
    first_seen,
    last_seen,
    saved_search_asset_ids,
)
from tests.conftest import BASE
from tests.fixtures import HOSTNAME_ONLY, NOW, SERVER, WORKSTATION

DOMAIN_NAMES = {0: "DEFAULT_DOMAIN", 1: "PROD1"}


def make_filter(**kwargs):
    return AssetFilter(now=NOW, **kwargs)


def test_last_and_first_seen():
    assert last_seen(WORKSTATION).isoformat() == "2026-10-25T12:00:00+00:00"
    assert first_seen(WORKSTATION).isoformat() == "2025-09-22T12:00:00+00:00"
    assert last_seen(HOSTNAME_ONLY) is None


def test_scanner_sighting_counts_as_seen():
    assert last_seen(SERVER).isoformat() == "2026-08-28T12:00:00+00:00"


@pytest.mark.parametrize(
    ("cidrs", "expected"),
    [
        (["192.0.2.0/24"], {2723}),
        (["10.0.0.0/8"], {3001}),
        (["2001:db8::/32"], {3001}),
        (["192.0.2.0/24", "10.2.0.0/16"], {2723, 3001}),
        (["172.16.0.0/12"], set()),
    ],
)
def test_cidr_filter(cidrs, expected):
    flt = make_filter(networks=[ipaddress.ip_network(c) for c in cidrs])
    assert {a["id"] for a in (WORKSTATION, SERVER, HOSTNAME_ONLY) if flt.matches(a)} == expected


def test_seen_within_and_stale_filters():
    assets = (WORKSTATION, SERVER, HOSTNAME_ONLY)
    assert {a["id"] for a in assets if make_filter(seen_within_days=7).matches(a)} == {2723}
    # Never seen counts as stale.
    assert {a["id"] for a in assets if make_filter(not_seen_for_days=30).matches(a)} == {3001, 2757}


def test_property_filters():
    assets = (WORKSTATION, SERVER, HOSTNAME_ONLY)
    assert {a["id"] for a in assets if make_filter(properties={"Business Owner": "SOC"}).matches(a)} == {2723}
    assert {a["id"] for a in assets if make_filter(properties={"Business Owner": ""}).matches(a)} == {3001, 2757}


def test_asset_row():
    [row] = asset_rows(SERVER, ["Given Name", "Business Owner"], DOMAIN_NAMES)
    assert row["domain_name"] == "PROD1"
    assert row["ip_addresses"] == "10.1.1.24;2001:db8::24;10.2.0.5"
    assert row["mac_addresses"] == "00:14:22:01:23:44;00:14:22:01:23:45"
    assert row["netbios_names"] == "srv-db01"
    assert row["dns_names"] == ""
    assert row["products"] == "Microsoft Windows Server 2022"
    assert row["Given Name"] == "SRV-DB01"
    assert row["Business Owner"] == ""
    assert set(row) == set(export_columns(["Given Name", "Business Owner"], per_ip=False))


def test_per_ip_rows_follow_cidr_filter():
    flt = make_filter(networks=[ipaddress.ip_network("10.0.0.0/8")])
    rows = list(asset_rows(SERVER, [], DOMAIN_NAMES, per_ip=True, asset_filter=flt))
    assert [(r["ip_address"], r["mac_address"]) for r in rows] == [
        ("10.1.1.24", "00:14:22:01:23:44"),
        ("10.2.0.5", "00:14:22:01:23:45"),
    ]
    assert all(r["ip_addresses"] == "10.1.1.24;2001:db8::24;10.2.0.5" for r in rows)


def test_per_ip_keeps_asset_without_ip():
    [row] = asset_rows(HOSTNAME_ONLY, [], DOMAIN_NAMES, per_ip=True)
    assert row["ip_address"] == ""
    assert row["dns_names"] == "gitlab"


def test_per_ip_columns_order():
    columns = export_columns(["Given Name"], per_ip=True)
    assert columns[:7] == ["id", "domain_id", "domain_name", "ip_address", "ip_type", "network_id", "mac_address"]
    assert columns[-1] == "Given Name"


SEARCHES = [
    {"id": 14, "name": "FTP Servers", "owner": "admin", "is_shared": True, "filters": []},
    {"id": 20, "name": "Stale", "owner": "admin", "is_shared": True, "filters": []},
    {"id": 21, "name": "Stale", "owner": "bob", "is_shared": False, "filters": []},
]


@responses.activate
def test_find_saved_search_by_id_and_name(client):
    responses.get(f"{BASE}/asset_model/saved_searches", json=SEARCHES)
    assert find_saved_search(client, "20")["name"] == "Stale"
    assert find_saved_search(client, "ftp servers")["id"] == 14


@responses.activate
def test_find_saved_search_errors(client):
    responses.get(f"{BASE}/asset_model/saved_searches", json=SEARCHES)
    with pytest.raises(LookupFailed, match="No asset saved search"):
        find_saved_search(client, "nope")
    with pytest.raises(LookupFailed, match="ids 20, 21"):
        find_saved_search(client, "Stale")


@responses.activate
def test_saved_search_ids(client):
    responses.get(
        f"{BASE}/asset_model/saved_searches/20/results",
        json=[{"id": 2723}, {"id": 3001}],
        match=[matchers.query_param_matcher({"fields": "id"})],
    )
    assert saved_search_asset_ids(client, 20) == [2723, 3001]


@responses.activate
def test_fetch_assets_by_ids_in_chunks(client, monkeypatch):
    monkeypatch.setattr("assetsuite.assets.ID_CHUNK", 2)
    url = f"{BASE}/asset_model/assets"
    responses.get(
        url,
        json=[WORKSTATION, SERVER],
        headers={"Content-Range": "items 0-1/2"},
        match=[matchers.query_param_matcher({"filter": "id IN (2723,3001) and domain_id = 1"})],
    )
    responses.get(
        url,
        json=[HOSTNAME_ONLY],
        match=[matchers.query_param_matcher({"filter": "id IN (2757) and domain_id = 1"})],
    )
    assert [a["id"] for a in fetch_assets(client, domain_id=1, asset_ids=[2723, 3001, 2757])] == [2723, 3001, 2757]


@responses.activate
def test_fetch_assets_by_domain(client):
    responses.get(
        f"{BASE}/asset_model/assets",
        json=[SERVER],
        match=[matchers.query_param_matcher({"filter": "domain_id = 1"})],
    )
    assert fetch_assets(client, domain_id=1) == [SERVER]
