"""NetBox integration, with payloads shaped like NetBox 4.4 answers (values anonymized)."""

import pytest
import responses
from responses import matchers

from assetsuite.mapping import apply_rule
from assetsuite.netbox import (
    DEFAULT_MAPPING,
    NetBoxClient,
    NetBoxError,
    build_records,
    fetch_records,
    import_rows,
    load_netbox_config,
)

NB = "https://netbox.example.lan"
NB_TOKEN = "0123456789abcdef0123456789abcdef01234567"

DEVICE = {
    "id": 7,
    "name": "nas-01",
    "role": {"id": 1, "name": "Storage"},
    "site": {"id": 1, "name": "Site-A"},
    "location": {"id": 1, "name": "DC-Room"},
    "rack": None,
    "tenant": {"id": 1, "name": "Home"},
    "platform": None,
    "serial": "SN123",
    "asset_tag": "Asset-NAS",
    "description": "Synology NAS",
    "custom_fields": {"bios_version": "1.2"},
}
VM = {
    "id": 3,
    "name": "PROD-Gitlab",
    "role": None,
    "site": {"id": 1, "name": "Site-A"},
    "cluster": {"id": 1, "name": "Cluster-01"},
    "tenant": {"id": 1, "name": "Home"},
    "platform": {"id": 2, "name": "Linux"},
    "description": "Gitlab",
    "custom_fields": {},
}


def ip(address, dns="", desc="", device=None, vm=None, status="active"):
    assigned = None
    if device:
        assigned = {"id": 100, "name": "eth0", "device": {"id": device, "name": "x"}}
    if vm:
        assigned = {"id": 200, "name": "eth0", "virtual_machine": {"id": vm, "name": "x"}}
    return {
        "address": address,
        "dns_name": dns,
        "description": desc,
        "status": {"value": status, "label": status.title()},
        "tenant": {"id": 1, "name": "Home"},
        "assigned_object": assigned,
        "tags": [],
        "custom_fields": {},
    }


IPS = [
    ip("192.0.2.74/24", dns="nas.example.lan", device=7),
    ip("192.0.2.72/24", dns="-", device=7),
    ip("192.0.2.85/24", dns="gitlab.example.lan", desc="Gitlab", vm=3),
    ip("192.0.2.111/24", dns="cti.example.lan", desc="Threat Intelligence VM"),
]


def config(**netbox):
    return load_netbox_config({"netbox": {"url": NB + "/", "token": NB_TOKEN, **netbox}}, environ={})


# --- Configuration -----------------------------------------------------------


def test_config_defaults():
    cfg = config()
    assert cfg.url == NB
    assert cfg.domain == "DEFAULT_DOMAIN" and cfg.statuses == ("active",) and cfg.verify is True
    assert list(cfg.mapping) == list(DEFAULT_MAPPING)
    assert NB_TOKEN not in repr(cfg)


def test_config_from_environment():
    cfg = load_netbox_config({}, environ={"NETBOX_URL": NB, "NETBOX_TOKEN": NB_TOKEN})
    assert cfg.url == NB


@pytest.mark.parametrize(
    ("sections", "message"),
    [
        ({}, "NetBox is not configured"),
        ({"netbox": {"url": NB, "token": "CHANGE_ME"}}, "'netbox.token' is not set"),
        ({"netbox": {"url": NB, "token": "t", "colour": "x"}}, "Unknown netbox setting"),
        ({"netbox": {"url": NB, "token": "t", "mapping": {"Given Name": "hostname"}}}, "unknown field"),
        (
            {"netbox": {"url": NB, "token": "t", "mapping": {"Given Name": {"pick": ["dns_name"]}}}},
            "must be a field name",
        ),
        ({"netbox": {"url": NB, "token": "t", "ssl_cert_path": "/nope.pem"}}, "does not exist"),
    ],
)
def test_config_errors(sections, message):
    with pytest.raises(NetBoxError, match=message):
        load_netbox_config(sections, environ={})


def test_mapping_shorthands_and_custom_fields():
    cfg = config(mapping={"Given Name": "object_name", "Description": ["ip_description", "cf_bios_version"]})
    assert cfg.mapping == {
        "Given Name": {"first": ["object_name"]},
        "Description": {"first": ["ip_description", "cf_bios_version"]},
    }


# --- Records and rows --------------------------------------------------------


def test_build_records():
    records = {r["ip"]: r for r in build_records(IPS, [DEVICE], [VM])}
    nas = records["192.0.2.74"]
    assert (nas["object_type"], nas["object_name"], nas["role"], nas["site"], nas["location"]) == (
        "device",
        "nas-01",
        "Storage",
        "Site-A",
        "DC-Room",
    )
    assert nas["description"] == "Synology NAS" and nas["cf_bios_version"] == "1.2"
    assert records["192.0.2.72"]["dns_name"] == ""  # "-" means no name
    gitlab = records["192.0.2.85"]
    assert (gitlab["object_type"], gitlab["role"], gitlab["platform"], gitlab["description"]) == (
        "virtual machine",
        "Virtual machine",
        "Linux",
        "Gitlab",
    )
    cti = records["192.0.2.111"]
    assert (cti["object_type"], cti["object_name"], cti["tenant"]) == ("", "", "Home")


def test_apply_rule():
    record = {"site": "Site-A", "location": "", "rack": "R1", "object_name": "", "dns_name": "a.lan"}
    assert apply_rule(record, {"join": ["site", "location", "rack"], "separator": " / "}) == "Site-A / R1"
    assert apply_rule(record, {"first": ["object_name", "dns_name"]}) == "a.lan"
    assert apply_rule(record, {"first": ["serial"]}) == ""


def test_import_rows_with_default_mapping():
    header, rows = import_rows(build_records(IPS, [DEVICE], [VM]), config(), "DEFAULT_DOMAIN")
    assert header == ["ip_address", "dns_names", "domain_name", *DEFAULT_MAPPING]
    assert [r.values["ip_address"] for r in rows] == ["192.0.2.72", "192.0.2.74", "192.0.2.85", "192.0.2.111"]
    by_ip = {r.values["ip_address"]: r.values for r in rows}
    assert by_ip["192.0.2.74"]["Given Name"] == "nas-01"
    assert by_ip["192.0.2.74"]["Location"] == "Site-A / DC-Room"
    assert by_ip["192.0.2.111"]["Given Name"] == "cti.example.lan"  # no device: the DNS name
    assert by_ip["192.0.2.111"]["Description"] == "Threat Intelligence VM"
    assert by_ip["192.0.2.85"]["Asset Type"] == "Virtual machine"
    assert by_ip["192.0.2.85"]["User Supplied OS"] == "Linux"
    assert [r.line for r in rows] == [2, 3, 4, 5]


# --- Client ------------------------------------------------------------------


@responses.activate
def test_client_pagination_and_token():
    url = f"{NB}/api/ipam/ip-addresses/"
    responses.get(
        url,
        json={"count": 3, "next": f"{url}?limit=2&offset=2&status=active", "results": IPS[:2]},
        match=[
            matchers.header_matcher({"Authorization": f"Token {NB_TOKEN}"}),
            matchers.query_param_matcher({"limit": "500", "status": "active"}),
        ],
    )
    responses.get(
        url,
        json={"count": 3, "next": None, "results": IPS[2:3]},
        match=[matchers.query_param_matcher({"limit": "2", "offset": "2", "status": "active"})],
    )
    client = NetBoxClient(config())
    assert len(client.get_all("ipam/ip-addresses", params={"status": ["active"]})) == 3


def test_v2_token_uses_bearer():
    cfg = load_netbox_config({"netbox": {"url": NB, "token": "nbt_abc.def"}}, environ={})
    assert NetBoxClient(cfg).session.headers["Authorization"] == "Bearer nbt_abc.def"


@responses.activate
def test_client_errors():
    responses.get(f"{NB}/api/ipam/ip-addresses/", status=403, json={"detail": "Invalid token."})
    with pytest.raises(NetBoxError, match="refused the token"):
        NetBoxClient(config()).get_all("ipam/ip-addresses")


def test_verify_disabled():
    assert NetBoxClient(config(verify_ssl=False)).session.verify is False


@responses.activate
def test_fetch_records_reads_only_assigned_objects():
    responses.get(f"{NB}/api/ipam/ip-addresses/", json={"next": None, "results": IPS})
    responses.get(
        f"{NB}/api/dcim/devices/",
        json={"next": None, "results": [DEVICE]},
        match=[matchers.query_param_matcher({"limit": "500", "id": "7"})],
    )
    responses.get(
        f"{NB}/api/virtualization/virtual-machines/",
        json={"next": None, "results": [VM]},
        match=[matchers.query_param_matcher({"limit": "500", "id": "3"})],
    )
    records = fetch_records(NetBoxClient(config()))
    assert {r["object_name"] for r in records} == {"nas-01", "PROD-Gitlab", ""}
