"""phpIPAM integration, with payloads shaped like phpIPAM 1.8.3 answers (values made up)."""

import pytest
import responses
from responses import matchers

from assetsuite.phpipam import (
    DEFAULT_MAPPING,
    PhpIpamClient,
    PhpIpamData,
    PhpIpamError,
    build_records,
    fetch_records,
    import_rows,
    load_phpipam_config,
)

PI = "https://ipam.example.lan"
API = f"{PI}/api/assetsuite"
PI_TOKEN = "AbCdEf0123456789AbCdEf0123456789"

STATUSES = [
    {"id": "1", "type": "Offline", "showtag": "1", "bgcolor": "#f59c99", "fgcolor": "#fff", "compress": "No"},
    {"id": "2", "type": "Used", "showtag": "0", "bgcolor": "#a9c9a4", "fgcolor": "#fff", "compress": "No"},
    {"id": "3", "type": "Reserved", "showtag": "1", "bgcolor": "#9ac0cd", "fgcolor": "#fff", "compress": "No"},
    {"id": "4", "type": "DHCP", "showtag": "1", "bgcolor": "#c9c9c9", "fgcolor": "#fff", "compress": "Yes"},
]
SECTIONS = [{"id": "1", "name": "Customers", "description": ""}, {"id": "2", "name": "Lab", "description": ""}]
SUBNETS = {
    "1": [{"id": "7", "subnet": "198.51.100.0", "mask": "24", "sectionId": "1", "description": "Customer A"}],
    "2": [{"id": "3", "subnet": "192.0.2.0", "mask": "24", "sectionId": "2", "description": "Servers"}],
}
DEVICES = [{"id": "5", "hostname": "nas-01", "description": "Synology NAS", "type": "9", "location": "2"}]
DEVICE_TYPES = [{"tid": "1", "tname": "Switch", "tdescription": ""}, {"tid": "9", "tname": "Other", "tdescription": ""}]
LOCATIONS = [{"id": "2", "name": "DC-Room", "description": "", "address": "", "lat": "", "long": ""}]


def address(ip, subnet="3", tag="2", **values):
    """An address as addresses/all gives it: every field, empty ones null or "0"."""
    fields = {
        "id": ip.split(".")[-1],
        "subnetId": subnet,
        "ip": ip,
        "is_gateway": "0",
        "description": None,
        "hostname": None,
        "mac": None,
        "owner": None,
        "tag": tag,
        "deviceId": "0",
        "location": "0",
        "port": None,
        "note": None,
        "lastSeen": "1970-01-01 00:00:01",
        "excludePing": "0",
        "PTRignore": "0",
        "PTR": "0",
        "firewallAddressObject": None,
        "editDate": None,
        "customer_id": None,
    }
    fields.update(values)
    return fields


ADDRESSES = [
    address("192.0.2.74", hostname="nas.example.lan", description="NAS", deviceId="5", mac="00-00-5E-00-53-01"),
    address("192.0.2.10", hostname="dc01.example.lan", description="Domain controller", owner="IT", note="Rack A1"),
    address("192.0.2.111", description="Threat Intelligence VM", custom_backup="weekly"),
    address("192.0.2.200", tag="4", description="DHCP pool"),
    address("192.0.2.31", hostname="printer.example.lan", description="-- autodiscovered --"),
    address("198.51.100.7", subnet="7", hostname="web.customer-a.example", description="Customer A web"),
]


def config(**phpipam):
    section = {"url": PI + "/", "app_id": "assetsuite", "token": PI_TOKEN, **phpipam}
    return load_phpipam_config({"phpipam": section}, environ={})


def data(addresses=ADDRESSES):
    subnets = [s for group in SUBNETS.values() for s in group]
    return PhpIpamData(addresses, STATUSES, SECTIONS, subnets, DEVICES, DEVICE_TYPES, LOCATIONS)


# --- Configuration -----------------------------------------------------------


def test_config_defaults():
    cfg = config()
    assert (cfg.url, cfg.app_id) == (PI, "assetsuite")
    assert cfg.domain == "DEFAULT_DOMAIN" and cfg.statuses == ("Used",) and cfg.sections == () and cfg.verify is True
    assert list(cfg.mapping) == list(DEFAULT_MAPPING)
    assert PI_TOKEN not in repr(cfg)


def test_config_url_with_api_and_environment():
    assert config(url=f"{PI}/api/").url == PI
    cfg = load_phpipam_config(
        {}, environ={"PHPIPAM_URL": PI, "PHPIPAM_APP_ID": "assetsuite", "PHPIPAM_TOKEN": PI_TOKEN}
    )
    assert (cfg.url, cfg.app_id, cfg.token) == (PI, "assetsuite", PI_TOKEN)


@pytest.mark.parametrize(
    ("section", "message"),
    [
        (None, "phpIPAM is not configured"),
        ({"url": PI, "token": "t"}, "phpIPAM is not configured"),
        ({"url": PI, "app_id": "a", "token": "CHANGE_ME"}, "'phpipam.token' is not set"),
        ({"url": PI, "app_id": "a", "token": "t", "colour": "x"}, "Unknown phpipam setting"),
        ({"url": PI, "app_id": "a", "token": "t", "mapping": {"Given Name": "dns_name"}}, "unknown field"),
        ({"url": PI, "app_id": "a", "token": "t", "statuses": [1]}, "must be a list of names"),
        ({"url": PI, "app_id": "a", "token": "t", "ssl_cert_path": "/nope.pem"}, "does not exist"),
    ],
)
def test_config_errors(section, message):
    with pytest.raises(PhpIpamError, match=message):
        load_phpipam_config({"phpipam": section} if section else {}, environ={})


def test_mapping_with_custom_fields():
    cfg = config(mapping={"Given Name": "hostname", "Description": ["note", "custom_backup"]})
    assert cfg.mapping == {"Given Name": {"first": ["hostname"]}, "Description": {"first": ["note", "custom_backup"]}}


# --- Records and rows --------------------------------------------------------


def test_build_records():
    records, read = build_records(data(), config())
    assert read == 6
    by_ip = {r["ip"]: r for r in records}
    assert "192.0.2.200" not in by_ip  # DHCP: only Used by default
    nas = by_ip["192.0.2.74"]
    assert (nas["device_name"], nas["device_description"], nas["device_type"], nas["location"]) == (
        "nas-01",
        "Synology NAS",
        "Other",
        "DC-Room",  # the location of the device, the address having none
    )
    assert (nas["mac"], nas["status"], nas["section"], nas["subnet"], nas["subnet_description"]) == (
        "00:00:5e:00:53:01",
        "Used",
        "Lab",
        "192.0.2.0/24",
        "Servers",
    )
    dc = by_ip["192.0.2.10"]
    assert (dc["owner"], dc["note"], dc["device_name"], dc["location"]) == ("IT", "Rack A1", "", "")
    assert by_ip["192.0.2.111"]["custom_backup"] == "weekly"
    assert by_ip["198.51.100.7"]["section"] == "Customers"
    assert by_ip["192.0.2.31"]["description"] == ""  # the text of phpIPAM scans, not a description


def test_statuses_and_sections_of_the_config():
    records, _ = build_records(data(), config(statuses=["used", "DHCP"], sections=["lab"]))
    assert sorted(r["ip"] for r in records) == ["192.0.2.10", "192.0.2.111", "192.0.2.200", "192.0.2.31", "192.0.2.74"]
    records, _ = build_records(data(), config(statuses=[]))  # no status filter
    assert len(records) == 6


def test_import_rows_with_default_mapping():
    records, _ = build_records(data(), config())
    header, rows = import_rows(records, config(), "DEFAULT_DOMAIN")
    assert header == ["ip_address", "mac_address", "dns_names", "domain_name", *DEFAULT_MAPPING]
    assert [r.values["ip_address"] for r in rows] == [
        "192.0.2.10",
        "192.0.2.31",
        "192.0.2.74",
        "192.0.2.111",
        "198.51.100.7",
    ]
    by_ip = {r.values["ip_address"]: r.values for r in rows}
    nas = by_ip["192.0.2.74"]
    assert (nas["Given Name"], nas["Description"], nas["Location"], nas["Asset Type"]) == (
        "nas.example.lan",
        "NAS",
        "DC-Room",
        "Other",
    )
    assert (nas["mac_address"], nas["dns_names"]) == ("00:00:5e:00:53:01", "nas.example.lan")
    assert by_ip["192.0.2.10"]["Business Owner"] == "IT"
    cti = by_ip["192.0.2.111"]
    assert (cti["Given Name"], cti["dns_names"], cti["Description"]) == ("", "", "Threat Intelligence VM")
    assert [r.line for r in rows] == [2, 3, 4, 5, 6]


# --- Client ------------------------------------------------------------------


@responses.activate
def test_client_token_and_envelope():
    responses.get(
        f"{API}/addresses/tags/",
        json={"code": 200, "success": True, "data": STATUSES, "time": 0.01},
        match=[matchers.header_matcher({"token": PI_TOKEN})],
    )
    assert PhpIpamClient(config()).get_list("addresses/tags") == STATUSES


@responses.activate
def test_nothing_is_an_empty_list_not_an_error():
    responses.get(
        f"{API}/devices/",
        status=404,
        json={"code": 404, "success": False, "message": "No devices configured", "time": 0.01},
    )
    assert PhpIpamClient(config()).get_list("devices") == []


@responses.activate
@pytest.mark.parametrize(
    ("status", "body", "message"),
    [
        (401, {"code": 401, "success": False, "message": "Invalid token"}, "refused the token"),
        (403, {"code": 403, "success": False, "message": "Invalid app id"}, "refused the token"),
        (404, {"code": 404, "success": False, "message": "Invalid controller"}, "HTTP 404 from phpIPAM"),
        (500, None, "HTTP 500 from phpIPAM"),
    ],
)
def test_client_errors(status, body, message):
    responses.get(f"{API}/addresses/all/", status=status, json=body)
    with pytest.raises(PhpIpamError, match=message):
        PhpIpamClient(config()).get_list("addresses/all")


def test_verify_disabled():
    assert PhpIpamClient(config(verify_ssl=False)).session.verify is False


def ok(data_):
    return {"code": 200, "success": True, "data": data_, "time": 0.01}


@responses.activate
def test_fetch_records_reads_devices_and_locations_only_when_used():
    responses.get(f"{API}/addresses/all/", json=ok(ADDRESSES))
    responses.get(f"{API}/addresses/tags/", json=ok(STATUSES))
    responses.get(f"{API}/sections/", json=ok(SECTIONS))
    for section_id, subnets in SUBNETS.items():
        responses.get(f"{API}/sections/{section_id}/subnets/", json=ok(subnets))
    responses.get(f"{API}/devices/", json=ok(DEVICES))
    responses.get(f"{API}/tools/device_types/", json=ok(DEVICE_TYPES))
    responses.get(f"{API}/tools/locations/", json=ok(LOCATIONS))
    records, read = fetch_records(PhpIpamClient(config()))
    assert read == 6 and {r["device_name"] for r in records} == {"nas-01", ""}
    assert all(c.request.method == "GET" for c in responses.calls)

    responses.calls.reset()
    plain = [address("192.0.2.10", hostname="dc01.example.lan")]  # as on a phpIPAM without devices nor locations
    responses.replace(responses.GET, f"{API}/addresses/all/", json=ok(plain))
    records, read = fetch_records(PhpIpamClient(config()))
    assert (read, records[0]["hostname"]) == (1, "dc01.example.lan")
    called = {c.request.url.split("/api/assetsuite/")[1] for c in responses.calls}
    assert called == {"addresses/all/", "addresses/tags/", "sections/", "sections/1/subnets/", "sections/2/subnets/"}
