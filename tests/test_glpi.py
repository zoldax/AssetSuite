"""GLPI integration, with payloads shaped like GLPI 12.0.1 legacy API answers (values made up)."""

import pytest
import responses
from responses import matchers

from assetsuite.glpi import (
    DEFAULT_MAPPING,
    GlpiClient,
    GlpiData,
    GlpiError,
    build_records,
    fetch_data,
    fetch_records,
    import_rows,
    load_glpi_config,
)
from tests.test_progress import Recorder

GL = "https://glpi.example.lan"
API = f"{GL}/apirest.php"
USER_TOKEN = "UsErToKeN0123456789abcdefABCDEF0123456789"
APP_TOKEN = "ApPToKeN0123456789abcdefABCDEF0123456789"
SESSION = "s3ss10n"

COMPUTERS = [
    {
        "id": 1,
        "name": "srv-files",
        "entities_id": "Root entity > Customer A",
        "locations_id": "HQ > Server room",
        "computertypes_id": "Server",
        "manufacturers_id": "Example Inc.",
        "computermodels_id": "R740",
        "states_id": "In production",
        "users_id": "jdoe",
        "users_id_tech": "glpi",
        "contact": "admin",
        "serial": "SN-0001",
        "otherserial": "INV-0001",
        "uuid": "4c4c4544-0000-1000-8000-000000000001",
        "comment": "File server",
        "is_template": 0,
        "is_deleted": 0,
    },
    {"id": 2, "name": "ws-042", "entities_id": "Root entity > Customer B > Site 2", "computertypes_id": 0,
     "states_id": "In stock", "is_template": 0},
    {"id": 3, "name": "template-pc", "entities_id": "Root entity", "is_template": 1},
    {"id": 4, "name": "laptop-07", "entities_id": "Root entity", "states_id": 0, "is_template": 0},
]  # fmt: skip
PRINTERS = [{"id": 9, "name": "prn-floor2", "entities_id": "Root entity", "printertypes_id": "Laser", "is_template": 0}]
PORTS = [
    {"id": 10, "itemtype": "Computer", "items_id": 1, "name": "eno1", "mac": "00:00:5E:00:53:01",
     "instantiation_type": "NetworkPortEthernet"},
    {"id": 11, "itemtype": "Computer", "items_id": 1, "name": "docker0", "mac": "02:42:ac:11:00:01",
     "instantiation_type": "NetworkPortEthernet"},
    {"id": 12, "itemtype": "Computer", "items_id": 1, "name": "lo", "mac": "00:00:00:00:00:00",
     "instantiation_type": "NetworkPortLocal"},
    {"id": 13, "itemtype": "Computer", "items_id": 2, "name": "Ethernet", "mac": "00-00-5E-00-53-02",
     "instantiation_type": "NetworkPortEthernet"},
    {"id": 14, "itemtype": "Printer", "items_id": 9, "name": "eth0", "mac": "00:00:5e:00:53:09",
     "instantiation_type": "NetworkPortEthernet"},
]  # fmt: skip
NAMES = [
    {"id": 20, "itemtype": "NetworkPort", "items_id": 10, "name": "srv-files"},
    {"id": 21, "itemtype": "NetworkPort", "items_id": 11, "name": "docker0"},
    {"id": 22, "itemtype": "NetworkPort", "items_id": 12, "name": "lo"},
    {"id": 23, "itemtype": "NetworkPort", "items_id": 14, "name": "prn-floor2"},
]
ADDRESSES = [
    {"id": 30, "itemtype": "NetworkName", "items_id": 20, "mainitemtype": "Computer", "mainitems_id": 1,
     "name": "192.0.2.20", "version": 4, "is_deleted": 0},
    {"id": 31, "itemtype": "NetworkName", "items_id": 20, "mainitemtype": "Computer", "mainitems_id": 1,
     "name": "fe80::1", "version": 6, "is_deleted": 0},
    {"id": 32, "itemtype": "NetworkName", "items_id": 21, "mainitemtype": "Computer", "mainitems_id": 1,
     "name": "172.17.0.1", "version": 4, "is_deleted": 0},
    {"id": 33, "itemtype": "NetworkName", "items_id": 22, "mainitemtype": "Computer", "mainitems_id": 1,
     "name": "127.0.0.1", "version": 4, "is_deleted": 0},
    {"id": 34, "itemtype": "NetworkName", "items_id": 23, "mainitemtype": "Printer", "mainitems_id": 9,
     "name": "192.0.2.12", "version": 4, "is_deleted": 0},
    {"id": 35, "itemtype": "NetworkName", "items_id": 20, "mainitemtype": "Computer", "mainitems_id": 1,
     "name": "2001:db8::20", "version": 6, "is_deleted": 0},
]  # fmt: skip
GROUP_ITEMS = [
    {"id": 1, "itemtype": "Computer", "items_id": 1, "groups_id": 5, "type": 1},
    {"id": 2, "itemtype": "Computer", "items_id": 1, "groups_id": 6, "type": 2},
    {"id": 3, "itemtype": "Computer", "items_id": 1, "groups_id": 7, "type": 1},
]
GROUPS = [{"id": 5, "name": "Finance"}, {"id": 6, "name": "IT Ops"}, {"id": 7, "name": "Audit"}]
SYSTEMS = [
    {"id": 1, "itemtype": "Computer", "items_id": 1, "operatingsystems_id": 3, "operatingsystemversions_id": 4},
    {"id": 2, "itemtype": "Computer", "items_id": 2, "operatingsystems_id": 5, "operatingsystemversions_id": 6},
]
SYSTEM_NAMES = [{"id": 3, "name": "Ubuntu 24.04.5 LTS"}, {"id": 5, "name": "Windows 11"}]
SYSTEM_VERSIONS = [{"id": 4, "name": "24.04.5 LTS (Noble Numbat)"}, {"id": 6, "name": "23H2"}]


def config(**glpi):
    section = {"url": GL + "/", "user_token": USER_TOKEN, "app_token": APP_TOKEN, **glpi}
    return load_glpi_config({"glpi": section}, environ={})


def data(**changes):
    values = dict(
        items={"Computer": COMPUTERS, "Printer": PRINTERS},
        addresses=ADDRESSES,
        names=NAMES,
        ports=PORTS,
        groups=GROUP_ITEMS,
        group_names=GROUPS,
        systems=SYSTEMS,
        system_names=SYSTEM_NAMES,
        system_versions=SYSTEM_VERSIONS,
    )
    return GlpiData(**{**values, **changes})


# --- Configuration -----------------------------------------------------------


def test_config_defaults():
    cfg = config()
    assert (cfg.url, cfg.app_token, cfg.domain, cfg.overwrite, cfg.verify) == (
        GL,
        APP_TOKEN,
        "DEFAULT_DOMAIN",
        False,
        True,
    )
    assert cfg.itemtypes == ("Computer", "NetworkEquipment", "Printer", "Phone", "Peripheral")
    assert list(cfg.mapping) == list(DEFAULT_MAPPING) and "docker*" in cfg.ignore_ports
    assert USER_TOKEN not in repr(cfg) and APP_TOKEN not in repr(cfg)


def test_config_url_environment_and_no_app_token():
    assert config(url=f"{GL}/apirest.php").url == GL
    cfg = load_glpi_config({}, environ={"GLPI_URL": GL, "GLPI_USER_TOKEN": USER_TOKEN})
    assert (cfg.url, cfg.user_token, cfg.app_token) == (GL, USER_TOKEN, "")


@pytest.mark.parametrize(
    ("section", "message"),
    [
        (None, "GLPI is not configured"),
        ({"url": GL, "user_token": "CHANGE_ME"}, "'glpi.user_token' is not set"),
        ({"url": GL, "user_token": "t", "colour": "x"}, "Unknown glpi setting"),
        ({"url": GL, "user_token": "t", "itemtypes": ["Computer", "Monitor"]}, "Unknown glpi.itemtypes: Monitor"),
        ({"url": GL, "user_token": "t", "entity_domains": {"Customer A": 1}}, "must map GLPI entity names"),
        ({"url": GL, "user_token": "t", "states": [1]}, "must be a list of names"),
        ({"url": GL, "user_token": "t", "mapping": {"Given Name": "hostname"}}, "unknown field"),
        ({"url": GL, "user_token": "t", "ssl_cert_path": "/nope.pem"}, "does not exist"),
    ],
)
def test_config_errors(section, message):
    with pytest.raises(GlpiError, match=message):
        load_glpi_config({"glpi": section} if section else {}, environ={})


def test_domain_of_an_entity_is_its_most_precise_rule():
    cfg = config(
        domain="LAB", entity_domains={"Root entity > Customer B": "PROD2", "root entity > customer b > site 2": "PROD3"}
    )
    assert cfg.domain_of("Root entity > Customer B > Site 2") == "PROD3"  # case does not matter
    assert cfg.domain_of("Root entity > Customer B > Site 1") == "PROD2"
    assert cfg.domain_of("Root entity > Customer BB") == "LAB"  # whole names only
    assert cfg.domain_of("Root entity") == "LAB"


# --- Records and rows --------------------------------------------------------


def test_build_records():
    records, read, skipped = build_records(data(), config(entity_domains={"Root entity > Customer A": "PROD1"}))
    assert read == 4  # the template is not an asset
    assert skipped == [("Computer laptop-07", "no IP nor MAC address in GLPI")]
    by_name = {r["name"]: r for r in records}
    files = by_name["srv-files"]
    assert files["ips"] == ["192.0.2.20", "2001:db8::20"]  # no docker0, loopback nor link-local address
    assert files["macs"] == ["00:00:5e:00:53:01"]  # nor their MACs
    assert (files["group"], files["technical_group"], files["user"], files["technician"]) == (
        "Finance; Audit",
        "IT Ops",
        "jdoe",
        "glpi",
    )
    assert (files["os"], files["os_name"], files["os_version"]) == (
        "Ubuntu 24.04.5 LTS",  # the version is in the name already
        "Ubuntu 24.04.5 LTS",
        "24.04.5 LTS (Noble Numbat)",
    )
    assert (files["type"], files["model"], files["location"], files["inventory_number"]) == (
        "Server",
        "R740",
        "HQ > Server room",
        "INV-0001",
    )
    assert files["domain"] == "PROD1"
    ws = by_name["ws-042"]
    assert (ws["ips"], ws["macs"], ws["os"], ws["type"], ws["domain"]) == (
        [],
        ["00:00:5e:00:53:02"],
        "Windows 11 23H2",
        "",  # no type: the itemtype in the default mapping
        "DEFAULT_DOMAIN",
    )
    assert by_name["prn-floor2"]["itemtype"] == "Printer"


def test_states_and_ignored_ports_of_the_config():
    records, _, skipped = build_records(data(), config(states=["in production"], ignore_ports=[]))
    assert [r["name"] for r in records] == ["srv-files"]
    assert "172.17.0.1" in records[0]["ips"]  # docker0 kept when no port is ignored
    assert ("Computer ws-042", "status 'In stock' not in glpi.states") in skipped


def test_import_rows_with_default_mapping():
    records, _, _ = build_records(data(), config())
    header, rows = import_rows(records, config(), "LAB")
    assert header == ["ip_addresses", "mac_addresses", "dns_names", "domain_name", *DEFAULT_MAPPING]
    assert [r.values["dns_names"] for r in rows] == ["prn-floor2", "srv-files", "ws-042"]  # by IP, no IP last
    by_name = {r.values["dns_names"]: r.values for r in rows}
    files = by_name["srv-files"]
    assert (files["ip_addresses"], files["mac_addresses"], files["domain_name"]) == (
        "192.0.2.20;2001:db8::20",
        "00:00:5e:00:53:01",
        "LAB",  # the domain given replaces the default one
    )
    assert (files["Given Name"], files["Asset Type"], files["Business Owner"], files["Technical Owner"]) == (
        "srv-files",
        "Server",
        "Finance; Audit",
        "IT Ops",
    )
    assert (files["Location"], files["Technical Contact"], files["User Supplied OS"]) == (
        "HQ > Server room",
        "admin",
        "Ubuntu 24.04.5 LTS",
    )
    assert by_name["ws-042"]["Asset Type"] == "Computer" and by_name["ws-042"]["Business Owner"] == ""
    assert by_name["prn-floor2"]["Asset Type"] == "Laser"


# --- Client ------------------------------------------------------------------


def session_answers(page=None):
    responses.get(
        f"{API}/initSession",
        json={"session_token": SESSION},
        match=[matchers.header_matcher({"Authorization": f"user_token {USER_TOKEN}", "App-Token": APP_TOKEN})],
    )
    responses.get(f"{API}/killSession", json=True, match=[matchers.header_matcher({"Session-Token": SESSION})])


def page(items, start, total, itemtype="Computer"):
    end = start + len(items) - 1
    return {
        "json": items,
        "status": 206 if len(items) < total else 200,
        "headers": {"Content-Range": f"{start}-{end}/{total}", "Accept-Range": f"{itemtype} 5000"},
    }


@responses.activate
def test_session_pages_and_close(monkeypatch):
    monkeypatch.setattr("assetsuite.glpi.PAGE_SIZE", 2)
    session_answers()
    responses.get(
        f"{API}/Computer", match=[matchers.query_param_matcher({"range": "0-1"})], **page(COMPUTERS[:2], 0, 4)
    )
    responses.get(
        f"{API}/Computer", match=[matchers.query_param_matcher({"range": "2-3"})], **page(COMPUTERS[2:], 2, 4)
    )
    with GlpiClient(config()) as client:
        assert [c["id"] for c in client.get_all("Computer")] == [1, 2, 3, 4]
        assert client.session.headers["Session-Token"] == SESSION
    assert responses.calls[-1].request.url.endswith("/killSession")
    assert all(c.request.method == "GET" for c in responses.calls)


@responses.activate
def test_session_renewed_once_when_glpi_ended_it():
    session_answers()
    responses.get(f"{API}/Computer", status=401, json=["ERROR_SESSION_TOKEN_INVALID", "session expired"])
    responses.get(f"{API}/Computer", **page(COMPUTERS[:1], 0, 1))
    with GlpiClient(config()) as client:
        assert len(client.get_all("Computer")) == 1
    assert [c.request.url.split("/apirest.php/")[1].split("?")[0] for c in responses.calls].count("initSession") == 2


@responses.activate
@pytest.mark.parametrize(
    ("error", "message"),
    [
        ("ERROR_NOT_ALLOWED_IP", "not in the IP range of a GLPI API client"),
        ("ERROR_WRONG_APP_TOKEN_PARAMETER", "check glpi.app_token"),
        ("ERROR_GLPI_LOGIN_USER_TOKEN", "refused the user token"),
    ],
)
def test_session_errors(error, message):
    responses.get(f"{API}/initSession", status=400, json=[error, "GLPI message"])
    with pytest.raises(GlpiError, match=message):
        with GlpiClient(config()):
            pass


@responses.activate
def test_session_closed_after_an_error():
    session_answers()
    responses.get(f"{API}/Computer", status=500, json=["ERROR", "boom"])
    with pytest.raises(GlpiError, match="HTTP 500"):
        with GlpiClient(config()) as client:
            client.get_all("Computer")
    assert responses.calls[-1].request.url.endswith("/killSession")


@responses.activate
def test_range_beyond_the_total_is_an_empty_list():
    session_answers()
    responses.get(f"{API}/Phone", status=400, json=["ERROR_RANGE_EXCEED_TOTAL", "Provided range exceed total count"])
    with GlpiClient(config()) as client:
        assert client.get_all("Phone") == []


def test_verify_disabled():
    assert GlpiClient(config(verify_ssl=False)).session.verify is False


@responses.activate
def test_fetch_reads_in_bulk_and_leaves_aside_a_type_without_right():
    session_answers()
    responses.get(f"{API}/Computer", **page(COMPUTERS, 0, 4))
    responses.get(f"{API}/Printer", **page(PRINTERS, 0, 1, "Printer"))
    responses.get(f"{API}/Phone", status=401, json=["ERROR_RIGHT_MISSING", "You don't have permission"])
    for itemtype, items in (
        ("IPAddress", ADDRESSES),
        ("NetworkName", NAMES),
        ("NetworkPort", PORTS),
        ("Group_Item", GROUP_ITEMS),
        ("Group", GROUPS),
        ("Item_OperatingSystem", SYSTEMS),
        ("OperatingSystem", SYSTEM_NAMES),
        ("OperatingSystemVersion", SYSTEM_VERSIONS),
    ):
        responses.get(f"{API}/{itemtype}", **page(items, 0, len(items), itemtype))
    cfg = config(itemtypes=["Computer", "Printer", "Phone", "NetworkEquipment"])
    responses.get(f"{API}/NetworkEquipment", json=[])
    progress = Recorder()
    records, read, skipped = fetch_records(cfg, progress=progress)
    assert read == 4 and {r["name"] for r in records} == {"srv-files", "ws-042", "prn-floor2"}
    assert progress.phases() == [
        "GLPI computers",
        "GLPI printers",
        "GLPI phones",
        "GLPI network equipment",
        "GLPI network addresses",
        "GLPI groups and operating systems",
    ]
    # The phases of several lists count the lists, not their items.
    tail = progress.events[[e[:2] for e in progress.events].index(("phase", "GLPI network addresses")) :]
    assert tail[0] == ("phase", "GLPI network addresses", 3) and ("total", 6) not in tail
    assert [e for e in tail if e[0] == "advance"] == [("advance", 1)] * 8
    assert ("Phones", "the GLPI user cannot read Phone") in skipped
    expanded = [c.request.url for c in responses.calls if "expand_dropdowns" in c.request.url]
    assert {u.split("/apirest.php/")[1].split("?")[0] for u in expanded} == {
        "Computer",
        "Printer",
        "Phone",
        "NetworkEquipment",
    }
    assert all(c.request.method == "GET" for c in responses.calls)
    assert responses.calls[-1].request.url.endswith("/killSession")


@responses.activate
def test_fetch_skips_groups_and_systems_lists_when_unused():
    session_answers()
    responses.get(f"{API}/Computer", **page(COMPUTERS[:1], 0, 1))
    for itemtype in ("IPAddress", "NetworkName", "NetworkPort", "Group_Item", "Item_OperatingSystem"):
        responses.get(f"{API}/{itemtype}", status=400, json=["ERROR_RANGE_EXCEED_TOTAL", "empty"])
    with GlpiClient(config(itemtypes=["Computer"])) as client:
        found = fetch_data(client)
    assert found.groups == [] and found.group_names == [] and found.system_names == []
    called = {c.request.url.split("/apirest.php/")[1].split("?")[0] for c in responses.calls}
    assert "Group" not in called and "OperatingSystem" not in called
