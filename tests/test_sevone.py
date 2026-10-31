"""SevOne integration, with payloads shaped like SevOne NPM 7.2 answers (values anonymized)."""

import pytest
import responses
from responses import matchers

from assetsuite.sevone import (
    DEFAULT_MAPPING,
    SevOneClient,
    SevOneError,
    build_record,
    device_types,
    fetch_records,
    flatten_metadata,
    import_rows,
    load_sevone_config,
    skip_reason,
)

SO = "https://sevone.example.lan"
SO_TOKEN = "eyJ1dWlkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwIn0="


def device(id, name, ip, description="", **extra):
    return {
        "id": id,
        "name": name,
        "alternateName": "",
        "description": description,
        "ipAddress": ip,
        "isDeleted": False,
        "isNew": False,
        "isQueuedForDeletion": False,
        **extra,
    }


DEVICES = [
    device(1, "SevOne", "127.0.0.1"),
    device(2, "nas-01", "192.0.2.72", "Synology NAS"),
    device(3, "fw-01", "192.0.2.254", "Gateway"),
    device(4, "printer-01", "192.0.2.12"),
    device(5, "old-switch", "192.0.2.53", isDeleted=True),
]


def attribute(*values):
    values = [{"id": i, "value": v} for i, v in enumerate(values)]
    return {"attributeType": "string", "attributeId": 1, "values": values}


METADATA = {
    2: {
        "{system}.sysName": attribute("nas-01.example.lan"),
        "{system}.sysContact": attribute("IT Operations"),
        "{system}.sysLocation": attribute("Unknown"),
        "Device.Class": attribute("Host"),
        "Device.OS Family": attribute("Linux"),
        "Device.OS Version": attribute("5.10.55"),
        "Device.Description": attribute("Linux running netSnmp"),
        "Device.Main Website": {
            "attributeType": "url",
            "attributeId": 9,
            "values": [{"id": 1, "label": "Unknown", "url": "http://Unknown", "latitude": "", "longitude": ""}],
        },
        "Device.Serial Number": attribute("SN-0001"),
    },
    3: {
        "{system}.sysName": attribute("fw-01"),
        "{system}.sysLocation": attribute("Server room"),
        "Location.Site Name": attribute("HQ"),
        "Device.Class": attribute("Host"),
    },
    4: {"{system}.sysLocation": attribute("Office"), "Device.Class": attribute("Printer")},
}


def types(*leaves):
    """deviceTypeDefinition of a device in the given leaf types (paths under All Device Types)."""
    nodes = {"All Device Types": {"name": "All Device Types", "parentId": "1", "id": "42"}}
    for leaf in ("Generic/Linux (Net-SNMP)", *leaves):
        parent = "All Device Types"
        for i, name in enumerate(leaf.split("/")):
            path = "/".join(leaf.split("/")[: i + 1])
            nodes.setdefault(path, {"name": name, "parentId": nodes[parent]["id"], "id": str(100 + len(nodes))})
            parent = path
    return {"deviceTypeDefinition": list(nodes.values())}


TYPES = {2: types("Storage/Synology"), 3: types("Firewall"), 4: types()}


def config(**sevone):
    return load_sevone_config({"sevone": {"url": SO + "/", "token": SO_TOKEN, **sevone}}, environ={})


def mock_sevone(devices=DEVICES, pages=1):
    size = -(-len(devices) // pages)
    for page in range(pages):
        responses.get(
            f"{SO}/api/v2/devices",
            json={
                "content": devices[page * size : (page + 1) * size],
                "totalElements": len(devices),
                "totalPages": pages,
                "pageNumber": page,
            },
            match=[matchers.query_param_matcher({"page": str(page), "size": "200"})],
        )
    for device_id, metadata in METADATA.items():
        responses.get(f"{SO}/api/v2/devices/{device_id}/metadata", json=metadata)
        responses.get(f"{SO}/api/v3/devicetypes/members/{device_id}", json=TYPES[device_id])


# --- Configuration -----------------------------------------------------------


def test_config_defaults():
    cfg = config()
    assert cfg.url == SO and cfg.verify is True and cfg.domain == "DEFAULT_DOMAIN"
    assert cfg.device_groups == () and not cfg.overwrite
    assert list(cfg.mapping) == list(DEFAULT_MAPPING)
    assert SO_TOKEN not in repr(cfg)


def test_config_from_environment():
    cfg = load_sevone_config({}, environ={"SEVONE_URL": SO, "SEVONE_TOKEN": "t"})
    assert (cfg.url, cfg.token) == (SO, "t")


@pytest.mark.parametrize(
    ("section", "message"),
    [
        ({}, "SevOne is not configured"),
        ({"url": SO}, "'sevone.token' is not set"),
        ({"url": SO, "token": "CHANGE_ME"}, "'sevone.token' is not set"),
        ({"url": SO, "token": "t", "groups": []}, "Unknown sevone setting"),
        ({"url": SO, "token": "t", "overwrite": "yes"}, "must be true or false"),
        ({"url": SO, "token": "t", "device_groups": {"a": 1}}, "must be a list"),
        ({"url": SO, "token": "t", "mapping": {"Given Name": "hostname"}}, "unknown field"),
        ({"url": SO, "token": "t", "timeout": "soon"}, "must be a number"),
    ],
)
def test_config_errors(section, message):
    with pytest.raises(SevOneError, match=message):
        load_sevone_config({"sevone": section}, environ={})


def test_metadata_fields_in_mapping():
    cfg = config(mapping={"Given Name": "sys_name", "Description": {"join": ["vendor", "md:Device.Serial Number"]}})
    assert cfg.mapping["Given Name"] == {"first": ["sys_name"]}
    assert cfg.mapping["Description"]["join"] == ["vendor", "md:Device.Serial Number"]


# --- Records -----------------------------------------------------------------


def test_flatten_metadata_drops_unknown_values():
    flat = flatten_metadata(METADATA[2])
    assert flat["{system}.sysName"] == "nas-01.example.lan"
    assert "{system}.sysLocation" not in flat and "Device.Main Website" not in flat
    assert flatten_metadata({"A.b": attribute("x", "y", "x")}) == {"A.b": "x; y"}


def test_device_types_without_generic_branch():
    assert device_types(TYPES[2]["deviceTypeDefinition"]) == ["Storage/Synology"]
    assert device_types(types("Switch", "Firewall")["deviceTypeDefinition"]) == ["Firewall", "Switch"]
    assert device_types(TYPES[4]["deviceTypeDefinition"]) == []


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({}, ""),
        ({"ipAddress": "127.0.0.1"}, "polled on 127.0.0.1"),
        ({"ipAddress": "::1"}, "polled on ::1"),
        ({"ipAddress": ""}, "no valid IP address"),
        ({"isDeleted": True}, "deleted in SevOne"),
        ({"isQueuedForDeletion": True}, "deleted in SevOne"),
    ],
)
def test_skip_reason(changes, reason):
    assert skip_reason({**device(2, "nas-01", "192.0.2.72"), **changes}).startswith(reason)


def test_build_record():
    record = build_record(DEVICES[1], flatten_metadata(METADATA[2]), ["Storage/Synology"])
    assert (record["ip"], record["name"], record["description"]) == ("192.0.2.72", "nas-01", "Synology NAS")
    assert record["dns_name"] == "nas-01.example.lan"  # fully qualified sysName
    assert (record["device_type"], record["device_types"]) == ("Storage", "Storage/Synology")
    assert record["os"] == "Linux 5.10.55"
    assert record["sys_location"] == ""  # "Unknown"
    assert record["md:Device.Serial Number"] == "SN-0001"
    short = build_record(DEVICES[2], flatten_metadata(METADATA[3]), ["Firewall"])
    assert short["dns_name"] == ""  # a short sysName is not used as DNS name


def test_import_rows_with_default_mapping():
    records = [
        build_record(DEVICES[i], flatten_metadata(METADATA[d]), device_types(TYPES[d]["deviceTypeDefinition"]))
        for i, d in ((1, 2), (2, 3), (3, 4))
    ]
    header, rows = import_rows(records, config(), "PROD1")
    assert header == ["ip_address", "dns_names", "domain_name", *DEFAULT_MAPPING]
    by_ip = {r.values["ip_address"]: r.values for r in rows}
    nas, fw, printer = by_ip["192.0.2.72"], by_ip["192.0.2.254"], by_ip["192.0.2.12"]
    assert (nas["Asset Type"], nas["Technical Contact"]) == ("Storage", "IT Operations")
    assert nas["User Supplied OS"] == "Linux 5.10.55"
    assert nas["Location"] == "" and nas["domain_name"] == "PROD1"
    assert (fw["Location"], fw["Asset Type"], fw["Description"]) == ("HQ", "Firewall", "Gateway")
    assert (printer["Location"], printer["Asset Type"]) == ("Office", "Printer")  # sysLocation, Device.Class
    assert [r.values["ip_address"] for r in rows] == ["192.0.2.12", "192.0.2.72", "192.0.2.254"]


# --- Client ------------------------------------------------------------------


@responses.activate
def test_fetch_records_pages_and_skips():
    mock_sevone(pages=2)
    result = fetch_records(SevOneClient(config()))
    assert result.total == 5
    assert sorted(r["name"] for r in result.records) == ["fw-01", "nas-01", "printer-01"]
    assert [name for name, _ in result.skipped] == ["SevOne", "old-switch"]
    assert all(c.request.headers["X-AUTH-TOKEN"] == SO_TOKEN for c in responses.calls)
    assert all(c.request.method == "GET" for c in responses.calls)


@responses.activate
def test_fetch_records_device_groups():
    mock_sevone()
    responses.get(
        f"{SO}/api/v2/devicegroups",
        json={
            "content": [
                {"id": 2, "name": "All Device Groups", "parentId": None, "devices": [1, 2, 3, 4, 5]},
                {"id": 192, "name": "NAS Devices", "parentId": 2, "devices": [{"id": 2}]},
                {"id": 193, "name": "Security", "parentId": 2, "devices": [3]},
            ],
            "totalPages": 1,
        },
        match=[matchers.query_param_matcher({"includeMembers": "true", "page": "0", "size": "200"})],
    )
    records = fetch_records(SevOneClient(config(device_groups=["NAS Devices", "All Device Groups/Security"]))).records
    assert sorted(r["name"] for r in records) == ["fw-01", "nas-01"]
    with pytest.raises(SevOneError, match="Unknown SevOne device group"):
        fetch_records(SevOneClient(config(device_groups=["Nope"])))


@responses.activate
def test_client_errors():
    responses.get(f"{SO}/api/v2/devices", status=401, json={"title": "Unauthorized", "status": 401})
    with pytest.raises(SevOneError, match="refused the API key"):
        fetch_records(SevOneClient(config()))
    responses.replace(responses.GET, f"{SO}/api/v2/devices", status=500, json={"title": "Server Error"})
    with pytest.raises(SevOneError, match="HTTP 500 from SevOne.*Server Error"):
        fetch_records(SevOneClient(config()))
    responses.replace(responses.GET, f"{SO}/api/v2/devices", json=[])
    with pytest.raises(SevOneError, match="Unexpected answer"):
        fetch_records(SevOneClient(config()))


def test_verify_disabled():
    assert SevOneClient(config(verify_ssl=False)).session.verify is False


# --- Service account ---------------------------------------------------------


def account(**extra):
    return load_sevone_config(
        {"sevone": {"url": SO, "username": "svc-assetsuite", "password": "s3cret", **extra}}, environ={}
    )


def test_service_account_config():
    cfg = account()
    assert (cfg.token, cfg.username, cfg.password) == ("", "svc-assetsuite", "s3cret")
    assert "s3cret" not in repr(cfg)
    from_env = load_sevone_config({"sevone": {"url": SO}}, environ={"SEVONE_USERNAME": "svc", "SEVONE_PASSWORD": "pw"})
    assert (from_env.username, from_env.password) == ("svc", "pw")
    with pytest.raises(SevOneError, match="go together"):
        load_sevone_config({"sevone": {"url": SO, "username": "svc"}}, environ={})
    with pytest.raises(SevOneError, match="or a service account"):
        load_sevone_config({"sevone": {"url": SO, "token": "CHANGE_ME"}}, environ={})


@responses.activate
def test_service_account_signs_in_reads_and_signs_out():
    from assetsuite.service import sevone_source

    signin = responses.post(
        f"{SO}/api/v2/authentication/signin",
        json={"token": "session-1"},
        match=[matchers.json_params_matcher({"name": "svc-assetsuite", "password": "s3cret"})],
    )
    responses.get(
        f"{SO}/api/v2/devices",
        json={"content": [], "totalElements": 0, "totalPages": 1},
        match=[matchers.header_matcher({"X-AUTH-TOKEN": "session-1"})],
    )
    signout = responses.delete(
        f"{SO}/api/v2/authentication/signout", match=[matchers.header_matcher({"X-AUTH-TOKEN": "session-1"})]
    )
    source = sevone_source(account())
    assert source.read == 0
    assert signin.call_count == 1 and signout.call_count == 1


@responses.activate
def test_service_account_session_renewed_once():
    responses.post(f"{SO}/api/v2/authentication/signin", json={"token": "session-1"})
    responses.post(f"{SO}/api/v2/authentication/signin", json={"token": "session-2"})
    responses.get(
        f"{SO}/api/v3/health/version", status=401, match=[matchers.header_matcher({"X-AUTH-TOKEN": "session-1"})]
    )
    responses.get(
        f"{SO}/api/v3/health/version",
        json={"version": "7.2.1"},
        match=[matchers.header_matcher({"X-AUTH-TOKEN": "session-2"})],
    )
    client = SevOneClient(account())
    assert client.get("api/v3/health/version") == {"version": "7.2.1"}


@responses.activate
def test_service_account_errors():
    responses.post(f"{SO}/api/v2/authentication/signin", status=401, json={"title": "Unauthorized"})
    with pytest.raises(SevOneError, match="refused the service account .HTTP 401.: check sevone.username"):
        SevOneClient(account()).get("api/v2/devices")
    responses.replace(responses.POST, f"{SO}/api/v2/authentication/signin", json={"token": "session-1"})
    responses.get(f"{SO}/api/v2/devices", status=403, json={"title": "Forbidden"})
    with pytest.raises(SevOneError, match="refused the service account session .HTTP 403.: check the rights"):
        SevOneClient(account()).get("api/v2/devices")


def test_api_key_client_has_nothing_to_close():
    client = SevOneClient(config())
    assert not client.uses_account
    client.close()  # no request
