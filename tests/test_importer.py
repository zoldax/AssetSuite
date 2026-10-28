import ipaddress
import pathlib

import pytest

from assetsuite.importer import (
    Creation,
    ImportFileError,
    ImportRow,
    Planner,
    creation_payload,
    read_import_file,
    unescape,
)
from tests.fixtures import ASSETS, DOMAINS, PROPERTIES

CATALOG = PROPERTIES + [{"id": 1003, "name": "Weight", "data_type": "NUMERIC"}]
CATALOG_BY_NAME = {p["name"]: p for p in CATALOG}
DOMAIN_NAMES = {0: "DEFAULT_DOMAIN", 1: "PROD1", 2: "PROD2"}


def planner(**kwargs):
    domains = [{**d, "name": DOMAIN_NAMES[d["id"]]} for d in DOMAINS]
    return Planner(ASSETS, CATALOG, domains, **kwargs)


def rows(*dicts):
    return [ImportRow(line, values) for line, values in enumerate(dicts, start=2)]


def plan_of(header, *values, **kwargs):
    return planner(**kwargs).plan(header, rows(*[dict(zip(header, v)) for v in values]))


# --- Reading -----------------------------------------------------------------


def test_read_semicolon_file_with_bom(tmp_path):
    path = tmp_path / "in.csv"
    path.write_text("﻿id;Business Owner\n2723;IT\n;\n", encoding="utf-8")
    header, data = read_import_file(str(path))
    assert header == ["id", "Business Owner"]
    assert [(r.line, r.values) for r in data] == [(2, {"id": "2723", "Business Owner": "IT"})]


def test_read_unescapes_export_formulas(tmp_path):
    path = tmp_path / "in.csv"
    path.write_text("id,Given Name\n1,'=SUM(A1)\n2,'quoted\n", encoding="utf-8")
    _, data = read_import_file(str(path))
    assert [r.values["Given Name"] for r in data] == ["=SUM(A1)", "'quoted"]


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("", "no header"),
        ("id,id\n1,2\n", "Duplicate column"),
        ("id,Given Name\n1,a,b\n", "more fields than the header"),
    ],
)
def test_read_errors(tmp_path, content, message):
    path = tmp_path / "in.csv"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ImportFileError, match=message):
        read_import_file(str(path))


def test_unescape():
    assert unescape("'-x") == "-x"
    assert unescape("'abc") == "'abc"
    assert unescape("'") == "'"


# --- Columns -----------------------------------------------------------------


def test_unknown_column_rejected():
    with pytest.raises(ImportFileError, match="Unknown column.*business owner"):
        planner().plan(["id", "business owner"], [])


def test_match_column_required():
    with pytest.raises(ImportFileError, match="at least one of these columns"):
        planner().plan(["Business Owner"], [])


def test_export_round_trip_is_unchanged():
    header = ["id", "domain_name", "ip_addresses", "users", "last_seen", "Business Owner", "Unified Name"]
    plan = plan_of(header, ["2723", "DEFAULT_DOMAIN", "192.0.2.143", "admin", "2026", "SOC", "ws01.example.lan"])
    assert plan.unchanged == [(2, 2723)]
    assert not plan.has_writes and not plan.errors


# --- Matching and updates ----------------------------------------------------


def test_update_by_id():
    plan = plan_of(["id", "Business Owner", "Given Name"], ["2723", "IT", ""])
    update = plan.updates[2723]
    assert list(update.changes) == ["Business Owner"]  # empty cell = unchanged
    change = update.changes["Business Owner"]
    assert (change.type_id, change.old, change.new) == (1005, "SOC", "IT")


@pytest.mark.parametrize(
    ("column", "value", "asset_id"),
    [
        ("ip_address", "10.2.0.5", 3001),
        ("mac_address", "00-14-22-01-23-44", 3001),
        ("dns_names", "WS01.example.lan", 2723),
        ("netbios_names", "srv-db01", 3001),
    ],
)
def test_match_by_keys(column, value, asset_id):
    plan = plan_of([column, "Business Owner"], [value, "NEW"])
    assert list(plan.updates) == [asset_id]


def test_netbios_placeholder_is_not_a_key():
    plan = plan_of(["netbios_names", "Business Owner"], ["-", "X"])
    assert not plan.updates and len(plan.not_found) == 1


def test_domain_restricts_matching():
    plan = plan_of(["ip_address", "domain_name", "Business Owner"], ["10.2.0.5", "PROD2", "X"])
    assert not plan.updates and len(plan.not_found) == 1


def test_ambiguous_match():
    plan = plan_of(["ip_addresses", "Business Owner"], ["192.0.2.143;10.2.0.5", "X"])
    assert "matches several assets (2723, 3001)" in plan.errors[0].message


@pytest.mark.parametrize(
    ("values", "message"),
    [
        (["99", "", "X", ""], "asset id 99 does not exist"),
        (["abc", "", "X", ""], "invalid asset id"),
        (["2723", "PROD1", "X", ""], "is in domain 0, not 1"),
        (["2723", "", "", "heavy"], "'Weight' must be a number"),
        (["2723", "NOPE", "X", ""], "unknown domain_name"),
    ],
)
def test_row_errors(values, message):
    plan = plan_of(["id", "domain_name", "Business Owner", "Weight"], values)
    assert message in plan.errors[0].message


def test_numeric_comparison():
    asset = {**ASSETS[0], "properties": ASSETS[0]["properties"] + [{"name": "Weight", "type_id": 1003, "value": "5"}]}
    domains = [{**d, "name": DOMAIN_NAMES[d["id"]]} for d in DOMAINS]
    plan = Planner([asset], CATALOG, domains).plan(["id", "Weight"], rows({"id": "2723", "Weight": "5.0"}))
    assert plan.unchanged == [(2, 2723)]


def test_per_ip_rows_of_same_asset_merge():
    header = ["id", "ip_address", "Given Name"]
    plan = plan_of(header, ["3001", "10.1.1.24", "DB"], ["3001", "10.2.0.5", "DB"])
    assert plan.updates[3001].lines == [2, 3]
    assert not plan.errors


def test_conflicting_values_for_same_asset():
    header = ["id", "ip_address", "Given Name"]
    plan = plan_of(header, ["3001", "10.1.1.24", "DB"], ["3001", "10.2.0.5", "OTHER"])
    assert plan.errors[0].line == 3
    assert "set to 'DB' on line 2" in plan.errors[0].message


# --- Creations ---------------------------------------------------------------

CREATE_HEADER = ["ip_addresses", "mac_address", "dns_names", "netbios_names", "domain_name", "Business Owner"]


def test_not_found_without_create():
    plan = plan_of(
        CREATE_HEADER, ["198.51.100.7", "", "", "", "PROD1", "X"], create_blocked_reason="use --allow-create"
    )
    assert plan.not_found[0][1] == "use --allow-create"
    assert not plan.creations


def test_creation_planned():
    plan = plan_of(
        CREATE_HEADER,
        ["198.51.100.7;2001:db8::7", "02-00-00-00-00-07", "new.example.lan", "NEW", "PROD1", "IT"],
        can_create=True,
    )
    [creation] = plan.creations
    assert (creation.domain_id, creation.ips, creation.mac) == (1, ["198.51.100.7", "2001:db8::7"], "02:00:00:00:00:07")
    assert creation.properties == {"Business Owner": "IT"}


@pytest.mark.parametrize(
    ("values", "message"),
    [
        (["", "", "new.example.lan", "", "PROD1", ""], "an IP address is required"),
        (["198.51.100.1;198.51.100.2;198.51.100.3", "", "", "", "PROD1", ""], "at most 2 IPs"),
        (["198.51.100.300", "", "", "", "PROD1", ""], "invalid IP"),
        (["fe80::1", "", "", "", "PROD1", ""], "link-local"),
        (["198.51.100.7", "zz:00", "", "", "PROD1", ""], "invalid MAC"),
        (["198.51.100.7", "", "a.lan;b.lan", "", "PROD1", ""], "one DNS name"),
        (["198.51.100.7", "", "", "", "", ""], "domain unknown"),
    ],
)
def test_creation_errors(values, message):
    plan = plan_of(CREATE_HEADER, values, can_create=True)
    assert message in plan.errors[0].message


def test_default_domain_option_for_creation():
    plan = plan_of(CREATE_HEADER, ["198.51.100.7", "", "", "", "", ""], can_create=True, default_domain_id=2)
    assert plan.creations[0].domain_id == 2


def test_duplicate_creation_in_file():
    plan = plan_of(
        CREATE_HEADER,
        ["198.51.100.7", "", "", "", "PROD1", ""],
        ["198.51.100.7", "", "", "", "PROD1", ""],
        can_create=True,
    )
    assert len(plan.creations) == 1
    assert "already created by line 2" in plan.errors[0].message


# --- Payloads ----------------------------------------------------------------

CREATION = Creation(
    line=2,
    domain_id=1,
    ips=["198.51.100.7"],
    mac="02:00:00:00:00:07",
    dns="new.example.lan",
    netbios=None,
    properties={"Business Owner": "IT"},
)


def test_single_payload_uses_names():
    assert creation_payload(CREATION, CATALOG_BY_NAME, DOMAIN_NAMES, bulk=False) == {
        "interfaces": [{"ip_addresses": [{"value": "198.51.100.7"}], "mac_address": "02:00:00:00:00:07"}],
        "hostnames": [{"name": "new.example.lan", "type": "DNS"}],
        "domain_name": "PROD1",
        "properties": [{"name": "Business Owner", "value": "IT"}],
    }


def test_single_payload_default_domain_is_implicit():
    creation = Creation(2, 0, ["198.51.100.7"], None, None, None, {})
    assert creation_payload(creation, CATALOG_BY_NAME, DOMAIN_NAMES, bulk=False) == {
        "interfaces": [{"ip_addresses": [{"value": "198.51.100.7"}]}]
    }


def test_bulk_payload_uses_ids():
    payload = creation_payload(CREATION, CATALOG_BY_NAME, DOMAIN_NAMES, bulk=True)
    assert payload["domain_id"] == 1
    assert payload["properties"] == [{"type_id": 1005, "value": "IT"}]
    assert "domain_name" not in payload


# --- Tie-break by hostname, fill-empty-only ----------------------------------


def shared_ip_assets():
    import copy

    first = copy.deepcopy(ASSETS[0])  # 2723, ws01.example.lan, 192.0.2.143
    second = copy.deepcopy(ASSETS[0])
    second["id"] = 9001
    second["hostnames"] = [{"name": "ai-lab.example.lan", "type": "DNS"}]
    return [first, second]


def test_shared_ip_resolved_by_dns_name():
    domains = [{**d, "name": DOMAIN_NAMES[d["id"]]} for d in DOMAINS]
    planner = Planner(shared_ip_assets(), CATALOG, domains)
    plan = planner.plan(
        ["ip_address", "dns_names", "Business Owner"],
        rows({"ip_address": "192.0.2.143", "dns_names": "AI-LAB.example.lan", "Business Owner": "X"}),
    )
    assert list(plan.updates) == [9001] and not plan.errors


def test_shared_ip_resolved_by_short_name():
    domains = [{**d, "name": DOMAIN_NAMES[d["id"]]} for d in DOMAINS]
    planner = Planner(shared_ip_assets(), CATALOG, domains)
    plan = planner.plan(
        ["ip_address", "netbios_names", "Business Owner"],
        rows({"ip_address": "192.0.2.143", "netbios_names": "AI-LAB", "Business Owner": "X"}),
    )
    assert list(plan.updates) == [9001]


def test_shared_ip_without_name_stays_ambiguous():
    domains = [{**d, "name": DOMAIN_NAMES[d["id"]]} for d in DOMAINS]
    planner = Planner(shared_ip_assets(), CATALOG, domains)
    plan = planner.plan(["ip_address", "Business Owner"], rows({"ip_address": "192.0.2.143", "Business Owner": "X"}))
    assert "matches several assets (2723, 9001)" in plan.errors[0].message


def test_fill_empty_only():
    plan = plan_of(["id", "Business Owner", "Given Name"], ["2723", "IT", "WS01"], fill_empty_only=True)
    # Business Owner is "SOC" in QRadar: kept. Given Name is empty: set.
    assert list(plan.updates[2723].changes) == ["Given Name"]


def test_tie_broken_by_mac_first():
    import copy

    assets = shared_ip_assets()
    assets[1]["interfaces"] = copy.deepcopy(assets[1]["interfaces"])
    assets[1]["interfaces"][0]["mac_address"] = "02:00:00:00:00:99"
    domains = [{**d, "name": DOMAIN_NAMES[d["id"]]} for d in DOMAINS]
    header = ["ip_address", "mac_address", "dns_names", "Business Owner"]
    # The row's name points to 2723 but its MAC to 9001: the MAC wins.
    values = {
        "ip_address": "192.0.2.143",
        "mac_address": "02-00-00-00-00-99",
        "dns_names": "ws01.example.lan",
        "Business Owner": "X",
    }
    plan = Planner(assets, CATALOG, domains).plan(header, rows(values))
    assert list(plan.updates) == [9001]


def test_tie_broken_by_first_name_in_row_order():
    domains = [{**d, "name": DOMAIN_NAMES[d["id"]]} for d in DOMAINS]
    planner = Planner(shared_ip_assets(), CATALOG, domains)
    # Both names match one asset each: the first one decides.
    values = {"ip_address": "192.0.2.143", "dns_names": "ai-lab.example.lan;ws01.example.lan", "Business Owner": "X"}
    plan = planner.plan(["ip_address", "dns_names", "Business Owner"], rows(values))
    assert list(plan.updates) == [9001]


def test_asset_without_ip_is_skipped_not_updated():
    # HOSTNAME_ONLY (2757) has no interface: matched by DNS name, QRadar would answer 422.
    plan = plan_of(["dns_names", "Business Owner"], ["gitlab", "IT"])
    assert not plan.updates and not plan.errors
    assert plan.skipped == [(2, 2757, "the asset has no IP address: QRadar refuses property updates on it (HTTP 422)")]


def test_asset_without_ip_and_nothing_to_change_is_unchanged():
    plan = plan_of(["dns_names", "Business Owner"], ["gitlab", ""])
    assert plan.unchanged == [(2, 2757)] and not plan.skipped


# --- Template ----------------------------------------------------------------

TEMPLATE = pathlib.Path(__file__).resolve().parent.parent / "templates" / "assets-import-template.csv"
TEMPLATE_CATALOG = [
    {"id": 1000 + i, "name": name}
    for i, name in enumerate(
        ("Given Name", "Description", "Location", "Asset Type", "Business Owner", "User Supplied OS")
    )
]


def test_template_plans_without_errors():
    header, template_rows = read_import_file(str(TEMPLATE))
    domains = [{**d, "name": DOMAIN_NAMES[d["id"]]} for d in DOMAINS]
    plan = Planner([], TEMPLATE_CATALOG, domains, can_create=True).plan(header, template_rows)
    assert not plan.errors and not plan.not_found
    by_ip = {c.ips[0]: c for c in plan.creations}
    assert sorted(by_ip) == ["192.0.2.10", "192.0.2.20", "192.0.2.30", "192.0.2.40"]
    assert by_ip["192.0.2.20"].ips == ["192.0.2.20", "192.0.2.21"]
    assert (by_ip["192.0.2.10"].mac, by_ip["192.0.2.10"].dns) == ("00:00:5e:00:53:01", "srv01.example.lan")
    assert by_ip["192.0.2.30"].properties["Description"] == "Printer, floor 1"
    assert by_ip["192.0.2.40"].properties == {"Business Owner": "Security team"}  # empty cells left unchanged


def test_template_only_uses_documentation_values():
    """The template stays generic: documentation IPs (RFC 5737), MACs (RFC 7042) and example.lan names."""
    _, template_rows = read_import_file(str(TEMPLATE))
    documentation = ipaddress.ip_network("192.0.2.0/24")
    for row in template_rows:
        assert all(ipaddress.ip_address(ip) in documentation for ip in row.values["ip_addresses"].split(";"))
        mac = row.values["mac_addresses"]
        assert not mac or mac.startswith("00:00:5e:00:53:")
        assert all(name.endswith(".example.lan") for name in row.values["dns_names"].split(";") if name)
    assert "zoldax" not in TEMPLATE.read_text(encoding="utf-8")
