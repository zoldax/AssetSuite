import json
import re

import pytest
import responses

from assetsuite.cli import EXIT_CONFIG, EXIT_ERROR, EXIT_OK, main
from tests.conftest import BASE, HOST, TOKEN


@pytest.fixture
def config_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for name in ("QRADAR_HOST", "QRADAR_SEC_TOKEN", "QRADAR_API_VERSION"):
        monkeypatch.delenv(name, raising=False)
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"host": HOST, "token": TOKEN, "log_file": str(tmp_path / "test.log")}))
    return str(path)


@responses.activate
def test_check_version(config_file, capsys):
    responses.get(
        f"{BASE}/system/about",
        json={
            "release_name": "7.5.0 UpdatePackage 13",
            "build_version": "x",
            "fips_enabled": False,
            "external_version": "7.5.0",
        },
    )
    assert main(["-c", config_file, "check", "version"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "release_name: 7.5.0 UpdatePackage 13" in out


@responses.activate
def test_check_domains_labels_default_domain(config_file, capsys):
    responses.get(f"{BASE}/config/domain_management/domains", json=[{"id": 0, "name": ""}, {"id": 3, "name": "SOC"}])
    assert main(["-c", config_file, "check", "domains"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Domain ID: 0, Domain Name: DEFAULT_DOMAIN" in out
    assert "Domain ID: 3, Domain Name: SOC" in out


@responses.activate
def test_check_api_reports_missing_create(config_file, capsys):
    responses.get(f"{BASE}/help/versions", json=[{"version": "20.0"}])
    responses.get(
        f"{BASE}/help/endpoints",
        json=[{"http_method": "GET", "path": "/asset_model/assets", "version": "20.0"}],
    )
    assert main(["-c", config_file, "check", "api"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Read assets ..." in out and "... yes" in out
    assert "Create missing assets ..." in out
    assert "(POST /asset_model/assets is not offered by this QRadar)" in out
    assert "Assets unknown to QRadar will be reported by the import, not created." in out


@responses.activate
def test_api_error_exit_code(config_file, capsys):
    responses.get(f"{BASE}/system/about", status=401, json={"message": "Invalid token"})
    assert main(["-c", config_file, "check", "version"]) == EXIT_ERROR
    assert "Invalid token" in capsys.readouterr().err


def test_config_error_exit_code(tmp_path, capsys):
    assert main(["-c", str(tmp_path / "nope.json"), "check", "version"]) == EXIT_CONFIG
    assert "Configuration error" in capsys.readouterr().err


def test_no_command_prints_help(capsys):
    assert main([]) == EXIT_CONFIG
    assert "usage" in capsys.readouterr().out


def mock_catalog():
    from tests.fixtures import ASSETS, DOMAINS, PROPERTIES

    responses.get(f"{BASE}/asset_model/properties", json=PROPERTIES)
    responses.get(f"{BASE}/config/domain_management/domains", json=DOMAINS)
    return ASSETS


@responses.activate
def test_properties_command(config_file, capsys):
    mock_catalog()
    assert main(["-c", config_file, "properties"]) == EXIT_OK
    out = capsys.readouterr().out
    assert re.search(r"^1005 +Business Owner +TEXT$", out, re.M)
    assert "MVS Status" in out and "custom" in out


@responses.activate
def test_saved_searches_command(config_file, capsys):
    responses.get(
        f"{BASE}/asset_model/saved_searches",
        json=[
            {
                "id": 20,
                "name": "Stale",
                "owner": "admin",
                "is_shared": True,
                "filters": [{"parameter": "Days Since Asset Scanned", "operator": "Greater than", "value": "14"}],
            }
        ],
    )
    assert main(["-c", config_file, "saved-searches"]) == EXIT_OK
    assert "Days Since Asset Scanned greater than 14" in capsys.readouterr().out


@responses.activate
def test_export_csv_with_filters(config_file, tmp_path, capsys):
    import csv

    assets = mock_catalog()
    responses.get(f"{BASE}/asset_model/assets", json=assets)
    output = tmp_path / "out.csv"
    code = main(
        ["-c", config_file, "export", "-o", str(output), "--cidr", "192.0.2.0/24", "--properties", "Business Owner"]
    )
    assert code == EXIT_OK
    assert "1 assets exported" in capsys.readouterr().out
    with open(output, encoding="utf-8", newline="") as file:
        rows = list(csv.DictReader(file))
    assert [r["id"] for r in rows] == ["2723"]
    assert rows[0]["domain_name"] == "DEFAULT_DOMAIN"
    assert rows[0]["Business Owner"] == "SOC"
    # Only a cell starting with a formula character is run by a spreadsheet: this one is safe as is.
    assert rows[0]["users"] == "admin;=cmd|' /C calc'!A0"
    assert list(rows[0])[-1] == "Business Owner"


@responses.activate
def test_export_json_from_saved_search_and_domain(config_file, tmp_path, capsys):
    from responses import matchers

    from tests.fixtures import SERVER

    mock_catalog()
    responses.get(f"{BASE}/asset_model/saved_searches", json=[{"id": 20, "name": "Stale"}])
    responses.get(f"{BASE}/asset_model/saved_searches/20/results", json=[{"id": 3001}, {"id": 2757}])
    responses.get(
        f"{BASE}/asset_model/assets",
        json=[SERVER],
        match=[matchers.query_param_matcher({"filter": "id IN (3001,2757) and domain_id = 1"})],
    )
    output = tmp_path / "out.json"
    assert (
        main(["-c", config_file, "export", "-o", str(output), "--saved-search", "stale", "--domain", "prod1"])
        == EXIT_OK
    )
    assert json.loads(output.read_text(encoding="utf-8")) == [SERVER]
    out = capsys.readouterr().out
    assert "Saved search 20 'Stale': 2 assets" in out


@responses.activate
def test_export_default_path(config_file, tmp_path, capsys):
    assets = mock_catalog()
    responses.get(f"{BASE}/asset_model/assets", json=assets)
    assert main(["-c", config_file, "export", "--per-ip"]) == EXIT_OK
    files = list((tmp_path / "exports").glob(f"assets-{HOST}-*.csv"))
    assert len(files) == 1
    out = capsys.readouterr().out
    assert "3 assets exported" in out
    assert "(5 rows, one per IP)" in out


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--domain", "PROD9"], "Unknown domain 'PROD9'"),
        (["--properties", "Owner"], "Unknown asset property: Owner"),
        (["--property", "Business Owner"], "--property expects NAME=VALUE"),
        (["--cidr", "10.0.0.300/8"], "Invalid --cidr value"),
    ],
)
@responses.activate
def test_export_usage_errors(config_file, capsys, extra, message):
    mock_catalog()
    assert main(["-c", config_file, "export", *extra]) == EXIT_CONFIG
    assert message in capsys.readouterr().err


@responses.activate
def test_export_escapes_formula_cell(config_file, tmp_path):
    from tests.fixtures import HOSTNAME_ONLY

    mock_catalog()
    evil = {**HOSTNAME_ONLY, "users": [{"username": '=HYPERLINK("http://x")'}]}
    responses.get(f"{BASE}/asset_model/assets", json=[evil])
    output = tmp_path / "out.csv"
    assert main(["-c", config_file, "export", "-o", str(output), "--properties", ""]) == EXIT_OK
    assert "'=HYPERLINK" in output.read_text(encoding="utf-8")


def mock_caps(api="29.0"):
    responses.get(f"{BASE}/help/versions", json=[{"version": "24.0"}, {"version": "29.0"}])
    endpoints = [
        ("GET", "/asset_model/assets", "24.0"),
        ("GET", "/asset_model/assets", "29.0"),
        ("POST", "/asset_model/assets/{asset_id}", "24.0"),
        ("POST", "/asset_model/assets/{asset_id}", "29.0"),
        ("POST", "/asset_model/assets", "24.0"),
        ("POST", "/asset_model/assets", "29.0"),
        ("DELETE", "/asset_model/assets/{asset_id}", "29.0"),
        ("PATCH", "/asset_model/assets", "29.0"),
        ("GET", "/asset_model/asset_bulk_tasks/{id}", "29.0"),
    ]
    responses.get(
        f"{BASE}/help/endpoints",
        json=[{"http_method": m, "path": p, "version": v, "caller_has_access": True} for m, p, v in endpoints],
    )


def write_import_file(tmp_path, text):
    path = tmp_path / "in.csv"
    path.write_text(text, encoding="utf-8")
    return str(path)


def writes(calls):
    return [c for c in calls if c.request.method in ("POST", "PATCH", "DELETE")]


@responses.activate
def test_import_dry_run_writes_nothing(config_file, tmp_path, capsys):
    assets = mock_catalog()
    mock_caps()
    responses.get(f"{BASE}/asset_model/assets", json=assets)
    path = write_import_file(tmp_path, "id,Business Owner\n2723,IT\n3001,\n,\n")
    report = tmp_path / "report.csv"
    assert main(["-c", config_file, "import", path, "--report", str(report)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Assets to update ...... 1 (1 property changes)" in out
    assert "asset 2723 (192.0.2.143): Business Owner: 'SOC' -> 'IT'" in out
    assert "Dry run: nothing was written" in out
    assert writes(responses.calls) == []
    assert "update,2723" in report.read_text(encoding="utf-8")


@responses.activate
def test_import_apply_with_backup(config_file, tmp_path, capsys):
    assets = mock_catalog()
    mock_caps()
    responses.get(f"{BASE}/asset_model/assets", json=assets)
    responses.post(f"{BASE}/asset_model/assets/2723", status=202, json={})
    path = write_import_file(tmp_path, "ip_address,Business Owner\n192.0.2.143,IT\n")
    assert main(["-c", config_file, "import", path, "--apply"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Result: 1 update submitted" in out
    [backup] = list((tmp_path / "safety").glob("backup-before-import-*.json"))
    data = json.loads(backup.read_text(encoding="utf-8"))
    assert [a["id"] for a in data["assets"]] == [2723]
    assert [c.request.url for c in writes(responses.calls)] == [f"{BASE}/asset_model/assets/2723"]


@responses.activate
def test_import_invalid_rows_block_apply(config_file, tmp_path, capsys):
    assets = mock_catalog()
    mock_caps()
    responses.get(f"{BASE}/asset_model/assets", json=assets)
    path = write_import_file(tmp_path, "id,Business Owner\n2723,IT\n99,X\n")
    assert main(["-c", config_file, "import", path, "--apply"]) == EXIT_CONFIG
    assert "1 invalid rows" in capsys.readouterr().err
    assert writes(responses.calls) == []


@responses.activate
def test_import_creates_in_bulk_when_allowed(config_file, tmp_path, capsys):
    assets = mock_catalog()
    mock_caps()
    responses.get(f"{BASE}/asset_model/assets", json=assets)
    responses.patch(
        f"{BASE}/asset_model/assets", status=202, headers={"Location": "/api/asset_model/asset_bulk_tasks/t1"}, json={}
    )
    responses.get(
        f"{BASE}/asset_model/asset_bulk_tasks/t1",
        json={"status": "COMPLETED_SUCCESSFULLY", "operation_statuses": [{"http_status": 201, "asset_id": 7001}]},
    )
    path = write_import_file(tmp_path, "ip_address,domain_name,Business Owner\n198.51.100.7,PROD1,IT\n")

    assert main(["-c", config_file, "import", path, "--apply"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Assets not found ...... 1" in out and "use --allow-create" in out
    assert list((tmp_path / "exports").glob("assets-not-found-*.csv"))

    assert main(["-c", config_file, "import", path, "--apply", "--allow-create"]) == EXIT_OK
    assert "1 create created" in capsys.readouterr().out
    [backup] = list((tmp_path / "safety").glob("backup-before-import-*.json"))
    assert json.loads(backup.read_text(encoding="utf-8"))["created_asset_ids"] == [7001]


@responses.activate
def test_restore_dry_run_then_apply(config_file, tmp_path, capsys):
    from tests.fixtures import PROPERTIES, WORKSTATION

    backup = tmp_path / "backup.json"
    backup.write_text(
        json.dumps({"host": HOST, "created_at": "x", "assets": [WORKSTATION], "created_asset_ids": [7001]}),
        encoding="utf-8",
    )
    changed = {**WORKSTATION, "properties": [{"name": "Business Owner", "type_id": 1005, "value": "IT"}]}
    responses.get(f"{BASE}/asset_model/properties", json=PROPERTIES)
    responses.get(f"{BASE}/asset_model/assets", json=[changed])
    mock_caps()
    responses.post(
        f"{BASE}/asset_model/assets/2723",
        status=202,
        json={},
        match=[
            responses.matchers.json_params_matcher(
                {"properties": [{"type_id": 1002, "value": "ws01.example.lan"}, {"type_id": 1005, "value": "SOC"}]}
            )
        ],
    )
    responses.delete(f"{BASE}/asset_model/assets/7001", status=204)

    assert main(["-c", config_file, "restore", str(backup), "--delete-created"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "asset 2723: Unified Name: '' -> 'ws01.example.lan'; Business Owner: 'IT' -> 'SOC'" in out
    assert "will be deleted: 7001" in out
    assert writes(responses.calls) == []

    assert main(["-c", config_file, "restore", str(backup), "--delete-created", "--apply"]) == EXIT_OK
    assert "Restore done: 2 succeeded, 0 failed" in capsys.readouterr().out


def test_restore_refuses_other_host(config_file, tmp_path, capsys):
    backup = tmp_path / "backup.json"
    backup.write_text(json.dumps({"host": "other.lan", "assets": []}), encoding="utf-8")
    assert main(["-c", config_file, "restore", str(backup)]) == EXIT_CONFIG
    assert "made on other.lan" in capsys.readouterr().err


NH = [
    {"id": 1, "network_id": 10, "group": "Z_Catch", "name": "doc", "cidr": "192.0.2.0/24", "domain_id": 0},
    {"id": 2, "network_id": 20, "group": "Servers", "name": "db", "cidr": "10.1.0.0/16", "domain_id": 2},
]


@responses.activate
def test_report_csv_and_fail_on(config_file, tmp_path, capsys):
    import csv

    assets = mock_catalog()
    responses.get(f"{BASE}/asset_model/assets", json=assets)
    responses.get(f"{BASE}/config/network_hierarchy/networks", json=NH)
    output = tmp_path / "report.csv"
    code = main(["-c", config_file, "report", "-o", str(output), "--catch-all-group", "Z_Catch", "--fail-on", "high"])
    out = capsys.readouterr().out
    assert code == 3  # SERVER 10.1.1.24 is in a network of domain 2
    assert "3 assets checked against 2 Network Hierarchy networks (QRadar)" in out
    assert "nh-domain-mismatch (1):" in out
    with open(output, encoding="utf-8", newline="") as file:
        rows = list(csv.DictReader(file))
    assert rows[0]["severity"] == "high" and rows[0]["check"] == "nh-domain-mismatch"
    assert {"nh-catch-all", "outside-nh", "stale", "no-owner"} <= {r["check"] for r in rows}


@responses.activate
def test_report_without_nh_and_only_some_checks(config_file, tmp_path, capsys):
    assets = mock_catalog()
    responses.get(f"{BASE}/asset_model/assets", json=assets)
    output = tmp_path / "report.json"
    assert (
        main(["-c", config_file, "report", "-o", str(output), "--checks", "no-owner,outside-nh", "--no-nh"]) == EXIT_OK
    )
    [payload] = json.loads(output.read_text(encoding="utf-8"))
    assert payload["options"]["checks"] == ["no-owner"]
    assert {f["check"] for f in payload["findings"]} == {"no-owner"}
    assert all(not c.request.url.endswith("networks") for c in responses.calls)


@responses.activate
def test_report_with_nhsuite_file(config_file, tmp_path, capsys):
    assets = mock_catalog()
    responses.get(f"{BASE}/asset_model/assets", json=assets)
    nh = tmp_path / "nh.csv"
    nh.write_text("id,group,name,cidr,description,domain_id,location,country_code\n1,All,all,0.0.0.0/0,,0,,\n")
    assert main(["-c", config_file, "report", "--nh-file", str(nh), "--checks", "outside-nh"]) == EXIT_OK
    out = capsys.readouterr().out
    assert f"Network Hierarchy networks ({nh})" in out
    assert "outside-nh (1):" in out  # only the IPv6 address


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--checks", "dupes"], "Unknown check(s): dupes"),
        (["--owner-property", "Owner"], "Unknown asset property: Owner"),
        (["--checks", "stale", "--skip", "stale"], "No check left to run"),
    ],
)
@responses.activate
def test_report_usage_errors(config_file, capsys, extra, message):
    mock_catalog()
    assert main(["-c", config_file, "report", *extra]) == EXIT_CONFIG
    assert message in capsys.readouterr().err


@responses.activate
def test_netbox_sync_dry_run(config_file, tmp_path, capsys):
    from tests.test_netbox import DEVICE, IPS, NB, NB_TOKEN, VM

    data = json.loads(open(config_file).read())
    data["netbox"] = {"url": NB, "token": NB_TOKEN, "verify_ssl": False}
    with open(config_file, "w") as file:
        json.dump(data, file)

    assets = mock_catalog()
    mock_caps()
    responses.get(f"{BASE}/asset_model/assets", json=assets)
    responses.get(f"{NB}/api/ipam/ip-addresses/", json={"next": None, "results": IPS})
    responses.get(f"{NB}/api/dcim/devices/", json={"next": None, "results": [DEVICE]})
    responses.get(f"{NB}/api/virtualization/virtual-machines/", json={"next": None, "results": [VM]})

    # The default mapping uses properties missing from the test catalog: they must be refused first.
    assert main(["-c", config_file, "netbox-sync"]) == EXIT_CONFIG
    assert "Unknown asset properties" in capsys.readouterr().err

    data["netbox"]["mapping"] = {"Given Name": {"first": ["object_name", "dns_name"]}, "Business Owner": "tenant"}
    with open(config_file, "w") as file:
        json.dump(data, file)
    csv_path = tmp_path / "netbox.csv"
    code = main(["-c", config_file, "netbox-sync", "--allow-create", "--save-csv", str(csv_path)])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "4 NetBox IP addresses (status active) -> domain DEFAULT_DOMAIN" in out
    assert "Assets to create ...... 4" in out  # none of the documentation IPs is in the mocked QRadar
    assert "Dry run: nothing was written" in out
    assert (
        csv_path.read_text(encoding="utf-8").splitlines()[0]
        == "ip_address,dns_names,domain_name,Given Name,Business Owner"
    )
    assert writes(responses.calls) == []


@responses.activate
def test_pfsense_sync_dry_run_fills_empty_only(config_file, tmp_path, capsys):
    import os

    from tests.fixtures import WORKSTATION

    data = json.loads(open(config_file).read())
    data["pfsense"] = {
        "networks": ["192.0.2.0/24"],
        "mapping": {"Given Name": "dns_name", "Business Owner": "category"},
    }
    with open(config_file, "w") as file:
        json.dump(data, file)
    mock_catalog()
    mock_caps()
    responses.get(f"{BASE}/asset_model/assets", json=[WORKSTATION])
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    report = tmp_path / "report.csv"
    code = main(
        [
            "-c", config_file, "pfsense-sync",
            "--file", os.path.join(fixtures, "pfsense-unbound.xml"),
            "--file", os.path.join(fixtures, "pfsense-dhcpd.xml"),
            "--report", str(report),
        ]
    )  # fmt: skip
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "6 pfSense IP addresses in 2 file(s), 4 kept (192.0.2.0/24) -> domain DEFAULT_DOMAIN" in out
    assert "pfSense only fills empty properties" in out
    # WORKSTATION (192.0.2.143) already has Business Owner "SOC": only the empty Given Name is set.
    assert "asset 2723 (192.0.2.143): Given Name: '' -> 'ws01.example.lan'" in out
    assert "Business Owner" not in out.split("Updates:")[1].split("\n")[1]
    assert "Assets not found ...... 3" in out
    assert writes(responses.calls) == []

    code = main(["-c", config_file, "pfsense-sync", "--file", os.path.join(fixtures, "missing.xml")])
    assert code == EXIT_CONFIG
    assert "pfSense backup file not found" in capsys.readouterr().err
