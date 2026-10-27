"""Read-only live tests: nothing is written to QRadar."""

import csv
import json

import pytest

from assetsuite.assets import iter_ips
from assetsuite.cli import EXIT_CONFIG, EXIT_ERROR, EXIT_FINDINGS, EXIT_OK
from assetsuite.network_hierarchy import NHSUITE_COLUMNS
from tests.live.conftest import CONFIG_PATH, skip_unless_live

pytestmark = [pytest.mark.live, skip_unless_live]


def csv_rows(path):
    with open(path, encoding="utf-8", newline="") as file:
        return list(csv.DictReader(file))


@pytest.fixture(scope="module")
def all_assets(live_client):
    return live_client.get_all("asset_model/assets")


# --- Connection and configuration errors (as in NHSuite-testing) -------------


def test_check_version(run):
    code, out, _ = run("check", "version")
    assert code == EXIT_OK
    release = next(line for line in out.splitlines() if line.startswith("release_name:"))
    assert release.split(":", 1)[1].strip() not in ("", "N/A")


def test_check_domains(run):
    code, out, _ = run("check", "domains")
    assert code == EXIT_OK
    assert "Domain ID: 0, Domain Name: DEFAULT_DOMAIN" in out


def test_check_api(run):
    code, out, _ = run("check", "api")
    assert code == EXIT_OK
    assert "Read assets .................. yes" in out
    assert "Update asset properties ...... yes" in out


def test_wrong_token(run_with_config):
    code, _, err = run_with_config("check", "version", token="00000000-0000-0000-0000-000000000000")
    assert code == EXIT_ERROR
    assert "HTTP 401" in err and "check the SEC token" in err


def test_unknown_host(run_with_config):
    code, _, err = run_with_config("check", "version", host="assetsuite-does-not-exist.invalid")
    assert code == EXIT_ERROR
    assert "Cannot reach assetsuite-does-not-exist.invalid" in err


def test_missing_ca_file(run_with_config):
    code, _, err = run_with_config("check", "version", verify_ssl=True, ssl_cert_path="/nonexistent/ca.pem")
    assert code == EXIT_CONFIG
    assert "ssl_cert_path /nonexistent/ca.pem does not exist" in err


def test_tls_without_internal_ca(run_with_config, live_config):
    if not (live_config.verify_ssl and live_config.ssl_cert_path):
        pytest.skip("the live QRadar is not verified with a custom CA")
    code, _, err = run_with_config("check", "version", verify_ssl=True, ssl_cert_path=None)
    assert code == EXIT_ERROR
    assert "TLS verification failed" in err


def test_unsupported_api_version(run_with_config):
    code, _, err = run_with_config("check", "version", api_version="99.0")
    assert code == EXIT_ERROR
    assert "HTTP 4" in err


def test_capabilities_follow_pinned_api_version(run_with_config, live_client):
    from assetsuite.capabilities import detect_capabilities

    versions = detect_capabilities(live_client).api_versions
    if "24.0" not in versions or "20.0" not in versions:
        pytest.skip("this QRadar does not offer API 20.0 and 24.0")
    _, out_24, _ = run_with_config("check", "api", api_version="24.0")
    assert "Create missing assets ........ yes" in out_24
    assert "Bulk create/delete (async) ... no" in out_24
    _, out_20, _ = run_with_config("check", "api", api_version="20.0")
    assert "Create missing assets ........ no" in out_20


# --- Read commands -----------------------------------------------------------


def test_properties(run):
    code, out, _ = run("properties")
    assert code == EXIT_OK
    assert "Given Name" in out and "Business Owner" in out


def test_saved_searches(run):
    code, out, _ = run("saved-searches")
    assert code == EXIT_OK
    assert out.startswith("ID")


def test_export_csv_has_every_asset(run, workdir, all_assets):
    code, out, _ = run("export", "-o", "all.csv")
    assert code == EXIT_OK
    rows = csv_rows(workdir / "all.csv")
    assert sorted(int(r["id"]) for r in rows) == sorted(a["id"] for a in all_assets)
    assert f"{len(all_assets)} assets exported" in out


def test_export_json_and_per_ip(run, workdir, all_assets):
    assert run("export", "-o", "all.json")[0] == EXIT_OK
    assert len(json.loads((workdir / "all.json").read_text(encoding="utf-8"))) == len(all_assets)

    assert run("export", "--per-ip", "--properties", "", "-o", "per-ip.csv")[0] == EXIT_OK
    expected = sum(max(1, len(list(iter_ips(a)))) for a in all_assets)
    assert len(csv_rows(workdir / "per-ip.csv")) == expected


def test_export_import_round_trip_changes_nothing(run, workdir, all_assets):
    assert run("export", "-o", "all.csv")[0] == EXIT_OK
    code, out, _ = run("import", "all.csv", "--report", "report.csv")
    assert code == EXIT_OK
    assert "Dry run: nothing was written" in out
    actions = {r["action"] for r in csv_rows(workdir / "report.csv")}
    assert actions == {"unchanged"}, f"unexpected actions: {actions}"
    assert not (workdir / "safety").exists()


def test_report(run, workdir):
    code, out, _ = run("report", "-o", "report.csv")
    assert code == EXIT_OK
    rows = csv_rows(workdir / "report.csv")
    assert f"{len(rows)} findings written" in out

    code, _, _ = run("report", "--fail-on", "info", "-o", "report2.csv")
    assert code == (EXIT_FINDINGS if rows else EXIT_OK)


def test_report_nhsuite_file_matches_api(run, workdir, live_client):
    networks = live_client.get("config/network_hierarchy/networks")
    with open(workdir / "nh.csv", "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=NHSUITE_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(networks)

    checks = "outside-nh,nh-domain-mismatch,empty-network"
    assert run("report", "--checks", checks, "-o", "api.csv")[0] == EXIT_OK
    assert run("report", "--checks", checks, "--nh-file", "nh.csv", "-o", "file.csv")[0] == EXIT_OK
    key = lambda r: (r["check"], r["asset_id"], r["target"])  # noqa: E731
    assert sorted(map(key, csv_rows(workdir / "api.csv"))) == sorted(map(key, csv_rows(workdir / "file.csv")))


def test_netbox_sync_dry_run(run, workdir, live_config):
    from assetsuite.netbox import NetBoxError, load_netbox_config

    try:
        load_netbox_config(live_config.sections)
    except NetBoxError as e:
        pytest.skip(f"NetBox not configured: {e}")
    code, out, err = run("netbox-sync", "--allow-create", "--report", "netbox-report.csv", "--save-csv", "netbox.csv")
    assert code == EXIT_OK, out + err
    assert "Dry run: nothing was written" in out
    assert len(csv_rows(workdir / "netbox.csv")) == len(csv_rows(workdir / "netbox-report.csv"))
    assert not (workdir / "safety").exists()


def test_pfsense_sync_dry_run(run, workdir):
    import glob
    import os

    pattern = os.path.join(os.path.dirname(CONFIG_PATH), "private", "*.xml")
    if not glob.glob(pattern):
        pytest.skip("no pfSense backup in private/")
    code, out, err = run("pfsense-sync", "--file", pattern, "--report", "pf-report.csv", "--save-csv", "pf.csv")
    assert code == EXIT_OK, out + err
    assert "pfSense only fills empty properties" in out and "Dry run: nothing was written" in out
    assert len(csv_rows(workdir / "pf.csv")) == len(csv_rows(workdir / "pf-report.csv"))
    assert not (workdir / "safety").exists()
