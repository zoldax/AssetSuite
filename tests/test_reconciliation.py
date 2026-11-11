"""The identifiers QRadar leaves out of its asset reconciliation: reading the reference sets, the excluded check,
the duplicates that say whether their shared value is excluded."""

import copy
import json
import re
from datetime import timedelta
from urllib.parse import unquote_plus

import pytest
import responses

from assetsuite.cli import EXIT_OK, main
from assetsuite.quality import CHECKS, ReportOptions, check_assets
from assetsuite.reconciliation import (
    ADD,
    EXCLUDED,
    KEPT,
    REMOVE,
    ReconciliationError,
    apply_change,
    describe,
    for_asset,
    normalize_value,
    plan_change,
    read_lists,
    ttl_seconds,
)
from assetsuite.service import prepare_report, report_payload, run_report
from tests.conftest import BASE, HOST, TOKEN
from tests.fixtures import DAY_MS, DOMAINS, NOW, NOW_MS, PROPERTIES, SERVER, WORKSTATION

WEEK_MS = 7 * DAY_MS
SETS = [
    {"id": 5, "name": "Asset Reconciliation IPv4 Blacklist", "time_to_live": WEEK_MS, "expiry_type": "LAST_SEEN"},
    {"id": 7, "name": "Asset Reconciliation DNS Blacklist", "time_to_live": WEEK_MS, "expiry_type": "LAST_SEEN"},
    {"id": 8, "name": "Asset Reconciliation MAC Blacklist", "time_to_live": WEEK_MS, "expiry_type": "LAST_SEEN"},
    {"id": 3, "name": "Asset Reconciliation DNS Whitelist", "time_to_live": None, "expiry_type": "FIRST_SEEN"},
]
RULE = "AssetExclusion: Exclude DNS Name By IP"


def entry(collection_id, value, source=RULE, days_ago=2, domain_id=None):
    seen = NOW_MS - days_ago * DAY_MS
    return {
        "id": 100 + len(value) * 10 + collection_id,
        "collection_id": collection_id,
        "value": value,
        "source": source,
        "first_seen": seen,
        "last_seen": seen,
        "domain_id": domain_id,
    }


ENTRIES = [
    entry(7, "WS01.example.lan"),  # case ignored, as the set does
    entry(8, "02:00:00:00:9B:6E", source="AssetExclusion: Exclude MAC Address By IP"),
    entry(5, "10.1.1.24", source="reference data api", domain_id=2),  # another domain than SERVER's
    entry(3, "gitlab", source="admin"),
]


def mock_lists(sets=SETS, entries=ENTRIES, base=BASE):
    responses.get(f"{base}/reference_data_collections/sets", json=sets)
    responses.get(f"{base}/reference_data_collections/set_entries", json=entries)


@pytest.fixture
def lists(client):
    with responses.RequestsMock() as mock:
        mock.get(f"{BASE}/reference_data_collections/sets", json=SETS)
        mock.get(f"{BASE}/reference_data_collections/set_entries", json=ENTRIES)
        return read_lists(client)


def test_lists_read_with_the_collections_api(client, lists):
    assert lists.sets == sorted(s["name"] for s in SETS)
    dns = lists.lookup("dns", "ws01.EXAMPLE.lan")[0]
    assert (dns.listed, dns.source) == (EXCLUDED, RULE)
    assert (dns.expires - dns.last_seen).days == 7  # LAST_SEEN: a week after it was last seen
    # The time of the console, as QRadar counts and shows it: no time zone, never converted.
    assert dns.first_seen.tzinfo is None and dns.first_seen == NOW.replace(tzinfo=None) - timedelta(days=2)
    assert "since 2026-10-25T12:00:00, by" in describe(dns)
    assert lists.lookup("mac", "02-00-00-00-9b-6e")  # MAC compared normalized
    assert lists.lookup("ip", "10.1.1.24", 1) == [] and lists.lookup("ip", "10.1.1.24", 2)  # its domain only
    kept = lists.lookup("dns", "gitlab")[0]
    assert kept.listed == KEPT and kept.expires is None
    assert describe(kept).startswith("on the reconciliation whitelist since ")


@responses.activate
def test_sets_filtered_by_name_and_entries_by_collection(client):
    other = {"id": 9, "name": "Asset Reconciliation Notes", "time_to_live": None, "expiry_type": "FIRST_SEEN"}
    mock_lists(SETS + [other])
    read_lists(client)
    sets_call, entries_call = (unquote_plus(c.request.url) for c in responses.calls)
    assert 'filter=name ILIKE "Asset Reconciliation %"' in sets_call
    assert "filter=collection_id IN (3, 5, 7, 8)" in entries_call  # not 9: not a reconciliation list


@responses.activate
def test_older_qradar_read_with_the_reference_data_api(client):
    responses.get(f"{BASE}/reference_data_collections/sets", status=404, json={"message": "no such endpoint"})
    responses.get(
        f"{BASE}/reference_data/sets",
        json=[{"name": "Asset Reconciliation DNS Blacklist", "time_to_live": "7 days", "timeout_type": "LAST_SEEN"}],
    )
    item = entry(7, "ws01.example.lan")
    responses.get(f"{BASE}/reference_data/sets/Asset%20Reconciliation%20DNS%20Blacklist", json={"data": [item]})
    lists = read_lists(client)
    (dns,) = lists.lookup("dns", "ws01.example.lan")
    assert (dns.expires - dns.last_seen).days == 7


def test_time_to_live_in_both_forms():
    assert ttl_seconds(WEEK_MS) == 7 * 86400
    assert ttl_seconds("7 days") == 7 * 86400
    assert ttl_seconds("1 mon 2 days") == 32 * 86400
    assert ttl_seconds(None) is None and ttl_seconds("") is None and ttl_seconds("forever") is None


def test_identifiers_of_an_asset_on_a_list(lists):
    found = [(kind, value, e.listed) for kind, value, e in for_asset(WORKSTATION, lists)]
    assert found == [("mac", "02:00:00:00:9b:6e", EXCLUDED), ("dns", "ws01.example.lan", EXCLUDED)]
    assert for_asset(SERVER, lists) == []  # 10.1.1.24 is excluded in another domain


def test_excluded_check(lists):
    findings = check_assets([WORKSTATION, SERVER], ReportOptions(now=NOW), {"excluded"}, lists=lists)
    assert [(f.asset_id, f.target) for f in findings] == [(2723, "02:00:00:00:9b:6e"), (2723, "ws01.example.lan")]
    assert findings[1].detail.startswith("DNS name excluded from reconciliation since ")
    assert f"by {RULE}, until " in findings[1].detail
    assert CHECKS["excluded"][0] == "low"
    assert check_assets([WORKSTATION], ReportOptions(now=NOW), {"excluded"}) == []  # lists not read


def test_duplicates_say_whether_their_shared_value_is_excluded(lists):
    twin = copy.deepcopy(WORKSTATION)
    twin["id"] = 9001
    findings = check_assets([WORKSTATION, twin], ReportOptions(now=NOW), {"duplicate-ip", "duplicate-mac"}, lists=lists)
    details = {(f.check, f.asset_id): f.detail for f in findings}
    assert details[("duplicate-ip", 2723)] == "also on asset(s) 9001"  # its IP is on no list
    mac = details[("duplicate-mac", 2723)]
    assert re.match(r"also on asset\(s\) 9001; excluded from reconciliation since .+, by ", mac)


@responses.activate
def test_report_reads_the_lists_once(client):
    responses.get(f"{BASE}/asset_model/properties", json=PROPERTIES)
    responses.get(f"{BASE}/config/domain_management/domains", json=DOMAINS)
    responses.get(f"{BASE}/asset_model/assets", json=[WORKSTATION, SERVER])
    mock_lists()
    outcome = run_report(client, prepare_report(client, checks=["excluded", "stale"]))
    assert [f.target for f in outcome.findings if f.check == "excluded"] == ["02:00:00:00:9b:6e", "ws01.example.lan"]
    assert report_payload(HOST, outcome)["warnings"] == []
    assert sum("reference_data_collections/sets" in c.request.url for c in responses.calls) == 1


@responses.activate
def test_report_goes_on_when_qradar_refuses_the_lists(client):
    responses.get(f"{BASE}/asset_model/properties", json=PROPERTIES)
    responses.get(f"{BASE}/config/domain_management/domains", json=DOMAINS)
    responses.get(f"{BASE}/asset_model/assets", json=[WORKSTATION])
    responses.get(f"{BASE}/reference_data_collections/sets", status=403, json={"message": "No access"})
    outcome = run_report(client, prepare_report(client, checks=["excluded", "unnamed"]))
    payload = report_payload(HOST, outcome)
    assert payload["options"]["checks"] == ["unnamed"] and "excluded" not in payload["summary"]
    (warning,) = payload["warnings"]
    assert warning.startswith("Reconciliation exclusions not read (HTTP 403 on GET /reference_data_collections/sets")
    assert warning.endswith("the excluded check was not run.")


@responses.activate
def test_report_without_these_checks_does_not_read_the_lists(client):
    responses.get(f"{BASE}/asset_model/properties", json=PROPERTIES)
    responses.get(f"{BASE}/config/domain_management/domains", json=DOMAINS)
    responses.get(f"{BASE}/asset_model/assets", json=[WORKSTATION])
    run_report(client, prepare_report(client, checks=["stale"]))
    assert not any("reference_data" in c.request.url for c in responses.calls)


@responses.activate
def test_exclusions_command(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    for name in ("QRADAR_HOST", "QRADAR_SEC_TOKEN", "QRADAR_API_VERSION"):
        monkeypatch.delenv(name, raising=False)
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"host": HOST, "token": TOKEN, "log_file": str(tmp_path / "test.log")}))
    mock_lists()
    assert main(["-c", str(config), "exclusions"]) == EXIT_OK
    out = capsys.readouterr().out
    assert re.search(r"^MAC address +02:00:00:00:9B:6E +excluded .+Exclude MAC Address By IP$", out, re.M)
    assert re.search(r"^IP address +10\.1\.1\.24 +excluded .+ 2 +reference data api$", out, re.M)
    assert re.search(r"^DNS name +gitlab +whitelist .+ never +all +admin$", out, re.M)
    assert "3 excluded, 1 on a whitelist (4 reference sets)." in out


def test_values_are_checked_and_normalized():
    assert normalize_value("mac", "02-00-00-00-9B-6E") == "02:00:00:00:9b:6e"
    assert normalize_value("ip", " 192.0.2.7 ") == "192.0.2.7"
    for kind, value in (("ip", "192.0.2"), ("mac", "02:00"), ("dns", "two words"), ("dns", ""), ("os", "x")):
        with pytest.raises(ReconciliationError):
            normalize_value(kind, value)


def test_changes_planned_against_the_lists(lists):
    change = plan_change(lists, ADD, "dns", "printer-01.example.lan", EXCLUDED)
    assert (change.set_name, change.set_id, change.existing) == ("Asset Reconciliation DNS Blacklist", 7, None)
    assert change.text().endswith("QRadar no longer matches assets on it.")
    again = plan_change(lists, ADD, "dns", "ws01.example.lan", EXCLUDED)  # already there: its time starts over
    assert again.existing and "again" in again.text()
    removed = plan_change(lists, REMOVE, "mac", "02:00:00:00:9b:6e", EXCLUDED)
    assert removed.existing.entry_id and removed.text().startswith("Remove MAC address 02:00:00:00:9b:6e from")
    kept = plan_change(lists, ADD, "dns", "files.example.lan", KEPT)
    assert kept.set_name == "Asset Reconciliation DNS Whitelist"
    refused = {
        "nothing to remove": (REMOVE, "dns", "files.example.lan", EXCLUDED),
        "remove it from there first": (ADD, "dns", "gitlab", EXCLUDED),  # on the whitelist
        "no asset reconciliation NetBIOS name blacklist": (ADD, "netbios", "WS01", EXCLUDED),
        "no asset reconciliation IPv6 blacklist": (ADD, "ip", "2001:db8::5", EXCLUDED),
    }
    for message, args in refused.items():
        with pytest.raises(ReconciliationError, match=message):
            plan_change(lists, *args)


@responses.activate
def test_changes_written_to_qradar(client, lists):
    added = {"id": 900, "collection_id": 7, "value": "printer-01.example.lan", "notes": "AssetSuite (admin)"}
    responses.post(f"{BASE}/reference_data_collections/set_entries", json=added, status=201)
    change = plan_change(lists, ADD, "dns", "printer-01.example.lan", EXCLUDED)
    entry = apply_change(client, change, "AssetSuite (admin)")
    assert entry["id"] == 900
    assert json.loads(responses.calls[0].request.body) == {
        "collection_id": 7,
        "value": "printer-01.example.lan",
        "notes": "AssetSuite (admin)",
    }
    change = plan_change(lists, REMOVE, "mac", "02:00:00:00:9b:6e", EXCLUDED)
    responses.delete(f"{BASE}/reference_data_collections/set_entries/{change.existing.entry_id}", status=204)
    assert apply_change(client, change)["source"] == "AssetExclusion: Exclude MAC Address By IP"
    assert responses.calls[-1].request.headers["Accept"] == "text/plain"  # QRadar answers 406 to JSON


@responses.activate
def test_lists_read_with_the_older_api_cannot_be_changed(client):
    responses.get(f"{BASE}/reference_data_collections/sets", status=404, json={"message": "no such endpoint"})
    responses.get(
        f"{BASE}/reference_data/sets",
        json=[{"name": "Asset Reconciliation DNS Blacklist", "time_to_live": "7 days", "timeout_type": "LAST_SEEN"}],
    )
    responses.get(f"{BASE}/reference_data/sets/Asset%20Reconciliation%20DNS%20Blacklist", json={"data": []})
    with pytest.raises(ReconciliationError, match="collections API"):
        plan_change(read_lists(client), ADD, "dns", "printer", EXCLUDED)


@responses.activate
def test_exclusions_command_changes_one_entry(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    for name in ("QRADAR_HOST", "QRADAR_SEC_TOKEN", "QRADAR_API_VERSION"):
        monkeypatch.delenv(name, raising=False)
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"host": HOST, "token": TOKEN, "log_file": str(tmp_path / "test.log")}))
    mock_lists()
    assert main(["-c", str(config), "exclusions", "--add", "dns:printer-01.example.lan"]) == EXIT_OK
    assert "Dry run: nothing written" in capsys.readouterr().out
    assert all(c.request.method == "GET" for c in responses.calls)

    responses.post(f"{BASE}/reference_data_collections/set_entries", json={"id": 901}, status=201)
    args = ["-c", str(config), "exclusions", "--add", "ip:198.51.100.7", "--whitelist", "--apply", "--note", "VIP"]
    responses.replace(responses.GET, f"{BASE}/reference_data_collections/sets", json=SETS + [WHITELIST_IPV4])
    assert main(args) == EXIT_OK
    assert "Done: entry 901 added to Asset Reconciliation IPv4 Whitelist." in capsys.readouterr().out
    assert json.loads(responses.calls[-1].request.body) == {"collection_id": 1, "value": "198.51.100.7", "notes": "VIP"}
    assert main(["-c", str(config), "exclusions", "--remove", "dns:nobody"]) != EXIT_OK


WHITELIST_IPV4 = {
    "id": 1,
    "name": "Asset Reconciliation IPv4 Whitelist",
    "time_to_live": None,
    "expiry_type": "FIRST_SEEN",
}
