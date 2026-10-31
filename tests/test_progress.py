"""Progress reporting and cancellation through the core, and the service layer used by the CLI and the App."""

import pytest
import responses
from responses import matchers

from assetsuite.config import config_from_mapping
from assetsuite.importer import ImportRow
from assetsuite.progress import NO_PROGRESS, Cancelled, Progress, or_none
from assetsuite.service import (
    REPORT_COLUMNS,
    ServiceError,
    plan_import,
    prepare_import,
    prepare_report,
    report_payload,
    report_rows,
    run_report,
)
from tests.conftest import BASE, TOKEN
from tests.fixtures import ASSETS, DOMAINS, PROPERTIES
from tests.test_cli import mock_caps


class Recorder(Progress):
    """Keeps every event; cancels after `cancel_after` check_cancelled calls."""

    def __init__(self, cancel_after=None):
        self.events = []
        self.checks = 0
        self.cancel_after = cancel_after

    def phase(self, name, total=None):
        self.events.append(("phase", name, total))

    def set_total(self, total):
        self.events.append(("total", total))

    def advance(self, count=1):
        self.events.append(("advance", count))

    def note(self, text):
        self.events.append(("note", text))

    def check_cancelled(self):
        self.checks += 1
        if self.cancel_after is not None and self.checks > self.cancel_after:
            raise Cancelled()

    def done(self):
        return sum(e[1] for e in self.events if e[0] == "advance")

    def phases(self):
        return [e[1] for e in self.events if e[0] == "phase"]


def page(start, end, total, items):
    return {"json": items, "headers": {"Content-Range": f"items {start}-{end}/{total}"}}


def test_default_progress_does_nothing():
    assert or_none(None) is NO_PROGRESS
    progress = Recorder()
    assert or_none(progress) is progress
    NO_PROGRESS.phase("x", 3)
    NO_PROGRESS.advance()
    NO_PROGRESS.check_cancelled()


def test_config_from_mapping():
    config = config_from_mapping(
        {"host": "https://qradar.example.lan/", "token": TOKEN, "sevone": {"url": "https://sevone.example.lan"}},
        environ={},
    )
    assert config.host == "qradar.example.lan" and config.sections == {"sevone": {"url": "https://sevone.example.lan"}}
    with_env = config_from_mapping({"host": "a", "token": TOKEN}, environ={"QRADAR_HOST": "b"})
    assert with_env.host == "b"


# --- Core loops --------------------------------------------------------------


@responses.activate
def test_iter_pages_reports_total_and_items(small_page_client):
    url = f"{BASE}/asset_model/assets"
    responses.get(url, **page(0, 1, 3, [{"id": 1}, {"id": 2}]), match=[matchers.header_matcher({"Range": "items=0-1"})])
    responses.get(url, **page(2, 2, 3, [{"id": 3}]), match=[matchers.header_matcher({"Range": "items=2-3"})])
    progress = Recorder()
    assert len(small_page_client.get_all("asset_model/assets", progress=progress)) == 3
    assert progress.events == [("total", 3), ("advance", 2), ("advance", 1)]


@responses.activate
def test_iter_pages_cancels_between_pages(small_page_client):
    url = f"{BASE}/asset_model/assets"
    responses.get(url, **page(0, 1, 4, [{"id": 1}, {"id": 2}]))
    with pytest.raises(Cancelled):
        small_page_client.get_all("asset_model/assets", progress=Recorder(cancel_after=1))
    assert len(responses.calls) == 1  # the second page was never asked for


def test_planner_counts_rows():
    from assetsuite.importer import Planner

    domains = [{**d, "name": d["name"] or "DEFAULT_DOMAIN"} for d in DOMAINS]
    rows = [ImportRow(2, {"ip_address": "192.0.2.143", "Business Owner": "IT"}), ImportRow(3, {"ip_address": "x"})]
    progress = Recorder()
    plan = Planner(ASSETS, PROPERTIES, domains).plan(["ip_address", "Business Owner"], rows, progress)
    assert progress.events[0] == ("total", 2) and progress.done() == 2
    assert len(plan.updates) == 1 and len(plan.not_found) == 1


@responses.activate
def test_sevone_phases():
    from assetsuite.sevone import SevOneClient
    from assetsuite.sevone import fetch_records as sevone_fetch
    from tests.test_sevone import config, mock_sevone

    mock_sevone()
    progress = Recorder()
    result = sevone_fetch(SevOneClient(config()), progress)
    assert progress.phases() == ["SevOne devices", "SevOne device details"]
    assert ("total", 5) in progress.events and progress.done() == 10  # 5 devices listed, then 5 detailed
    assert len(result.records) == 3


@responses.activate
def test_netbox_phases():
    from assetsuite.netbox import NetBoxClient
    from assetsuite.netbox import fetch_records as netbox_fetch
    from tests.test_netbox import DEVICE, IPS, NB, VM, config

    responses.get(f"{NB}/api/ipam/ip-addresses/", json={"count": 4, "next": None, "results": IPS})
    responses.get(f"{NB}/api/dcim/devices/", json={"count": 1, "next": None, "results": [DEVICE]})
    responses.get(f"{NB}/api/virtualization/virtual-machines/", json={"count": 1, "next": None, "results": [VM]})
    progress = Recorder()
    netbox_fetch(NetBoxClient(config()), progress)
    assert progress.phases() == ["NetBox IP addresses", "NetBox devices", "NetBox virtual machines"]
    assert progress.events[1] == ("total", 4)


# --- Service -----------------------------------------------------------------


def mock_qradar(assets=ASSETS):
    responses.get(f"{BASE}/asset_model/properties", json=PROPERTIES)
    responses.get(f"{BASE}/config/domain_management/domains", json=DOMAINS)
    responses.get(f"{BASE}/asset_model/assets", json=assets)


@responses.activate
def test_plan_import_phases_and_no_write(client):
    mock_qradar()
    mock_caps()
    context = prepare_import(client, domain="PROD1", allow_create=False)
    assert context.default_domain_id == 1 and not context.can_create
    progress = Recorder()
    rows = [ImportRow(2, {"ip_address": "198.51.100.7", "Business Owner": "IT"})]
    _, plan = plan_import(client, context, ["ip_address", "Business Owner"], rows, progress=progress)
    assert progress.phases() == ["QRadar assets", "Import plan"]
    assert "use --allow-create" in plan.not_found[0][1]
    assert [r["action"] for r in report_rows(plan)] == ["not_found"]
    assert set(report_rows(plan)[0]) <= set(REPORT_COLUMNS)
    assert all(c.request.method == "GET" for c in responses.calls)


@responses.activate
def test_prepare_import_unknown_domain(client):
    mock_qradar()
    mock_caps()
    with pytest.raises(ServiceError, match="Unknown domain 'nope'"):
        prepare_import(client, domain="nope")


@responses.activate
def test_report_through_service(client):
    mock_qradar()
    setup = prepare_report(client, checks=["stale", "unnamed"], stale_days=30)
    progress = Recorder()
    outcome = run_report(client, setup, progress=progress)
    assert progress.phases() == ["QRadar assets", "Asset checks"]
    assert outcome.assets == len(ASSETS) and outcome.networks is None
    payload = report_payload("qradar.example.lan", outcome)
    assert payload["options"]["checks"] == ["stale", "unnamed"]
    assert payload["summary"].keys() == {"stale", "unnamed"}
    assert len(payload["findings"]) == len(outcome.findings)


@responses.activate
def test_prepare_report_errors(client):
    mock_qradar()
    with pytest.raises(ServiceError, match="No check left"):
        prepare_report(client, checks=["stale"], skip=["stale"])
    with pytest.raises(ServiceError, match="Unknown asset property: Owner"):
        prepare_report(client, owner_properties=["Owner"])
