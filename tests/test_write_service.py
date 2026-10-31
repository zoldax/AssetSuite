"""Write services shared by the CLI and the QRadar App: fingerprint, backup, apply, clean stop, restore."""

import json
from dataclasses import replace

import pytest
import responses

from assetsuite.client import QRadarClient
from assetsuite.importer import ImportRow
from assetsuite.service import (
    ServiceError,
    plan_fingerprint,
    plan_import,
    prepare_import,
    prepare_restore,
    restore_fingerprint,
    run_restore,
    safety_backup,
    write_plan,
)
from assetsuite.writer import read_backup
from tests.conftest import BASE, HOST
from tests.fixtures import ASSETS, PROPERTIES, WORKSTATION
from tests.test_cli import mock_caps, writes
from tests.test_progress import Recorder, mock_qradar

HEADER = ["id", "ip_address", "domain_name", "Business Owner"]


@pytest.fixture
def client(config):
    """No API version forced: QRadar's latest, where creating and deleting assets exist."""
    return QRadarClient(replace(config, api_version=None))


def rows(*values):
    return [ImportRow(line, dict(zip(HEADER, v))) for line, v in enumerate(values, start=2)]


def plan_for(client, values, assets=ASSETS, allow_create=True):
    context = prepare_import(client, allow_create=allow_create)
    planner, plan = plan_import(client, context, HEADER, rows(*values))
    return context, planner, plan


UPDATES = (("2723", "", "", "IT"), ("3001", "", "", "DBA"))
CREATION = ("", "198.51.100.7", "PROD1", "IT")


@responses.activate
def test_fingerprint_follows_what_would_be_written(client):
    mock_qradar()
    mock_caps()
    _, _, plan = plan_for(client, UPDATES)
    _, _, same = plan_for(client, UPDATES)
    _, _, other_value = plan_for(client, (("2723", "", "", "NOC"), UPDATES[1]))
    assert plan_fingerprint(plan) == plan_fingerprint(same)
    assert plan_fingerprint(plan) != plan_fingerprint(other_value)

    # The same rows against an asset changed in QRadar since: the old value differs, so does the fingerprint.
    changed = [{**a, "properties": []} if a["id"] == 2723 else a for a in ASSETS]
    responses.replace(responses.GET, f"{BASE}/asset_model/assets", json=changed)
    _, _, after_change = plan_for(client, UPDATES)
    assert plan_fingerprint(after_change) != plan_fingerprint(plan)


@responses.activate
def test_write_plan_updates_creates_and_records_the_created(client, tmp_path):
    mock_qradar()
    mock_caps()
    responses.post(f"{BASE}/asset_model/assets/2723", status=202, json={})
    responses.post(f"{BASE}/asset_model/assets/3001", status=202, json={})
    responses.patch(
        f"{BASE}/asset_model/assets", status=202, headers={"Location": "/api/asset_model/asset_bulk_tasks/t1"}, json={}
    )
    responses.get(
        f"{BASE}/asset_model/asset_bulk_tasks/t1",
        json={"status": "COMPLETED_SUCCESSFULLY", "operation_statuses": [{"http_status": 201, "asset_id": 7001}]},
    )
    context, planner, plan = plan_for(client, (*UPDATES, CREATION))
    backup = safety_backup(client, planner, plan, directory=str(tmp_path / "safety"))
    assert backup.startswith(str(tmp_path / "safety")) and writes(responses.calls) == []

    progress = Recorder()
    result = write_plan(client, context, plan, backup, progress=progress)
    assert not result.stopped and not result.failed
    assert result.counts() == {"update submitted": 2, "create created": 1}
    assert result.created_ids == [7001]
    assert progress.phases() == ["Property updates", "Asset creations"]
    assert ("note", "Creating 1 assets in bulk, this can take a few minutes...") in progress.events
    data = read_backup(backup)
    assert sorted(a["id"] for a in data["assets"]) == [2723, 3001] and data["created_asset_ids"] == [7001]


@responses.activate
def test_write_plan_stops_between_two_assets(client):
    mock_qradar()
    mock_caps()
    responses.post(f"{BASE}/asset_model/assets/2723", status=202, json={})
    context, _, plan = plan_for(client, (*UPDATES, CREATION))
    result = write_plan(client, context, plan, progress=Recorder(cancel_after=1))
    assert result.stopped
    assert [(o.action, o.asset_id) for o in result.outcomes] == [("update", 2723)]
    assert [c.request.url for c in writes(responses.calls)] == [f"{BASE}/asset_model/assets/2723"]


def backup_file(tmp_path, host=HOST, created=(7001,)):
    path = tmp_path / "backup.json"
    path.write_text(
        json.dumps({"host": host, "created_at": "x", "assets": [WORKSTATION], "created_asset_ids": list(created)}),
        encoding="utf-8",
    )
    return read_backup(str(path))


def mock_restore_reads(caps_api="29.0"):
    changed = {**WORKSTATION, "properties": [{"name": "Business Owner", "type_id": 1005, "value": "IT"}]}
    responses.get(f"{BASE}/asset_model/properties", json=PROPERTIES)
    responses.get(f"{BASE}/asset_model/assets", json=[changed])
    mock_caps(caps_api)


@responses.activate
def test_restore_plan_and_run(client, tmp_path):
    mock_restore_reads()
    responses.post(f"{BASE}/asset_model/assets/2723", status=202, json={})
    responses.delete(f"{BASE}/asset_model/assets/7001", status=204)
    backup = backup_file(tmp_path)

    plan = prepare_restore(client, backup, delete_created=True)
    assert [item.asset_id for item in plan.to_restore] == [2723] and plan.created == [7001]
    assert plan.missing == [] and plan.delete_blocked == ""
    assert restore_fingerprint(plan, True) != restore_fingerprint(plan, False)
    assert writes(responses.calls) == []

    progress = Recorder()
    result = run_restore(client, plan, delete_created=True, progress=progress)
    assert result.counts() == {"update submitted": 1, "delete deleted": 1} and not result.stopped
    assert progress.phases() == ["Restore", "Delete created assets"]


@responses.activate
def test_restore_refused_before_any_write(client, tmp_path):
    with pytest.raises(ServiceError, match="made on other.lan"):
        prepare_restore(client, backup_file(tmp_path, host="other.lan"))

    mock_restore_reads()
    plan = prepare_restore(client, backup_file(tmp_path), delete_created=True)
    plan.delete_blocked = "the token may not delete assets"
    with pytest.raises(ServiceError, match="Cannot delete assets"):
        run_restore(client, plan, delete_created=True)
    assert writes(responses.calls) == []
