import json

import responses
from responses import matchers

from assetsuite.importer import Creation, ImportPlan, PropertyChange, Update
from assetsuite.writer import (
    apply_updates,
    create_in_bulk,
    create_one_by_one,
    delete_assets,
    plan_restore,
    read_backup,
    record_created_assets,
    write_backup,
)
from tests.conftest import BASE
from tests.fixtures import PROPERTIES, SERVER, WORKSTATION

CATALOG = {p["name"]: p for p in PROPERTIES}


def creation(line, ip):
    return Creation(line, 1, [ip], None, None, None, {"Business Owner": "IT"})


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds

    def __call__(self):
        return self.now


@responses.activate
def test_apply_updates(client):
    plan = ImportPlan(header=[], property_columns=[])
    plan.updates[2723] = Update(
        2723, 0, "x", [2], {"Business Owner": PropertyChange("Business Owner", 1005, "SOC", "IT")}
    )
    plan.updates[3001] = Update(3001, 1, "y", [3], {"Given Name": PropertyChange("Given Name", 1001, "a", "b")})
    responses.post(
        f"{BASE}/asset_model/assets/2723",
        status=202,
        json={},
        match=[matchers.json_params_matcher({"properties": [{"type_id": 1005, "value": "IT"}]})],
    )
    responses.post(f"{BASE}/asset_model/assets/3001", status=422, json={"code": 1005, "message": "invalid property"})
    outcomes = apply_updates(client, plan)
    assert [(o.asset_id, o.status) for o in outcomes] == [(2723, "submitted"), (3001, "failed")]
    assert "invalid property" in outcomes[1].message


@responses.activate
def test_create_one_by_one(client):
    responses.post(f"{BASE}/asset_model/assets", status=201, json={"id": 5001})
    responses.post(f"{BASE}/asset_model/assets", status=200, json={"id": 2723})
    responses.post(f"{BASE}/asset_model/assets", status=409, json={"code": 1001, "message": "No domain exists"})
    outcomes = create_one_by_one(
        client,
        [creation(2, "198.51.100.1"), creation(3, "198.51.100.2"), creation(4, "198.51.100.3")],
        CATALOG,
        {1: "PROD1"},
    )
    assert [(o.line, o.asset_id, o.status) for o in outcomes] == [
        (2, 5001, "created"),
        (3, 2723, "reconciled"),
        (4, None, "failed"),
    ]
    sent = json.loads(responses.calls[0].request.body)
    assert sent["domain_name"] == "PROD1"


def bulk_task(statuses, status="COMPLETED_WITH_ERRORS"):
    return {"id": "t1", "status": status, "operation_statuses": statuses}


@responses.activate
def test_create_in_bulk_polls_task(client):
    clock = FakeClock()
    responses.patch(
        f"{BASE}/asset_model/assets",
        status=202,
        headers={"Location": f"{BASE}/asset_model/asset_bulk_tasks/t1"},
        json={},
    )
    task_url = f"{BASE}/asset_model/asset_bulk_tasks/t1"
    responses.get(task_url, json={"id": "t1", "status": "IN_PROGRESS", "operation_statuses": []})
    responses.get(
        task_url,
        json=bulk_task(
            [
                {"asset_id": 6001, "operation_type": "CREATE", "http_status": 201, "message": "created"},
                {"asset_id": 2723, "operation_type": "CREATE", "http_status": 200, "message": "reconciled"},
                {
                    "asset_id": None,
                    "operation_type": "CREATE",
                    "http_status": 422,
                    "message": "Invalid IP",
                    "unique_code": 1010,
                },
            ]
        ),
    )
    outcomes = create_in_bulk(
        client,
        [creation(2, "198.51.100.1"), creation(3, "198.51.100.2"), creation(4, "198.51.100.3")],
        CATALOG,
        sleep=clock.sleep,
        clock=clock,
    )
    assert [(o.line, o.asset_id, o.status) for o in outcomes] == [
        (2, 6001, "created"),
        (3, 2723, "reconciled"),
        (4, None, "failed"),
    ]
    assert outcomes[2].message == "Invalid IP (code 1010)"
    assert clock.sleeps == [5.0]
    body = json.loads(responses.calls[0].request.body)
    assert body[0]["domain_id"] == 1 and body[0]["properties"] == [{"type_id": 1005, "value": "IT"}]


@responses.activate
def test_bulk_too_large_is_split(client):
    clock = FakeClock()
    url = f"{BASE}/asset_model/assets"
    responses.patch(url, status=422, json={"code": 1002, "message": "exceeds the maximum limit"})
    responses.patch(url, status=202, headers={"Location": "/api/asset_model/asset_bulk_tasks/a"}, json={})
    responses.patch(url, status=202, headers={"Location": "/api/asset_model/asset_bulk_tasks/b"}, json={})
    ok = {"http_status": 201, "message": "created"}
    responses.get(
        f"{BASE}/asset_model/asset_bulk_tasks/a", json=bulk_task([{**ok, "asset_id": 1}], "COMPLETED_SUCCESSFULLY")
    )
    responses.get(
        f"{BASE}/asset_model/asset_bulk_tasks/b", json=bulk_task([{**ok, "asset_id": 2}], "COMPLETED_SUCCESSFULLY")
    )
    outcomes = create_in_bulk(
        client, [creation(2, "198.51.100.1"), creation(3, "198.51.100.2")], CATALOG, sleep=clock.sleep, clock=clock
    )
    assert [(o.line, o.asset_id, o.status) for o in outcomes] == [(2, 1, "created"), (3, 2, "created")]
    assert [len(json.loads(call.request.body)) for call in responses.calls if call.request.method == "PATCH"] == [
        2,
        1,
        1,
    ]


@responses.activate
def test_bulk_rate_limit_retried(client):
    clock = FakeClock()
    url = f"{BASE}/asset_model/assets"
    responses.patch(url, status=429, json={"code": 1003, "message": "too many requests"})
    responses.patch(url, status=202, headers={"Location": "/api/asset_model/asset_bulk_tasks/a"}, json={})
    responses.get(
        f"{BASE}/asset_model/asset_bulk_tasks/a",
        json=bulk_task([{"http_status": 201, "asset_id": 1}], "COMPLETED_SUCCESSFULLY"),
    )
    outcomes = create_in_bulk(client, [creation(2, "198.51.100.1")], CATALOG, sleep=clock.sleep, clock=clock)
    assert outcomes[0].status == "created"
    assert clock.sleeps == [10.0]


@responses.activate
def test_bulk_timeout(client):
    clock = FakeClock()
    responses.patch(f"{BASE}/asset_model/assets", status=202, headers={"Location": "/x/asset_bulk_tasks/t9"}, json={})
    responses.get(f"{BASE}/asset_model/asset_bulk_tasks/t9", json={"status": "IN_PROGRESS"})
    outcomes = create_in_bulk(
        client, [creation(2, "198.51.100.1")], CATALOG, timeout=12, sleep=clock.sleep, clock=clock
    )
    assert outcomes[0].status == "timeout"
    assert "t9 still in progress" in outcomes[0].message


def test_backup_round_trip(tmp_path):
    path = tmp_path / "safety" / "b.json"
    write_backup(str(path), "qradar.example.lan", [WORKSTATION])
    record_created_assets(str(path), [6001])
    data = read_backup(str(path))
    assert data["host"] == "qradar.example.lan"
    assert data["assets"] == [WORKSTATION]
    assert data["created_asset_ids"] == [6001]


def test_plan_restore():
    changed = {
        **WORKSTATION,
        "properties": [
            {"name": "Unified Name", "type_id": 1002, "value": "ws01.example.lan"},
            {"name": "Business Owner", "type_id": 1005, "value": "IT"},
            {"name": "Given Name", "type_id": 1001, "value": "new"},
        ],
    }
    [item] = plan_restore({"assets": [WORKSTATION, SERVER]}, [changed], PROPERTIES)
    assert [(c.name, c.old, c.new) for c in item.changes] == [("Business Owner", "IT", "SOC")]
    assert item.cannot_clear == ["Given Name"]


@responses.activate
def test_delete_assets(client):
    responses.delete(f"{BASE}/asset_model/assets/6001", status=204)
    responses.delete(f"{BASE}/asset_model/assets/6002", status=404, json={"code": 1002, "message": "not found"})
    responses.delete(f"{BASE}/asset_model/assets/6003", status=403, json={"code": 1009, "message": "no permission"})
    outcomes = delete_assets(client, [6001, 6002, 6003])
    assert [o.status for o in outcomes] == ["deleted", "deleted", "failed"]


TEXT = matchers.header_matcher({"Accept": "text/plain"})


@responses.activate
def test_text_plain_endpoints_ask_for_text(client):
    clock = FakeClock()
    plan = ImportPlan(header=[], property_columns=[])
    plan.updates[2723] = Update(2723, 0, "x", [2], {"Business Owner": PropertyChange("Business Owner", 1005, "", "IT")})
    responses.post(f"{BASE}/asset_model/assets/2723", status=202, body="", match=[TEXT])
    responses.patch(f"{BASE}/asset_model/assets", status=202, body="t7", match=[TEXT])
    responses.get(
        f"{BASE}/asset_model/asset_bulk_tasks/t7",
        json=bulk_task([{"http_status": 201, "asset_id": 9}], "COMPLETED_SUCCESSFULLY"),
        match=[matchers.header_matcher({"Accept": "application/json"})],
    )
    responses.delete(f"{BASE}/asset_model/assets/9", status=204, match=[TEXT])

    assert apply_updates(client, plan)[0].status == "submitted"
    # No Location header: the plain-text body is the task id.
    assert (
        create_in_bulk(client, [creation(2, "198.51.100.1")], CATALOG, sleep=clock.sleep, clock=clock)[0].asset_id == 9
    )
    assert delete_assets(client, [9])[0].status == "deleted"
