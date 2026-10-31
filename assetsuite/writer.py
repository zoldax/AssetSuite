"""
writer.py

Applies an import plan to QRadar: safety backup, property updates, creation
of missing assets (bulk PATCH on API 29.0+, one POST per asset on 24.0+), and
the restore of a backup.

Both property updates and bulk creations are asynchronous in QRadar: an
update is accepted (202) and applied later by the asset profiler, a bulk
creation returns a task that is polled until it completes.

Each loop takes an optional Progress: one item done per asset (per chunk in
bulk), and a stop asked only before the next asset or chunk is sent, never
while QRadar works on a bulk task. A stopped loop returns the outcomes of what
was sent, so the caller can report and back up exactly that.

Copyright 2026 Pascal Weber (zoldax) / Abakus Sécurité
Licensed under the Apache License, Version 2.0 (see LICENSE).
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Dict, List, Mapping, Optional, Sequence

from assetsuite.assets import property_values
from assetsuite.client import QRadarAPIError, QRadarClient
from assetsuite.importer import Creation, ImportPlan, PropertyChange, creation_payload
from assetsuite.progress import Progress, or_none, stop_requested

logger = logging.getLogger(__name__)

SAFETY_DIR = "safety"
BULK_TASK_DONE = ("COMPLETED_SUCCESSFULLY", "COMPLETED_WITH_ERRORS")
BULK_TOO_LARGE_CODE = 1002
BULK_RATE_LIMIT_RETRIES = 3
BULK_RATE_LIMIT_WAIT = 10.0
MIN_POLL_INTERVAL = 5.0  # recommended by the API documentation
# The property update, bulk PATCH and DELETE endpoints only answer in text/plain:
# QRadar refuses them with HTTP 406 when the request asks for JSON.
TEXT_RESPONSE = {"Accept": "text/plain"}


@dataclass
class Outcome:
    line: Optional[int]
    action: str  # update | create | delete
    asset_id: Optional[int]
    status: str  # submitted | created | reconciled | deleted | failed | timeout
    message: str = ""

    @property
    def failed(self) -> bool:
        return self.status in ("failed", "timeout")


# --- Backup ------------------------------------------------------------------


def backup_path(host: str, directory: str = SAFETY_DIR) -> str:
    return os.path.join(directory, f"backup-before-import-{host}-{datetime.now().strftime('%Y%m%d%H%M%S')}.json")


def write_backup(path: str, host: str, assets: Sequence[Mapping]) -> None:
    """Assets before the import, as returned by QRadar. Raises OSError if it cannot be written."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    data = {
        "host": host,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "assets": list(assets),
        "created_asset_ids": [],
    }
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)
        file.write("\n")


def record_created_assets(path: str, asset_ids: Sequence[int]) -> None:
    with open(path, encoding="utf-8") as file:
        data = json.load(file)
    data["created_asset_ids"] = sorted(set(data.get("created_asset_ids", [])) | set(asset_ids))
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)
        file.write("\n")


def read_backup(path: str) -> dict:
    with open(path, encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, dict) or not isinstance(data.get("assets"), list):
        raise ValueError(f"{path} is not an AssetSuite backup")
    return data


# --- Updates -----------------------------------------------------------------


def update_properties(client: QRadarClient, asset_id: int, changes: Sequence[PropertyChange]) -> None:
    body = {"properties": [{"type_id": change.type_id, "value": change.new} for change in changes]}
    client.request("POST", f"asset_model/assets/{asset_id}", json_body=body, headers=TEXT_RESPONSE)


def apply_updates(client: QRadarClient, plan: ImportPlan, progress: Optional[Progress] = None) -> List[Outcome]:
    progress = or_none(progress)
    outcomes = []
    for update in plan.updates.values():
        if stop_requested(progress):
            break
        line = update.lines[0] if update.lines else None
        names = ", ".join(update.changes)
        try:
            update_properties(client, update.asset_id, list(update.changes.values()))
            outcomes.append(Outcome(line, "update", update.asset_id, "submitted", names))
        except QRadarAPIError as e:
            logger.error("Update of asset %s failed: %s", update.asset_id, e)
            outcomes.append(Outcome(line, "update", update.asset_id, "failed", str(e)))
        progress.advance()
    return outcomes


# --- Creations ---------------------------------------------------------------


def create_one_by_one(
    client: QRadarClient,
    creations: Sequence[Creation],
    catalog: Mapping[str, Mapping],
    domains: Mapping[int, str],
    progress: Optional[Progress] = None,
) -> List[Outcome]:
    """POST /asset_model/assets per asset (API 24.0+). 201 = created, 200 = reconciled with an existing asset."""
    progress = or_none(progress)
    outcomes = []
    for creation in creations:
        if stop_requested(progress):
            break
        try:
            response = client.request(
                "POST", "asset_model/assets", json_body=creation_payload(creation, catalog, domains, bulk=False)
            )
            body = response.json() if response.content else {}
            status = "reconciled" if response.status_code == 200 else "created"
            outcomes.append(Outcome(creation.line, "create", body.get("id"), status, creation.label))
        except (QRadarAPIError, ValueError) as e:
            logger.error("Creation from line %s failed: %s", creation.line, e)
            outcomes.append(Outcome(creation.line, "create", None, "failed", str(e)))
        progress.advance()
    return outcomes


def _task_id(response) -> Optional[str]:
    location = response.headers.get("Location", "")
    if location:
        return location.rstrip("/").rsplit("/", 1)[-1]
    text = response.text.strip()
    try:
        body = json.loads(text)
    except ValueError:
        # text/plain body: the task id itself.
        return text if text and len(text) < 128 and " " not in text else None
    if isinstance(body, dict) and body.get("id"):
        return str(body["id"])
    return str(body) if isinstance(body, (str, int)) and str(body) else None


def create_in_bulk(
    client: QRadarClient,
    creations: Sequence[Creation],
    catalog: Mapping[str, Mapping],
    chunk_size: int = 100,
    poll_interval: float = MIN_POLL_INTERVAL,
    timeout: float = 600.0,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    progress: Optional[Progress] = None,
) -> List[Outcome]:
    """
    PATCH /asset_model/assets (API 29.0+), then poll the bulk task.

    The maximum list size is not documented: a chunk refused as too large
    (422 code 1002) is split in two and sent again.
    """
    progress = or_none(progress)
    outcomes: List[Outcome] = []
    queue = [list(creations[i : i + chunk_size]) for i in range(0, len(creations), chunk_size)]
    while queue:
        if stop_requested(progress):
            break
        chunk = queue.pop(0)
        body = [creation_payload(c, catalog, {}, bulk=True) for c in chunk]
        try:
            response = _submit_bulk(client, body, sleep)
        except QRadarAPIError as e:
            if e.status == 422 and e.code == BULK_TOO_LARGE_CODE and len(chunk) > 1:
                half = len(chunk) // 2
                logger.warning("Bulk of %d assets refused as too large, retrying by %d", len(chunk), half)
                queue[0:0] = [chunk[:half], chunk[half:]]
                continue
            outcomes.extend(Outcome(c.line, "create", None, "failed", str(e)) for c in chunk)
            progress.advance(len(chunk))
            continue

        task_id = _task_id(response)
        if not task_id:
            outcomes.extend(Outcome(c.line, "create", None, "failed", "QRadar returned no bulk task id") for c in chunk)
        else:
            outcomes.extend(
                _wait_bulk_task(client, task_id, chunk, max(poll_interval, MIN_POLL_INTERVAL), timeout, sleep, clock)
            )
        progress.advance(len(chunk))
    return outcomes


def _submit_bulk(client: QRadarClient, body: list, sleep: Callable[[float], None]):
    for attempt in range(BULK_RATE_LIMIT_RETRIES + 1):
        try:
            return client.request("PATCH", "asset_model/assets", json_body=body, headers=TEXT_RESPONSE)
        except QRadarAPIError as e:
            if e.status != 429 or attempt == BULK_RATE_LIMIT_RETRIES:
                raise
            logger.warning("Bulk request rate limited, waiting %.0f s", BULK_RATE_LIMIT_WAIT)
            sleep(BULK_RATE_LIMIT_WAIT)
    raise AssertionError("unreachable")


def _wait_bulk_task(
    client: QRadarClient,
    task_id: str,
    chunk: Sequence[Creation],
    poll_interval: float,
    timeout: float,
    sleep: Callable[[float], None],
    clock: Callable[[], float],
) -> List[Outcome]:
    start = clock()
    while True:
        try:
            task = client.get(f"asset_model/asset_bulk_tasks/{task_id}") or {}
        except QRadarAPIError as e:
            return [Outcome(c.line, "create", None, "failed", f"bulk task {task_id}: {e}") for c in chunk]
        if task.get("status") in BULK_TASK_DONE:
            break
        if clock() - start >= timeout:
            message = f"bulk task {task_id} still in progress after {timeout:.0f} s: check it later in QRadar"
            return [Outcome(c.line, "create", None, "timeout", message) for c in chunk]
        sleep(poll_interval)

    statuses = task.get("operation_statuses") or []
    outcomes = []
    for index, creation in enumerate(chunk):
        op = statuses[index] if index < len(statuses) else {}
        http_status = op.get("http_status")
        if http_status == 201:
            status = "created"
        elif http_status == 200:
            status = "reconciled"
        else:
            status = "failed"
        message = op.get("message") or (f"no status returned by bulk task {task_id}" if not op else "")
        if op.get("unique_code"):
            message = f"{message} (code {op['unique_code']})"
        outcomes.append(Outcome(creation.line, "create", op.get("asset_id"), status, message or creation.label))
    return outcomes


# --- Restore -----------------------------------------------------------------


@dataclass
class RestoreItem:
    asset_id: int
    changes: List[PropertyChange]
    cannot_clear: List[str]  # properties set since the backup: the API cannot empty them


def plan_restore(backup: Mapping, current_assets: Sequence[Mapping], catalog: Sequence[Mapping]) -> List[RestoreItem]:
    """Property changes that bring the current assets back to their values in the backup."""
    type_ids = {str(p["name"]): int(p["id"]) for p in catalog}
    current: Dict[int, Mapping] = {int(a["id"]): a for a in current_assets}
    items = []
    for before in backup.get("assets", []):
        asset_id = int(before["id"])
        now = current.get(asset_id)
        if now is None:
            continue
        old_values, new_values = property_values(before), property_values(now)
        changes = [
            PropertyChange(name, type_ids[name], new_values.get(name, ""), value)
            for name, value in old_values.items()
            if value and name in type_ids and new_values.get(name, "") != value
        ]
        cannot_clear = [name for name, value in new_values.items() if value and not old_values.get(name)]
        if changes or cannot_clear:
            items.append(RestoreItem(asset_id, changes, cannot_clear))
    return items


def apply_restore(
    client: QRadarClient, items: Sequence[RestoreItem], progress: Optional[Progress] = None
) -> List[Outcome]:
    progress = or_none(progress)
    outcomes = []
    for item in items:
        if not item.changes:
            continue
        if stop_requested(progress):
            break
        try:
            update_properties(client, item.asset_id, item.changes)
            outcomes.append(
                Outcome(None, "update", item.asset_id, "submitted", ", ".join(c.name for c in item.changes))
            )
        except QRadarAPIError as e:
            outcomes.append(Outcome(None, "update", item.asset_id, "failed", str(e)))
        progress.advance()
    return outcomes


def delete_assets(client: QRadarClient, asset_ids: Sequence[int], progress: Optional[Progress] = None) -> List[Outcome]:
    progress = or_none(progress)
    outcomes = []
    for asset_id in asset_ids:
        if stop_requested(progress):
            break
        try:
            client.request("DELETE", f"asset_model/assets/{int(asset_id)}", headers=TEXT_RESPONSE)
            outcomes.append(Outcome(None, "delete", asset_id, "deleted"))
        except QRadarAPIError as e:
            status = "deleted" if e.status == 404 else "failed"  # already gone
            outcomes.append(Outcome(None, "delete", asset_id, status, str(e)))
        progress.advance()
    return outcomes
