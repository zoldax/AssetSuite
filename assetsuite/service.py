"""
service.py

The operations behind the commands, without any printing: read a source of
asset data (NetBox, SevOne, pfSense backups), plan an import against the
QRadar assets and write it, restore a safety backup, run the quality report. The CLI prints their results; the
QRadar App runs them as background jobs and follows them with a Progress.

Each operation is split where the CLI tells the user to wait (prepare, then
run), so both front ends keep control of what they show between the steps.

Copyright 2026 Pascal Weber (zoldax) / Abakus Sécurité
Licensed under the Apache License, Version 2.0 (see LICENSE).
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Sequence, Tuple

import requests

from assetsuite.assets import fetch_assets, list_properties
from assetsuite.capabilities import CREATE_ASSET, DELETE_ASSET, Capabilities, detect_capabilities
from assetsuite.client import QRadarClient
from assetsuite.importer import ImportPlan, ImportRow, Planner
from assetsuite.netbox import NetBoxClient, NetBoxConfig, NetBoxError, load_netbox_config
from assetsuite.netbox import fetch_records as netbox_fetch_records
from assetsuite.netbox import import_rows as netbox_import_rows
from assetsuite.network_hierarchy import (
    NetworkHierarchyError,
    NHIndex,
    check_network_hierarchy,
    load_from_api,
    load_from_nhsuite_csv,
)
from assetsuite.pfsense import PfSenseConfig, PfSenseError, build_records, load_pfsense_config, read_backups
from assetsuite.pfsense import import_rows as pfsense_import_rows
from assetsuite.pfsense import resolve_files as pfsense_resolve_files
from assetsuite.progress import Progress, or_none
from assetsuite.quality import CHECKS as QUALITY_CHECKS
from assetsuite.quality import NH_CHECKS, Finding, ReportOptions, check_assets, sort_findings, summary
from assetsuite.sevone import SevOneClient, SevOneConfig, SevOneError, load_sevone_config
from assetsuite.sevone import fetch_records as sevone_fetch_records
from assetsuite.sevone import import_rows as sevone_import_rows
from assetsuite.system import list_domains
from assetsuite.writer import (
    CREDENTIALS_REFUSED,
    SAFETY_DIR,
    Outcome,
    RestoreItem,
    apply_restore,
    apply_updates,
    backup_path,
    create_in_bulk,
    create_one_by_one,
    delete_assets,
    plan_restore,
    record_created_assets,
    write_backup,
)

logger = logging.getLogger(__name__)


class ServiceError(Exception):
    """Invalid value or configuration, found while preparing an operation."""


def resolve_domain(ref: str, domains: Sequence[dict]) -> int:
    for domain in domains:
        if ref == str(domain.get("id")) or ref.casefold() == str(domain.get("name") or "").casefold():
            return int(domain["id"])
    known = ", ".join(f"{d.get('id')} ({d.get('name')})" for d in domains)
    raise ServiceError(f"Unknown domain '{ref}'. Known domains: {known}")


def check_property_names(names: Sequence[str], known: Sequence[str]) -> None:
    unknown = [name for name in names if name not in known]
    if unknown:
        label = "properties" if len(unknown) > 1 else "property"
        raise ServiceError(f"Unknown asset {label}: {', '.join(unknown)} (see the properties command)")


def property_names(client: QRadarClient) -> List[str]:
    return [str(p.get("name")) for p in list_properties(client)]


# --- Sources of import rows --------------------------------------------------


@dataclass
class SyncSource:
    """Import rows built from another system, with what the user should know about them."""

    header: List[str]
    rows: List[ImportRow]
    domain: str
    read: int  # items read from the source
    kept: int  # items turned into rows
    fill_empty_only: bool = False  # the source only fills empty QRadar properties
    skipped: List[Tuple[str, str]] = field(default_factory=list)  # (item, reason) left aside
    files: List[str] = field(default_factory=list)


def load_netbox(client: QRadarClient) -> NetBoxConfig:
    """The netbox section, its mapping checked against the properties of this QRadar."""
    try:
        config = load_netbox_config(client.config.sections)
    except NetBoxError as e:
        raise ServiceError(str(e)) from e
    check_property_names(list(config.mapping), property_names(client))
    return config


def netbox_source(
    config: NetBoxConfig,
    domain: Optional[str] = None,
    progress: Optional[Progress] = None,
    session: Optional[requests.Session] = None,
) -> SyncSource:
    """session: a requests session with its proxy settings (the App sets one per connector)."""
    try:
        records = netbox_fetch_records(NetBoxClient(config, session=session), progress)
    except NetBoxError as e:
        raise ServiceError(str(e)) from e
    domain = domain if domain is not None else config.domain
    header, rows = netbox_import_rows(records, config, domain)
    return SyncSource(header, rows, domain, read=len(records), kept=len(records))


def load_pfsense(client: QRadarClient) -> PfSenseConfig:
    try:
        config = load_pfsense_config(client.config.sections)
    except PfSenseError as e:
        raise ServiceError(str(e)) from e
    check_property_names(list(config.mapping), property_names(client))
    return config


def pfsense_source(
    config: PfSenseConfig,
    files: Optional[Sequence[str]] = None,
    domain: Optional[str] = None,
    overwrite: bool = False,
    progress: Optional[Progress] = None,
) -> SyncSource:
    progress = or_none(progress)
    progress.phase("pfSense backups")
    try:
        paths = pfsense_resolve_files(files or config.files)
        progress.set_total(len(paths))
        entries = read_backups(paths)
        progress.advance(len(paths))
    except PfSenseError as e:
        raise ServiceError(str(e)) from e
    records = build_records(entries, config)
    domain = domain if domain is not None else config.domain
    header, rows = pfsense_import_rows(records, config, domain)
    return SyncSource(
        header,
        rows,
        domain,
        read=len(entries),
        kept=len(records),
        fill_empty_only=not (overwrite or config.overwrite),
        files=list(paths),
    )


def load_sevone(client: QRadarClient) -> SevOneConfig:
    try:
        config = load_sevone_config(client.config.sections)
    except SevOneError as e:
        raise ServiceError(str(e)) from e
    check_property_names(list(config.mapping), property_names(client))
    return config


def sevone_source(
    config: SevOneConfig,
    domain: Optional[str] = None,
    overwrite: bool = False,
    progress: Optional[Progress] = None,
    session: Optional[requests.Session] = None,
) -> SyncSource:
    client = SevOneClient(config, session=session)
    try:
        devices = sevone_fetch_records(client, progress)
    except SevOneError as e:
        raise ServiceError(str(e)) from e
    finally:
        client.close()  # signs a service account out
    domain = domain if domain is not None else config.domain
    header, rows = sevone_import_rows(devices.records, config, domain)
    return SyncSource(
        header,
        rows,
        domain,
        read=devices.total,
        kept=len(devices.records),
        fill_empty_only=not (overwrite or config.overwrite),
        skipped=list(devices.skipped),
    )


# --- Import plan -------------------------------------------------------------

REPORT_COLUMNS = ["line", "action", "asset_id", "target", "details", "status", "message"]


@dataclass
class ImportContext:
    """What an import needs from QRadar before reading the assets."""

    catalog: List[dict]
    domains: List[dict]
    caps: Capabilities
    default_domain_id: Optional[int]
    can_create: bool
    create_blocked_reason: str


def prepare_import(client: QRadarClient, domain: Optional[str] = None, allow_create: bool = False) -> ImportContext:
    catalog = list_properties(client)
    domains = list_domains(client)
    caps = detect_capabilities(client)
    default_domain = resolve_domain(domain, domains) if domain is not None else None
    if not allow_create:
        can_create, blocked = False, "not created, use --allow-create to create assets QRadar does not know"
    else:
        can_create, reason = caps.check(CREATE_ASSET)
        blocked = f"not created, {reason}" if not can_create else ""
    return ImportContext(catalog, domains, caps, default_domain, can_create, blocked)


def plan_import(
    client: QRadarClient,
    context: ImportContext,
    header: Sequence[str],
    rows: Sequence[ImportRow],
    fill_empty_only: bool = False,
    progress: Optional[Progress] = None,
) -> Tuple[Planner, ImportPlan]:
    """Read the assets and plan the rows against them. Writes nothing."""
    progress = or_none(progress)
    progress.phase("QRadar assets")
    assets = fetch_assets(client, progress=progress)
    progress.phase("Import plan", len(rows))
    planner = Planner(
        assets,
        context.catalog,
        context.domains,
        context.default_domain_id,
        context.can_create,
        context.create_blocked_reason,
        fill_empty_only=fill_empty_only,
    )
    return planner, planner.plan(header, rows, progress)


def changes_text(changes) -> str:
    return "; ".join(f"{c.name}: '{c.old}' -> '{c.new}'" for c in changes)


def report_rows(plan: ImportPlan, outcomes: Sequence[Outcome] = ()) -> List[Dict[str, object]]:
    """One row per planned or done action, for the import report (REPORT_COLUMNS)."""
    updated = {o.asset_id: o for o in outcomes if o.action == "update"}
    created = {o.line: o for o in outcomes if o.action == "create"}
    rows: List[Dict[str, object]] = []
    for u in plan.updates.values():
        outcome = updated.get(u.asset_id)
        rows.append(
            {
                "line": ";".join(str(line) for line in u.lines),
                "action": "update",
                "asset_id": u.asset_id,
                "target": u.label,
                "details": changes_text(u.changes.values()),
                "status": outcome.status if outcome else "planned",
                "message": outcome.message if outcome and outcome.failed else "",
            }
        )
    for c in plan.creations:
        outcome = created.get(c.line)
        rows.append(
            {
                "line": c.line,
                "action": "create",
                "asset_id": outcome.asset_id if outcome else "",
                "target": c.label,
                "details": "; ".join(f"{k}={v}" for k, v in c.properties.items()),
                "status": outcome.status if outcome else "planned",
                "message": outcome.message if outcome and outcome.status != "created" else "",
            }
        )
    rows += [{"line": line, "action": "unchanged", "asset_id": asset_id} for line, asset_id in plan.unchanged]
    rows += [{"line": row.line, "action": "not_found", "message": reason} for row, reason in plan.not_found]
    rows += [
        {"line": line, "action": "skipped", "asset_id": asset_id, "message": reason}
        for line, asset_id, reason in plan.skipped
    ]
    rows += [{"line": issue.line, "action": "error", "message": issue.message} for issue in plan.errors]
    return sorted(rows, key=lambda r: int(str(r["line"]).split(";")[0] or 0))


# --- Writes ------------------------------------------------------------------


def _fingerprint(items: list) -> str:
    return hashlib.sha256(json.dumps(items, sort_keys=True, default=str).encode()).hexdigest()


def plan_fingerprint(plan: ImportPlan) -> str:
    """
    SHA-256 of what a plan would write. The old values are part of it: an asset
    changed in QRadar since a dry run gives another fingerprint, so a write
    can be refused unless it is exactly the one that was reviewed.
    """
    items: list = [
        ["update", u.asset_id, sorted([c.name, c.old, c.new] for c in u.changes.values())]
        for u in sorted(plan.updates.values(), key=lambda u: u.asset_id)
    ]
    items += [
        ["create", c.line, c.domain_id, c.ips, c.mac, c.dns, c.netbios, sorted(c.properties.items())]
        for c in plan.creations
    ]
    return _fingerprint(items)


def safety_backup(client: QRadarClient, planner: Planner, plan: ImportPlan, directory: str = SAFETY_DIR) -> str:
    """Save the assets a plan updates, before writing. Returns the path; raises OSError if it cannot be written."""
    host = client.config.host
    path = backup_path(host, directory)
    write_backup(path, host, [planner.by_id[asset_id] for asset_id in plan.updates])
    return path


@dataclass
class ApplyOutcome:
    outcomes: List[Outcome]
    created_ids: List[int]
    stopped: bool  # the user asked to stop: some planned writes were not sent

    @property
    def failed(self) -> List[Outcome]:
        return [o for o in self.outcomes if o.failed]

    @property
    def credentials_refused(self) -> bool:
        """QRadar refused the token or session (HTTP 401) and the writes stopped there."""
        return any(o.http_status == CREDENTIALS_REFUSED for o in self.outcomes)

    def counts(self) -> Dict[str, int]:
        """'<action> <status>' -> number of outcomes, e.g. 'update submitted': 3."""
        counts: Dict[str, int] = {}
        for outcome in self.outcomes:
            key = f"{outcome.action} {outcome.status}"
            counts[key] = counts.get(key, 0) + 1
        return counts


def write_plan(
    client: QRadarClient,
    context: ImportContext,
    plan: ImportPlan,
    backup: Optional[str] = None,
    bulk_size: int = 100,
    progress: Optional[Progress] = None,
) -> ApplyOutcome:
    """
    Send the updates, then the creations, of a plan. The caller checks the plan
    (invalid rows, rights) and makes the safety backup first; the assets created
    are added to that backup, so a restore can delete them.
    """
    progress = or_none(progress)
    progress.phase("Property updates", len(plan.updates))
    outcomes = apply_updates(client, plan, progress)
    created_ids: List[int] = []
    if plan.creations and len(outcomes) == len(plan.updates):
        progress.phase("Asset creations", len(plan.creations))
        catalog_by_name = {str(p["name"]): p for p in context.catalog}
        if context.caps.can_bulk_assets:
            progress.note(f"Creating {len(plan.creations)} assets in bulk, this can take a few minutes...")
            outcomes += create_in_bulk(client, plan.creations, catalog_by_name, chunk_size=bulk_size, progress=progress)
        else:
            domain_names = {int(d["id"]): str(d.get("name") or "") for d in context.domains}
            outcomes += create_one_by_one(client, plan.creations, catalog_by_name, domain_names, progress)
        created_ids = [o.asset_id for o in outcomes if o.action == "create" and o.status == "created" and o.asset_id]
        if backup and created_ids:
            record_created_assets(backup, created_ids)
    stopped = len(outcomes) < len(plan.updates) + len(plan.creations)
    return ApplyOutcome(outcomes, created_ids, stopped)


@dataclass
class RestorePlan:
    backup: dict
    items: List[RestoreItem]
    created: List[int]  # assets created by the import
    missing: List[int]  # assets of the backup gone since
    delete_blocked: str = ""  # why the created assets cannot be deleted, when that was asked

    @property
    def asset_ids(self) -> List[int]:
        return [int(a["id"]) for a in self.backup["assets"]]

    @property
    def to_restore(self) -> List[RestoreItem]:
        return [item for item in self.items if item.changes]


def prepare_restore(client: QRadarClient, backup: dict, delete_created: bool = False) -> RestorePlan:
    """What a restore of a backup would change, read from the current assets. Writes nothing."""
    if backup.get("host") != client.config.host:
        raise ServiceError(f"The backup was made on {backup.get('host')}, not on {client.config.host}")
    ids = [int(a["id"]) for a in backup["assets"]]
    current = fetch_assets(client, asset_ids=ids) if ids else []
    items = plan_restore(backup, current, list_properties(client))
    created = [int(i) for i in backup.get("created_asset_ids", [])]
    missing = sorted(set(ids) - {int(a["id"]) for a in current})
    blocked = ""
    if delete_created and created:
        caps = detect_capabilities(client)
        if not caps.can_delete_assets:
            blocked = caps.check(DELETE_ASSET)[1]
    return RestorePlan(backup, items, created, missing, blocked)


def restore_fingerprint(plan: RestorePlan, delete_created: bool) -> str:
    items: list = [
        ["update", item.asset_id, sorted([c.name, c.old, c.new] for c in item.changes)] for item in plan.to_restore
    ]
    if delete_created:
        items += [["delete", asset_id] for asset_id in sorted(plan.created)]
    return _fingerprint(items)


def run_restore(
    client: QRadarClient, plan: RestorePlan, delete_created: bool = False, progress: Optional[Progress] = None
) -> ApplyOutcome:
    if delete_created and plan.created and plan.delete_blocked:
        raise ServiceError(f"Cannot delete assets: {plan.delete_blocked}")
    progress = or_none(progress)
    to_restore = plan.to_restore
    progress.phase("Restore", len(to_restore))
    outcomes = apply_restore(client, to_restore, progress)
    expected = len(to_restore)
    if delete_created and plan.created and len(outcomes) == len(to_restore):
        progress.phase("Delete created assets", len(plan.created))
        outcomes += delete_assets(client, plan.created, progress)
        expected += len(plan.created)
    return ApplyOutcome(outcomes, [], len(outcomes) < expected)


# --- Quality report ----------------------------------------------------------

REPORT_FINDING_COLUMNS = ["severity", "check", "asset_id", "domain_id", "target", "names", "detail"]


def parse_checks(value: str) -> List[str]:
    names = [name.strip() for name in value.split(",") if name.strip()]
    unknown = [name for name in names if name not in QUALITY_CHECKS]
    if unknown:
        raise ServiceError(f"Unknown check(s): {', '.join(unknown)}. Checks: {', '.join(QUALITY_CHECKS)}")
    return names


@dataclass
class ReportSetup:
    enabled: List[str]
    options: ReportOptions
    domain_id: Optional[int]


def prepare_report(
    client: QRadarClient,
    checks: Optional[Sequence[str]] = None,
    skip: Sequence[str] = (),
    no_nh: bool = False,
    owner_properties: Optional[Sequence[str]] = None,
    stale_days: int = ReportOptions.stale_days,
    catch_all_groups: Sequence[str] = (),
    domain: Optional[str] = None,
) -> ReportSetup:
    """The checks to run and their options, validated against this QRadar."""
    enabled = list(checks) if checks else list(QUALITY_CHECKS)
    skipped = list(skip) + (list(NH_CHECKS) if no_nh else [])
    enabled = [name for name in enabled if name not in skipped]
    if not enabled:
        raise ServiceError("No check left to run")

    known_properties = property_names(client)
    if owner_properties:
        owners = list(owner_properties)
        check_property_names(owners, known_properties)
    else:
        # Default owner properties missing from this QRadar are ignored rather than refused.
        owners = [name for name in ReportOptions.owner_properties if name in known_properties]
        if not owners and "no-owner" in enabled:
            logger.warning("No owner property on this QRadar: no-owner check skipped")
            enabled = [name for name in enabled if name != "no-owner"]
    options = ReportOptions(stale_days=stale_days, owner_properties=owners, catch_all_groups=catch_all_groups)
    domains = list_domains(client)
    domain_id = resolve_domain(domain, domains) if domain is not None else None
    return ReportSetup(enabled, options, domain_id)


@dataclass
class ReportOutcome:
    setup: ReportSetup
    assets: int
    findings: List[Finding]
    networks: Optional[int] = None  # Network Hierarchy networks checked, None without NH checks
    nh_source: str = ""


def run_report(
    client: QRadarClient, setup: ReportSetup, nh_file: Optional[str] = None, progress: Optional[Progress] = None
) -> ReportOutcome:
    progress = or_none(progress)
    enabled, options = set(setup.enabled), setup.options
    progress.phase("QRadar assets")
    assets = fetch_assets(client, setup.domain_id, progress=progress)
    progress.phase("Asset checks", len(assets))
    findings = check_assets(assets, options, enabled, progress)

    outcome = ReportOutcome(setup, len(assets), findings)
    if any(name in NH_CHECKS for name in setup.enabled):
        progress.phase("Network Hierarchy")
        try:
            networks = load_from_nhsuite_csv(nh_file) if nh_file else load_from_api(client)
        except NetworkHierarchyError as e:
            raise ServiceError(str(e)) from e
        groups = {n.group for n in networks}
        for group in options.catch_all_groups:
            if not any(g == group or g.startswith(group + ".") for g in groups):
                logger.warning("Catch-all group '%s' is not in the Network Hierarchy", group)
        nh_findings = check_network_hierarchy(assets, NHIndex(networks), options, enabled)
        if setup.domain_id is not None:
            nh_findings = [
                f for f in nh_findings if f.check != "empty-network" or f.domain_id in (None, setup.domain_id)
            ]
        findings += nh_findings
        outcome.networks, outcome.nh_source = len(networks), nh_file or "QRadar"
    outcome.findings = sort_findings(findings)
    return outcome


def finding_rows(findings: Sequence[Finding]) -> Iterator[Dict[str, object]]:
    return ({column: getattr(f, column) for column in REPORT_FINDING_COLUMNS} for f in findings)


def report_payload(host: str, outcome: ReportOutcome) -> dict:
    """The JSON form of a report."""
    setup = outcome.setup
    return {
        "host": host,
        "assets": outcome.assets,
        "options": {
            "stale_days": setup.options.stale_days,
            "owner_properties": list(setup.options.owner_properties),
            "catch_all_groups": list(setup.options.catch_all_groups),
            "checks": setup.enabled,
        },
        "summary": {name: count for name, count in summary(outcome.findings).items() if name in setup.enabled},
        "findings": list(finding_rows(outcome.findings)),
    }
