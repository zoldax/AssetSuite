"""
cli.py

Command-line interface of AssetSuite.

Copyright 2026 Pascal Weber (zoldax) / Abakus Sécurité
Licensed under the Apache License, Version 2.0 (see LICENSE).
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import sys
from typing import Dict, List, Optional, Sequence

from assetsuite import __version__
from assetsuite.assets import (
    AssetFilter,
    IPNetwork,
    LookupFailed,
    asset_rows,
    export_columns,
    fetch_assets,
    find_saved_search,
    list_properties,
    list_saved_searches,
    saved_search_asset_ids,
)
from assetsuite.capabilities import CREATE_ASSET, DELETE_ASSET, FEATURES, UPDATE_ASSET, detect_capabilities
from assetsuite.client import QRadarAPIError, QRadarClient
from assetsuite.config import Config, ConfigError, load_config
from assetsuite.export import default_export_path, write_csv, write_json
from assetsuite.importer import ImportFileError, ImportPlan, ImportRow, Planner, read_import_file
from assetsuite.netbox import NetBoxClient, NetBoxError, fetch_records, load_netbox_config
from assetsuite.netbox import import_rows as netbox_import_rows
from assetsuite.network_hierarchy import (
    NetworkHierarchyError,
    NHIndex,
    check_network_hierarchy,
    load_from_api,
    load_from_nhsuite_csv,
)
from assetsuite.pfsense import PfSenseError, build_records, load_pfsense_config, read_backups, resolve_files
from assetsuite.pfsense import import_rows as pfsense_import_rows
from assetsuite.quality import (
    CHECKS as QUALITY_CHECKS,
)
from assetsuite.quality import (
    NH_CHECKS,
    SEVERITIES,
    Finding,
    ReportOptions,
    check_assets,
    severity_rank,
    sort_findings,
    summary,
)
from assetsuite.sevone import SevOneClient, SevOneError, load_sevone_config
from assetsuite.sevone import fetch_records as sevone_fetch_records
from assetsuite.sevone import import_rows as sevone_import_rows
from assetsuite.system import get_system_about, list_domains
from assetsuite.writer import (
    Outcome,
    apply_restore,
    apply_updates,
    backup_path,
    create_in_bulk,
    create_one_by_one,
    delete_assets,
    plan_restore,
    read_backup,
    record_created_assets,
    write_backup,
)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONFIG = 2
EXIT_FINDINGS = 3

logger = logging.getLogger("assetsuite")


class UsageError(Exception):
    """Invalid command-line value, detected after argument parsing."""


def setup_logging(config: Config, verbose: bool) -> None:
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    file_handler = logging.FileHandler(config.log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(message)s"))
    logger.addHandler(file_handler)

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if verbose else logging.WARNING)
    console.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger.addHandler(console)


def cmd_check_version(client: QRadarClient) -> int:
    about = get_system_about(client)
    print(f"QRadar System Information: {client.config.host}")
    for key in ("release_name", "build_version", "fips_enabled", "external_version"):
        print(f"{key}: {about.get(key, 'N/A')}")
    return EXIT_OK


def cmd_check_domains(client: QRadarClient) -> int:
    for domain in list_domains(client):
        print(
            f"Domain ID: {domain.get('id', 'N/A')}, "
            f"Domain Name: {domain.get('name') or 'N/A'}, "
            f"Description: {domain.get('description') or 'N/A'}"
        )
    return EXIT_OK


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"


def cmd_check_api(client: QRadarClient) -> int:
    caps = detect_capabilities(client)
    print(f"QRadar API: {client.config.host}")
    if caps.api_versions:
        print(f"Supported API versions: {caps.api_versions[0]} -> {caps.latest_version}")
    print(f"API version used: {caps.configured_version or f'latest ({caps.latest_version})'}")
    if caps.configured_version and caps.configured_version not in caps.api_versions:
        print(f"WARNING: configured api_version {caps.configured_version} is not offered by this QRadar")

    print("\nAsset model endpoints:")
    if not caps.asset_endpoints:
        print("  (none found)")
    width = max((len(path) for _, path in caps.asset_endpoints), default=0)
    version = caps.effective_version
    for endpoint in caps.asset_endpoints.values():
        flags = []
        if endpoint.deprecated.get(version):
            flags.append("deprecated")
        if version in endpoint.access and not endpoint.access[version]:
            flags.append("no access")
        suffix = f"  [{', '.join(flags)}]" if flags else ""
        print(f"  {endpoint.method:<6} {endpoint.path:<{width}}  versions {endpoint.version_range}{suffix}")

    print(f"\nCapabilities with API {version}:")
    label_width = max(len(feature.label) for feature in FEATURES) + 4
    for feature in FEATURES:
        available, reason = caps.check(feature)
        print(
            f"  {(feature.label + ' ').ljust(label_width, '.')} {_yes_no(available)}{f' ({reason})' if reason else ''}"
        )
    if not caps.can_create_assets:
        print("\nAssets unknown to QRadar will be reported by the import, not created.")
    return EXIT_OK


CHECKS = {"version": cmd_check_version, "domains": cmd_check_domains, "api": cmd_check_api}


def _print_table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> None:
    cells = [[str(value) for value in row] for row in rows]
    widths = [max([len(header)] + [len(row[i]) for row in cells]) for i, header in enumerate(headers)]
    print("  ".join(header.ljust(width) for header, width in zip(headers, widths)).rstrip())
    print("  ".join("-" * width for width in widths))
    for row in cells:
        print("  ".join(value.ljust(width) for value, width in zip(row, widths)).rstrip())


def cmd_properties(client: QRadarClient, args: argparse.Namespace) -> int:
    rows = [
        (p.get("id"), p.get("name"), p.get("data_type"), "custom" if p.get("custom") else "")
        for p in list_properties(client)
    ]
    _print_table(("ID", "Name", "Type", "Custom"), rows)
    return EXIT_OK


def cmd_saved_searches(client: QRadarClient, args: argparse.Namespace) -> int:
    rows = []
    for search in sorted(list_saved_searches(client), key=lambda s: s.get("id") or 0):
        filters = "; ".join(
            f"{f.get('parameter')} {str(f.get('operator', '')).lower()} {f.get('value')}"
            for f in search.get("filters") or []
        )
        rows.append(
            (
                search.get("id"),
                search.get("name"),
                search.get("owner"),
                "yes" if search.get("is_shared") else "no",
                filters,
            )
        )
    _print_table(("ID", "Name", "Owner", "Shared", "Filters"), rows)
    return EXIT_OK


def _resolve_domain(ref: str, domains: Sequence[dict]) -> int:
    for domain in domains:
        if ref == str(domain.get("id")) or ref.casefold() == str(domain.get("name") or "").casefold():
            return int(domain["id"])
    known = ", ".join(f"{d.get('id')} ({d.get('name')})" for d in domains)
    raise UsageError(f"Unknown domain '{ref}'. Known domains: {known}")


def _check_property_names(names: Sequence[str], known: Sequence[str]) -> None:
    unknown = [name for name in names if name not in known]
    if unknown:
        label = "properties" if len(unknown) > 1 else "property"
        raise UsageError(f"Unknown asset {label}: {', '.join(unknown)} (see the properties command)")


def _parse_networks(values: Sequence[str]) -> List[IPNetwork]:
    try:
        return [ipaddress.ip_network(value, strict=False) for value in values]
    except ValueError as e:
        raise UsageError(f"Invalid --cidr value: {e}") from e


def _parse_property_filters(values: Sequence[str]) -> Dict[str, str]:
    filters = {}
    for value in values:
        name, separator, expected = value.partition("=")
        if not separator or not name.strip():
            raise UsageError(f"--property expects NAME=VALUE (NAME= for an empty value), got '{value}'")
        filters[name.strip()] = expected.strip()
    return filters


def cmd_export(client: QRadarClient, args: argparse.Namespace) -> int:
    output_format = args.format or ("json" if args.output and args.output.lower().endswith(".json") else "csv")
    output = args.output or default_export_path(client.config.host, output_format)

    known_properties = [str(p.get("name")) for p in list_properties(client)]
    property_columns = (
        [name.strip() for name in args.properties.split(",") if name.strip()]
        if args.properties is not None
        else known_properties
    )
    property_filters = _parse_property_filters(args.property)
    _check_property_names(property_columns, known_properties)
    _check_property_names(list(property_filters), known_properties)

    asset_filter = AssetFilter(
        networks=_parse_networks(args.cidr),
        seen_within_days=args.seen_within,
        not_seen_for_days=args.not_seen_for,
        properties=property_filters,
    )

    domains = list_domains(client)
    domain_names = {int(d["id"]): str(d.get("name") or "") for d in domains if d.get("id") is not None}
    domain_id = _resolve_domain(args.domain, domains) if args.domain is not None else None

    asset_ids = None
    if args.saved_search is not None:
        search = find_saved_search(client, args.saved_search)
        asset_ids = saved_search_asset_ids(client, int(search["id"]))
        print(f"Saved search {search['id']} '{search.get('name')}': {len(asset_ids)} assets")

    print("Please wait... exporting assets.")
    assets = fetch_assets(client, domain_id, asset_ids) if asset_ids is None or asset_ids else []
    selected = sorted((a for a in assets if asset_filter.matches(a)), key=lambda a: a.get("id") or 0)
    logger.info("Export: %d assets fetched, %d selected", len(assets), len(selected))

    if output_format == "json":
        write_json(output, selected)
        print(f"{len(selected)} assets exported to {output}")
        return EXIT_OK

    columns = export_columns(property_columns, args.per_ip)
    rows = (
        row
        for asset in selected
        for row in asset_rows(asset, property_columns, domain_names, args.per_ip, asset_filter)
    )
    count = write_csv(output, columns, rows, delimiter=args.delimiter)
    suffix = f" ({count} rows, one per IP)" if args.per_ip else ""
    print(f"{len(selected)} assets exported to {output}{suffix}")
    return EXIT_OK


DETAIL_LIMIT = 20
REPORT_COLUMNS = ["line", "action", "asset_id", "target", "details", "status", "message"]


def _limited(items: Sequence, verbose: bool) -> Sequence:
    return items if verbose else items[:DETAIL_LIMIT]


def _more(items: Sequence, verbose: bool) -> None:
    if not verbose and len(items) > DETAIL_LIMIT:
        print(f"    ... and {len(items) - DETAIL_LIMIT} more (see the report, or use -v)")


def _changes_text(changes) -> str:
    return "; ".join(f"{c.name}: '{c.old}' -> '{c.new}'" for c in changes)


def _print_plan(plan: ImportPlan, rows: int, verbose: bool) -> None:
    changes = sum(len(u.changes) for u in plan.updates.values())
    print(f"\nImport plan ({rows} rows):")
    print(f"  Assets to update ...... {len(plan.updates)} ({changes} property changes)")
    print(f"  Assets to create ...... {len(plan.creations)}")
    print(f"  Unchanged rows ........ {len(plan.unchanged)}")
    print(f"  Assets not found ...... {len(plan.not_found)}")
    print(f"  Assets skipped ........ {len(plan.skipped)}")
    print(f"  Invalid rows .......... {len(plan.errors)}")

    updates = list(plan.updates.values())
    if updates:
        print("\nUpdates:")
        for u in _limited(updates, verbose):
            print(f"  line {u.lines[0]:<5} asset {u.asset_id} ({u.label}): {_changes_text(u.changes.values())}")
        _more(updates, verbose)
    if plan.creations:
        print("\nCreations:")
        for c in _limited(plan.creations, verbose):
            props = ", ".join(f"{k}={v}" for k, v in c.properties.items())
            print(f"  line {c.line:<5} {c.label} in domain {c.domain_id}{f' ({props})' if props else ''}")
        _more(plan.creations, verbose)
    if plan.not_found:
        reasons = sorted({reason for _, reason in plan.not_found})
        print(f"\nAssets not found: {'; '.join(reasons)}")
    if plan.skipped:
        print("\nSkipped (QRadar cannot update these assets):")
        for line, asset_id, reason in _limited(plan.skipped, verbose):
            print(f"  line {line:<5} asset {asset_id}: {reason}")
        _more(plan.skipped, verbose)
    if plan.errors:
        print("\nInvalid rows:")
        for issue in _limited(plan.errors, verbose):
            print(f"  line {issue.line:<5} {issue.message}")
        _more(plan.errors, verbose)


def _report_rows(plan: ImportPlan, outcomes: Sequence[Outcome] = ()) -> List[Dict[str, object]]:
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
                "details": _changes_text(u.changes.values()),
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


def cmd_import(client: QRadarClient, args: argparse.Namespace) -> int:
    header, rows = read_import_file(args.file, args.delimiter)
    return run_import(client, args, header, rows)


def cmd_netbox_sync(client: QRadarClient, args: argparse.Namespace) -> int:
    try:
        nb_config = load_netbox_config(client.config.sections)
        properties = [str(p.get("name")) for p in list_properties(client)]
        _check_property_names(list(nb_config.mapping), properties)
        print(f"Please wait... reading NetBox {nb_config.url}.")
        records = fetch_records(NetBoxClient(nb_config))
    except NetBoxError as e:
        raise UsageError(str(e)) from e
    domain = args.domain if args.domain is not None else nb_config.domain
    header, rows = netbox_import_rows(records, nb_config, domain)
    print(f"{len(records)} NetBox IP addresses (status {', '.join(nb_config.statuses) or 'any'}) -> domain {domain}")
    if args.save_csv:
        write_csv(args.save_csv, header, (row.values for row in rows))
        print(f"Import rows saved to {args.save_csv}")
    # The rows already carry their domain.
    args.domain = None
    return run_import(client, args, header, rows)


def cmd_pfsense_sync(client: QRadarClient, args: argparse.Namespace) -> int:
    try:
        pf_config = load_pfsense_config(client.config.sections)
        properties = [str(p.get("name")) for p in list_properties(client)]
        _check_property_names(list(pf_config.mapping), properties)
        files = resolve_files(args.file or pf_config.files)
        entries = read_backups(files)
    except PfSenseError as e:
        raise UsageError(str(e)) from e
    records = build_records(entries, pf_config)
    domain = args.domain if args.domain is not None else pf_config.domain
    header, rows = pfsense_import_rows(records, pf_config, domain)
    networks = ", ".join(map(str, pf_config.networks)) or "all networks"
    print(
        f"{len(entries)} pfSense IP addresses in {len(files)} file(s), "
        f"{len(records)} kept ({networks}) -> domain {domain}"
    )
    overwrite = args.overwrite or pf_config.overwrite
    if not overwrite:
        print("pfSense only fills empty properties (--overwrite to replace QRadar values)")
    if args.save_csv:
        write_csv(args.save_csv, header, (row.values for row in rows))
        print(f"Import rows saved to {args.save_csv}")
    args.domain = None
    args.fill_empty_only = args.fill_empty_only or not overwrite
    return run_import(client, args, header, rows)


def cmd_sevone_sync(client: QRadarClient, args: argparse.Namespace) -> int:
    try:
        so_config = load_sevone_config(client.config.sections)
        properties = [str(p.get("name")) for p in list_properties(client)]
        _check_property_names(list(so_config.mapping), properties)
        print(f"Please wait... reading SevOne {so_config.url}.")
        devices = sevone_fetch_records(SevOneClient(so_config))
    except SevOneError as e:
        raise UsageError(str(e)) from e
    domain = args.domain if args.domain is not None else so_config.domain
    header, rows = sevone_import_rows(devices.records, so_config, domain)
    scope = f"groups {', '.join(so_config.device_groups)}" if so_config.device_groups else "all groups"
    print(f"{devices.total} SevOne devices ({scope}), {len(devices.records)} kept -> domain {domain}")
    for name, reason in _limited(devices.skipped, args.verbose):
        print(f"  left aside: {name}: {reason}")
    if not args.verbose and len(devices.skipped) > DETAIL_LIMIT:
        print(f"    ... and {len(devices.skipped) - DETAIL_LIMIT} more (use -v)")
    overwrite = args.overwrite or so_config.overwrite
    if not overwrite:
        print("SevOne only fills empty properties (--overwrite to replace QRadar values)")
    if args.save_csv:
        write_csv(args.save_csv, header, (row.values for row in rows))
        print(f"Import rows saved to {args.save_csv}")
    args.domain = None
    args.fill_empty_only = args.fill_empty_only or not overwrite
    return run_import(client, args, header, rows)


def run_import(client: QRadarClient, args: argparse.Namespace, header: List[str], rows: List[ImportRow]) -> int:
    """Plan, print and (with --apply) write an import, whatever the source of the rows."""
    host = client.config.host
    catalog = list_properties(client)
    domains = list_domains(client)
    caps = detect_capabilities(client)
    default_domain = _resolve_domain(args.domain, domains) if args.domain is not None else None

    if not args.allow_create:
        can_create, blocked = False, "not created, use --allow-create to create assets QRadar does not know"
    else:
        can_create, reason = caps.check(CREATE_ASSET)
        blocked = f"not created, {reason}" if not can_create else ""

    print("Please wait... reading assets.")
    planner = Planner(
        fetch_assets(client),
        catalog,
        domains,
        default_domain,
        can_create,
        blocked,
        fill_empty_only=args.fill_empty_only,
    )
    plan = planner.plan(header, rows)
    _print_plan(plan, len(rows), args.verbose)

    report = args.report or default_export_path(host, "csv", prefix="import-report")
    if plan.not_found:
        not_found_path = default_export_path(host, "csv", prefix="assets-not-found")
        write_csv(not_found_path, header, (row.values for row, _ in plan.not_found), delimiter=",")
        print(f"\nRows of assets not found saved to {not_found_path}")

    if not args.apply:
        write_csv(report, REPORT_COLUMNS, _report_rows(plan))
        print(f"Report: {report}")
        print("\nDry run: nothing was written to QRadar. Re-run with --apply to write.")
        return EXIT_OK

    if plan.errors and not args.skip_invalid:
        write_csv(report, REPORT_COLUMNS, _report_rows(plan))
        raise UsageError(
            f"{len(plan.errors)} invalid rows: fix them, or use --skip-invalid to import the valid rows only"
        )
    if plan.updates and not caps.can_update_assets:
        raise UsageError(f"Cannot update assets: {caps.check(UPDATE_ASSET)[1]}")
    if not plan.has_writes:
        write_csv(report, REPORT_COLUMNS, _report_rows(plan))
        print("\nNothing to write.")
        return EXIT_OK

    backup = None
    if client.config.safety:
        backup = backup_path(host)
        try:
            write_backup(backup, host, [planner.by_id[asset_id] for asset_id in plan.updates])
        except OSError as e:
            logger.error("Backup failed, import aborted: %s", e)
            return EXIT_ERROR
        print(f"\nSafety is on: assets backed up to {backup} before import")
    else:
        print("\nSafety is off: no backup before import")
        logger.warning("Safety is off: no backup before import")

    outcomes = apply_updates(client, plan)
    if plan.creations:
        catalog_by_name = {str(p["name"]): p for p in catalog}
        if caps.can_bulk_assets:
            print(f"Creating {len(plan.creations)} assets in bulk, this can take a few minutes...")
            outcomes += create_in_bulk(client, plan.creations, catalog_by_name, chunk_size=args.bulk_size)
        else:
            domain_names = {int(d["id"]): str(d.get("name") or "") for d in domains}
            outcomes += create_one_by_one(client, plan.creations, catalog_by_name, domain_names)
        created_ids = [o.asset_id for o in outcomes if o.action == "create" and o.status == "created" and o.asset_id]
        if backup and created_ids:
            record_created_assets(backup, created_ids)

    write_csv(report, REPORT_COLUMNS, _report_rows(plan, outcomes))
    counts: Dict[str, int] = {}
    for outcome in outcomes:
        key = f"{outcome.action} {outcome.status}"
        counts[key] = counts.get(key, 0) + 1
    print("\nResult: " + ", ".join(f"{n} {key}" for key, n in sorted(counts.items())))
    print(f"Report: {report}")
    if plan.updates:
        print(
            "Property updates are applied asynchronously by QRadar: run the same import again without --apply "
            "in a few minutes to check that nothing is left to change."
        )
    failed = [o for o in outcomes if o.failed]
    for outcome in _limited(failed, args.verbose):
        logger.error("line %s %s %s: %s", outcome.line, outcome.action, outcome.asset_id or "", outcome.message)
    return EXIT_ERROR if failed else EXIT_OK


def cmd_restore(client: QRadarClient, args: argparse.Namespace) -> int:
    try:
        backup = read_backup(args.backup)
    except (OSError, ValueError) as e:
        raise UsageError(f"Cannot read backup {args.backup}: {e}") from e
    if backup.get("host") != client.config.host:
        raise UsageError(f"The backup was made on {backup.get('host')}, not on {client.config.host}")

    ids = [int(a["id"]) for a in backup["assets"]]
    current = fetch_assets(client, asset_ids=ids) if ids else []
    items = plan_restore(backup, current, list_properties(client))
    created = [int(i) for i in backup.get("created_asset_ids", [])]
    missing = sorted(set(ids) - {int(a["id"]) for a in current})

    print(f"Backup of {backup.get('created_at')}: {len(ids)} assets, {len(created)} created by the import")
    to_restore = [item for item in items if item.changes]
    print(f"  Assets to restore ..... {len(to_restore)}")
    for item in _limited(to_restore, args.verbose):
        print(f"  asset {item.asset_id}: {_changes_text(item.changes)}")
    _more(to_restore, args.verbose)
    for item in items:
        if item.cannot_clear:
            print(f"  asset {item.asset_id}: cannot empty {', '.join(item.cannot_clear)} (no API to clear a property)")
    if missing:
        print(f"  Assets gone since the backup: {', '.join(map(str, missing))}")
    if created:
        action = "will be deleted" if args.delete_created else "are kept (use --delete-created to delete them)"
        print(f"  Assets created by the import {action}: {', '.join(map(str, created))}")

    if args.delete_created and created:
        caps = detect_capabilities(client)
        if not caps.can_delete_assets:
            raise UsageError(f"Cannot delete assets: {caps.check(DELETE_ASSET)[1]}")
    if not args.apply:
        print("\nDry run: nothing was written to QRadar. Re-run with --apply to restore.")
        return EXIT_OK

    outcomes = apply_restore(client, to_restore)
    if args.delete_created and created:
        outcomes += delete_assets(client, created)
    failed = [o for o in outcomes if o.failed]
    for outcome in failed:
        logger.error("%s asset %s failed: %s", outcome.action, outcome.asset_id, outcome.message)
    print(f"\nRestore done: {len(outcomes) - len(failed)} succeeded, {len(failed)} failed")
    return EXIT_ERROR if failed else EXIT_OK


REPORT_FINDING_COLUMNS = ["severity", "check", "asset_id", "domain_id", "target", "names", "detail"]
EXAMPLES_PER_CHECK = 5


def _parse_checks(value: str) -> List[str]:
    names = [name.strip() for name in value.split(",") if name.strip()]
    unknown = [name for name in names if name not in QUALITY_CHECKS]
    if unknown:
        raise UsageError(f"Unknown check(s): {', '.join(unknown)}. Checks: {', '.join(QUALITY_CHECKS)}")
    return names


def _print_report(findings: Sequence[Finding], enabled: Sequence[str], verbose: bool) -> None:
    counts = summary(findings)
    rows = [
        (name, QUALITY_CHECKS[name][0], counts[name], QUALITY_CHECKS[name][1])
        for name in QUALITY_CHECKS
        if name in enabled
    ]
    _print_table(("Check", "Severity", "Count", "Description"), rows)
    for name in QUALITY_CHECKS:
        selected = [f for f in findings if f.check == name]
        if not selected:
            continue
        print(f"\n{name} ({len(selected)}):")
        for f in selected if verbose else selected[:EXAMPLES_PER_CHECK]:
            asset = f"asset {f.asset_id}" if f.asset_id is not None else f"domain {f.domain_id}"
            parts = [part for part in (f.target, f.names) if part]
            print(f"  {asset}: {' / '.join(parts)}{' - ' if parts else ''}{f.detail}")
        if not verbose and len(selected) > EXAMPLES_PER_CHECK:
            print(f"  ... and {len(selected) - EXAMPLES_PER_CHECK} more (see the report file, or use -v)")


def cmd_report(client: QRadarClient, args: argparse.Namespace) -> int:
    enabled = _parse_checks(args.checks) if args.checks else list(QUALITY_CHECKS)
    skipped = _parse_checks(args.skip) if args.skip else []
    if args.no_nh:
        skipped += list(NH_CHECKS)
    enabled = [name for name in enabled if name not in skipped]
    if not enabled:
        raise UsageError("No check left to run")

    known_properties = [str(p.get("name")) for p in list_properties(client)]
    if args.owner_property:
        owner_properties = args.owner_property
        _check_property_names(owner_properties, known_properties)
    else:
        # Default owner properties missing from this QRadar are ignored rather than refused.
        owner_properties = [name for name in ReportOptions.owner_properties if name in known_properties]
        if not owner_properties and "no-owner" in enabled:
            logger.warning("No owner property on this QRadar: no-owner check skipped")
            enabled = [name for name in enabled if name != "no-owner"]
    options = ReportOptions(
        stale_days=args.stale_days, owner_properties=owner_properties, catch_all_groups=args.catch_all_group
    )

    domains = list_domains(client)
    domain_id = _resolve_domain(args.domain, domains) if args.domain is not None else None
    print("Please wait... reading assets.")
    assets = fetch_assets(client, domain_id)
    findings = check_assets(assets, options, set(enabled))

    if any(name in NH_CHECKS for name in enabled):
        try:
            networks = load_from_nhsuite_csv(args.nh_file) if args.nh_file else load_from_api(client)
        except NetworkHierarchyError as e:
            raise UsageError(str(e)) from e
        groups = {n.group for n in networks}
        for group in options.catch_all_groups:
            if not any(g == group or g.startswith(group + ".") for g in groups):
                logger.warning("Catch-all group '%s' is not in the Network Hierarchy", group)
        nh_findings = check_network_hierarchy(assets, NHIndex(networks), options, set(enabled))
        if domain_id is not None:
            nh_findings = [f for f in nh_findings if f.check != "empty-network" or f.domain_id in (None, domain_id)]
        findings += nh_findings
        source = args.nh_file or "QRadar"
        print(f"{len(assets)} assets checked against {len(networks)} Network Hierarchy networks ({source}).\n")
    else:
        print(f"{len(assets)} assets checked.\n")

    findings = sort_findings(findings)
    _print_report(findings, enabled, args.verbose)

    output_format = args.format or ("json" if args.output and args.output.lower().endswith(".json") else "csv")
    output = args.output or default_export_path(client.config.host, output_format, prefix="report")
    if output_format == "json":
        payload = {
            "host": client.config.host,
            "assets": len(assets),
            "options": {
                "stale_days": options.stale_days,
                "owner_properties": list(owner_properties),
                "catch_all_groups": list(options.catch_all_groups),
                "checks": enabled,
            },
            "summary": {name: count for name, count in summary(findings).items() if name in enabled},
            "findings": [{column: getattr(f, column) for column in REPORT_FINDING_COLUMNS} for f in findings],
        }
        write_json(output, [payload])
    else:
        rows = ({column: getattr(f, column) for column in REPORT_FINDING_COLUMNS} for f in findings)
        write_csv(output, REPORT_FINDING_COLUMNS, rows, delimiter=args.delimiter)
    print(f"\n{len(findings)} findings written to {output}")

    if args.fail_on:
        limit = severity_rank(args.fail_on)
        failing = [f for f in findings if severity_rank(f.severity) <= limit]
        if failing:
            print(f"{len(failing)} findings of severity {args.fail_on} or higher", file=sys.stderr)
            return EXIT_FINDINGS
    return EXIT_OK


def _positive(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        number = 0
    if number < 1:
        raise argparse.ArgumentTypeError(f"expected a positive number, got '{value}'")
    return number


def _days(value: str) -> int:
    try:
        days = int(value)
    except ValueError:
        days = -1
    if days < 0:
        raise argparse.ArgumentTypeError(f"expected a number of days, got '{value}'")
    return days


def _delimiter(value: str) -> str:
    value = "\t" if value in ("\\t", "tab") else value
    if len(value) != 1:
        raise argparse.ArgumentTypeError("the delimiter must be a single character (or 'tab')")
    return value


def _add_import_options(parser: argparse.ArgumentParser) -> None:
    """Write options shared by the import and the sync commands."""
    parser.add_argument("--apply", action="store_true", help="Write to QRadar (default: dry run)")
    parser.add_argument(
        "--allow-create", action="store_true", help="Create the assets QRadar does not know (if this QRadar allows it)"
    )
    parser.add_argument(
        "--fill-empty-only", action="store_true", help="Only set properties that are empty in QRadar, never overwrite"
    )
    parser.add_argument(
        "--skip-invalid", action="store_true", help="With --apply: import the valid rows, skip the others"
    )
    parser.add_argument(
        "--bulk-size", type=_positive, default=100, metavar="N", help="Assets per bulk creation request (default 100)"
    )
    parser.add_argument(
        "--report", metavar="FILE", help="Report file (default: exports/import-report-HOST-TIMESTAMP.csv)"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="AssetSuite.py",
        description="QRadar Asset Suite by Pascal Weber (zoldax) / Abakus Sécurité",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-c", "--config", metavar="FILE", help="Configuration file (default: config.json)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show debug messages on the console")

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    check = subparsers.add_parser("check", help="Check the connection to QRadar")
    check.add_argument(
        "what",
        choices=sorted(CHECKS),
        help="version: QRadar release | domains: list domains | api: API versions and asset capabilities",
    )
    check.set_defaults(handler=lambda client, args: CHECKS[args.what](client))

    properties = subparsers.add_parser("properties", help="List the asset property types")
    properties.set_defaults(handler=cmd_properties)

    saved = subparsers.add_parser("saved-searches", help="List the asset saved searches")
    saved.set_defaults(handler=cmd_saved_searches)

    export = subparsers.add_parser(
        "export",
        help="Export assets to CSV or JSON",
        description="Export assets to CSV (one row per asset, or per IP) or JSON (assets as returned by QRadar). "
        "Filters combine with AND.",
    )
    export.add_argument(
        "-o", "--output", metavar="FILE", help="Output file (default: exports/assets-HOST-TIMESTAMP.csv)"
    )
    export.add_argument(
        "-f", "--format", choices=("csv", "json"), help="Output format (default: from the file extension, else csv)"
    )
    export.add_argument("--per-ip", action="store_true", help="CSV: one row per IP address instead of one per asset")
    export.add_argument(
        "--properties",
        metavar="NAMES",
        help="CSV: comma-separated property columns, e.g. 'Given Name,Business Owner' (default: all, '' for none)",
    )
    export.add_argument(
        "--delimiter",
        type=_delimiter,
        default=",",
        help="CSV delimiter (default ','; ';' for a French Excel, or 'tab')",
    )
    filters = export.add_argument_group("filters")
    filters.add_argument("--domain", metavar="ID|NAME", help="Only assets of this domain")
    filters.add_argument(
        "--saved-search", metavar="ID|NAME", help="Only the assets returned by this asset saved search"
    )
    filters.add_argument(
        "--cidr",
        action="append",
        default=[],
        metavar="CIDR",
        help="Only assets with an IP in this network (repeatable)",
    )
    filters.add_argument("--seen-within", type=_days, metavar="DAYS", help="Only assets seen in the last DAYS days")
    filters.add_argument(
        "--not-seen-for", type=_days, metavar="DAYS", help="Only assets not seen for DAYS days (stale assets)"
    )
    filters.add_argument(
        "--property",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="Only assets whose property equals VALUE; 'NAME=' for an empty or missing property (repeatable)",
    )
    export.set_defaults(handler=cmd_export)

    importer = subparsers.add_parser(
        "import",
        help="Update asset properties from CSV, and create missing assets",
        description="Import a CSV file in the export format. Without --apply, only shows what would change (dry run).",
    )
    importer.add_argument("file", help="CSV file (UTF-8; ',' ';' or tab delimiter, guessed from the header)")
    importer.add_argument("--domain", metavar="ID|NAME", help="Domain of the rows without domain_id / domain_name")
    importer.add_argument("--delimiter", type=_delimiter, help="Force the CSV delimiter")
    _add_import_options(importer)
    importer.set_defaults(handler=cmd_import)

    netbox = subparsers.add_parser(
        "netbox-sync",
        help="Update asset properties from the NetBox IPAM, and create missing assets",
        description="Read the NetBox IP addresses (netbox section of the config) and import them as assets, "
        "with the property mapping of the config. Without --apply, only shows what would change (dry run).",
    )
    netbox.add_argument(
        "--domain", metavar="ID|NAME", help="QRadar domain of the NetBox addresses (default: netbox.domain)"
    )
    netbox.add_argument("--save-csv", metavar="FILE", help="Also save the generated import rows to this CSV file")
    _add_import_options(netbox)
    netbox.set_defaults(handler=cmd_netbox_sync)

    pfsense = subparsers.add_parser(
        "pfsense-sync",
        help="Name assets from the pfSense DNS Resolver and static DHCP mappings (backup files)",
        description="Read pfSense configuration backups (DNS Resolver host overrides, static DHCP mappings) and import "
        "them as assets. pfSense only fills empty properties unless --overwrite. Without --apply, only shows "
        "what would change (dry run).",
    )
    pfsense.add_argument(
        "--file",
        action="append",
        metavar="FILE",
        help="pfSense backup XML (repeatable; default: pfsense.files, private/*.xml)",
    )
    pfsense.add_argument(
        "--domain", metavar="ID|NAME", help="QRadar domain of the pfSense addresses (default: pfsense.domain)"
    )
    pfsense.add_argument("--save-csv", metavar="FILE", help="Also save the generated import rows to this CSV file")
    pfsense.add_argument(
        "--overwrite", action="store_true", help="Replace QRadar values (default: only fill empty properties)"
    )
    _add_import_options(pfsense)
    pfsense.set_defaults(handler=cmd_pfsense_sync)

    sevone = subparsers.add_parser(
        "sevone-sync",
        help="Fill asset properties from the devices monitored by IBM SevOne NPM",
        description="Read the SevOne devices (sevone section of the config) with their device types and metadata, "
        "and import them as assets. SevOne only fills empty properties unless --overwrite. Without --apply, only "
        "shows what would change (dry run).",
    )
    sevone.add_argument(
        "--domain", metavar="ID|NAME", help="QRadar domain of the SevOne devices (default: sevone.domain)"
    )
    sevone.add_argument("--save-csv", metavar="FILE", help="Also save the generated import rows to this CSV file")
    sevone.add_argument(
        "--overwrite", action="store_true", help="Replace QRadar values (default: only fill empty properties)"
    )
    _add_import_options(sevone)
    sevone.set_defaults(handler=cmd_sevone_sync)

    restore = subparsers.add_parser(
        "restore",
        help="Restore asset properties from a safety backup",
        description="Put back the property values saved in a safety backup. Without --apply, only shows the changes.",
    )
    restore.add_argument("backup", help="Backup file from the safety/ folder")
    restore.add_argument("--apply", action="store_true", help="Write to QRadar (default: dry run)")
    restore.add_argument("--delete-created", action="store_true", help="Also delete the assets created by the import")
    restore.set_defaults(handler=cmd_restore)

    report = subparsers.add_parser(
        "report",
        help="Asset data quality report, cross-checked with the Network Hierarchy",
        description=f"Checks: {', '.join(QUALITY_CHECKS)}. "
        "With --fail-on, exit code 3 when findings reach that severity.",
    )
    report.add_argument(
        "-o", "--output", metavar="FILE", help="Findings file (default: exports/report-HOST-TIMESTAMP.csv)"
    )
    report.add_argument(
        "-f", "--format", choices=("csv", "json"), help="Findings format (default: from the extension, else csv)"
    )
    report.add_argument("--delimiter", type=_delimiter, default=",", help="CSV delimiter (default ',')")
    report.add_argument("--checks", metavar="LIST", help="Comma-separated checks to run (default: all)")
    report.add_argument("--skip", metavar="LIST", help="Comma-separated checks to skip")
    report.add_argument("--domain", metavar="ID|NAME", help="Only the assets of this domain")
    report.add_argument(
        "--stale-days",
        type=_positive,
        default=30,
        metavar="DAYS",
        help="Stale after DAYS days without sighting (default 30)",
    )
    report.add_argument(
        "--owner-property",
        action="append",
        metavar="NAME",
        help="Property that names an owner (repeatable; default: Business Owner and Technical Owner)",
    )
    report.add_argument(
        "--catch-all-group",
        action="append",
        default=[],
        metavar="GROUP",
        help="Network Hierarchy group used as catch-all, with its sub-groups (repeatable), e.g. Z_CatchAll",
    )
    nh_source = report.add_mutually_exclusive_group()
    nh_source.add_argument(
        "--nh-file", metavar="FILE", help="Network Hierarchy CSV exported by NHSuite, instead of QRadar"
    )
    nh_source.add_argument("--no-nh", action="store_true", help="Skip the Network Hierarchy checks")
    report.add_argument(
        "--fail-on", choices=SEVERITIES, help="Exit with code 3 if a finding has this severity or higher"
    )
    report.set_defaults(handler=cmd_report)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return EXIT_CONFIG

    try:
        config = load_config(args.config)
    except ConfigError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return EXIT_CONFIG
    setup_logging(config, args.verbose)

    client = QRadarClient(config)
    try:
        return args.handler(client, args)
    except (UsageError, LookupFailed, ImportFileError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_CONFIG
    except QRadarAPIError as e:
        logger.error("%s", e)
        return EXIT_ERROR
    except OSError as e:
        logger.error("Cannot write %s: %s", getattr(e, "filename", None) or "output file", e.strerror or e)
        return EXIT_ERROR
