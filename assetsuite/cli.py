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
from assetsuite.capabilities import FEATURES, UPDATE_ASSET, detect_capabilities
from assetsuite.client import QRadarAPIError, QRadarClient
from assetsuite.config import Config, ConfigError, load_config
from assetsuite.export import default_export_path, write_csv, write_json
from assetsuite.importer import ImportFileError, ImportPlan, ImportRow, read_import_file
from assetsuite.progress import Progress
from assetsuite.quality import (
    CHECKS as QUALITY_CHECKS,
)
from assetsuite.quality import (
    SEVERITIES,
    Finding,
    severity_rank,
    summary,
)
from assetsuite.service import (
    REPORT_COLUMNS,
    REPORT_FINDING_COLUMNS,
    ServiceError,
    SyncSource,
    changes_text,
    check_property_names,
    finding_rows,
    load_netbox,
    load_pfsense,
    load_sevone,
    netbox_source,
    parse_checks,
    pfsense_source,
    plan_import,
    prepare_import,
    prepare_report,
    prepare_restore,
    report_payload,
    report_rows,
    resolve_domain,
    run_report,
    run_restore,
    safety_backup,
    sevone_source,
    write_plan,
)
from assetsuite.system import get_system_about, list_domains
from assetsuite.writer import (
    read_backup,
)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONFIG = 2
EXIT_FINDINGS = 3

logger = logging.getLogger("assetsuite")


class UsageError(ServiceError):
    """Invalid command-line value, detected after argument parsing."""


class PrintNotes(Progress):
    """Prints the notes of an operation (no progress bar on the command line)."""

    def note(self, text: str) -> None:
        print(text)


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
    check_property_names(property_columns, known_properties)
    check_property_names(list(property_filters), known_properties)

    asset_filter = AssetFilter(
        networks=_parse_networks(args.cidr),
        seen_within_days=args.seen_within,
        not_seen_for_days=args.not_seen_for,
        properties=property_filters,
    )

    domains = list_domains(client)
    domain_names = {int(d["id"]): str(d.get("name") or "") for d in domains if d.get("id") is not None}
    domain_id = resolve_domain(args.domain, domains) if args.domain is not None else None

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


def _limited(items: Sequence, verbose: bool) -> Sequence:
    return items if verbose else items[:DETAIL_LIMIT]


def _more(items: Sequence, verbose: bool) -> None:
    if not verbose and len(items) > DETAIL_LIMIT:
        print(f"    ... and {len(items) - DETAIL_LIMIT} more (see the report, or use -v)")


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
            print(f"  line {u.lines[0]:<5} asset {u.asset_id} ({u.label}): {changes_text(u.changes.values())}")
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


def cmd_import(client: QRadarClient, args: argparse.Namespace) -> int:
    header, rows = read_import_file(args.file, args.delimiter)
    return run_import(client, args, header, rows)


def _save_rows(path: Optional[str], source: SyncSource) -> None:
    if path:
        write_csv(path, source.header, (row.values for row in source.rows))
        print(f"Import rows saved to {path}")


def _run_source(client: QRadarClient, args: argparse.Namespace, source: SyncSource) -> int:
    _save_rows(args.save_csv, source)
    # The rows already carry their domain.
    args.domain = None
    args.fill_empty_only = args.fill_empty_only or source.fill_empty_only
    return run_import(client, args, source.header, source.rows)


def cmd_netbox_sync(client: QRadarClient, args: argparse.Namespace) -> int:
    nb_config = load_netbox(client)
    print(f"Please wait... reading NetBox {nb_config.url}.")
    source = netbox_source(nb_config, args.domain)
    statuses = ", ".join(nb_config.statuses) or "any"
    print(f"{source.kept} NetBox IP addresses (status {statuses}) -> domain {source.domain}")
    return _run_source(client, args, source)


def cmd_pfsense_sync(client: QRadarClient, args: argparse.Namespace) -> int:
    pf_config = load_pfsense(client)
    source = pfsense_source(pf_config, args.file, args.domain, args.overwrite)
    networks = ", ".join(map(str, pf_config.networks)) or "all networks"
    print(
        f"{source.read} pfSense IP addresses in {len(source.files)} file(s), "
        f"{source.kept} kept ({networks}) -> domain {source.domain}"
    )
    if source.fill_empty_only:
        print("pfSense only fills empty properties (--overwrite to replace QRadar values)")
    return _run_source(client, args, source)


def cmd_sevone_sync(client: QRadarClient, args: argparse.Namespace) -> int:
    so_config = load_sevone(client)
    print(f"Please wait... reading SevOne {so_config.url}.")
    source = sevone_source(so_config, args.domain, args.overwrite)
    scope = f"groups {', '.join(so_config.device_groups)}" if so_config.device_groups else "all groups"
    print(f"{source.read} SevOne devices ({scope}), {source.kept} kept -> domain {source.domain}")
    for name, reason in _limited(source.skipped, args.verbose):
        print(f"  left aside: {name}: {reason}")
    if not args.verbose and len(source.skipped) > DETAIL_LIMIT:
        print(f"    ... and {len(source.skipped) - DETAIL_LIMIT} more (use -v)")
    if source.fill_empty_only:
        print("SevOne only fills empty properties (--overwrite to replace QRadar values)")
    return _run_source(client, args, source)


def run_import(client: QRadarClient, args: argparse.Namespace, header: List[str], rows: List[ImportRow]) -> int:
    """Plan, print and (with --apply) write an import, whatever the source of the rows."""
    host = client.config.host
    context = prepare_import(client, args.domain, args.allow_create)
    caps = context.caps

    print("Please wait... reading assets.")
    planner, plan = plan_import(client, context, header, rows, fill_empty_only=args.fill_empty_only)
    _print_plan(plan, len(rows), args.verbose)

    report = args.report or default_export_path(host, "csv", prefix="import-report")
    if plan.not_found:
        not_found_path = default_export_path(host, "csv", prefix="assets-not-found")
        write_csv(not_found_path, header, (row.values for row, _ in plan.not_found), delimiter=",")
        print(f"\nRows of assets not found saved to {not_found_path}")

    if not args.apply:
        write_csv(report, REPORT_COLUMNS, report_rows(plan))
        print(f"Report: {report}")
        print("\nDry run: nothing was written to QRadar. Re-run with --apply to write.")
        return EXIT_OK

    if plan.errors and not args.skip_invalid:
        write_csv(report, REPORT_COLUMNS, report_rows(plan))
        raise UsageError(
            f"{len(plan.errors)} invalid rows: fix them, or use --skip-invalid to import the valid rows only"
        )
    if plan.updates and not caps.can_update_assets:
        raise UsageError(f"Cannot update assets: {caps.check(UPDATE_ASSET)[1]}")
    if not plan.has_writes:
        write_csv(report, REPORT_COLUMNS, report_rows(plan))
        print("\nNothing to write.")
        return EXIT_OK

    backup = None
    if client.config.safety:
        try:
            backup = safety_backup(client, planner, plan)
        except OSError as e:
            logger.error("Backup failed, import aborted: %s", e)
            return EXIT_ERROR
        print(f"\nSafety is on: assets backed up to {backup} before import")
    else:
        print("\nSafety is off: no backup before import")
        logger.warning("Safety is off: no backup before import")

    result = write_plan(client, context, plan, backup, bulk_size=args.bulk_size, progress=PrintNotes())
    outcomes = result.outcomes
    write_csv(report, REPORT_COLUMNS, report_rows(plan, outcomes))
    print("\nResult: " + ", ".join(f"{n} {key}" for key, n in sorted(result.counts().items())))
    print(f"Report: {report}")
    if plan.updates:
        print(
            "Property updates are applied asynchronously by QRadar: run the same import again without --apply "
            "in a few minutes to check that nothing is left to change."
        )
    failed = result.failed
    for outcome in _limited(failed, args.verbose):
        logger.error("line %s %s %s: %s", outcome.line, outcome.action, outcome.asset_id or "", outcome.message)
    return EXIT_ERROR if failed else EXIT_OK


def cmd_restore(client: QRadarClient, args: argparse.Namespace) -> int:
    try:
        backup = read_backup(args.backup)
    except (OSError, ValueError) as e:
        raise UsageError(f"Cannot read backup {args.backup}: {e}") from e
    plan = prepare_restore(client, backup, args.delete_created)
    items, created, missing, to_restore = plan.items, plan.created, plan.missing, plan.to_restore

    print(f"Backup of {backup.get('created_at')}: {len(plan.asset_ids)} assets, {len(created)} created by the import")
    print(f"  Assets to restore ..... {len(to_restore)}")
    for item in _limited(to_restore, args.verbose):
        print(f"  asset {item.asset_id}: {changes_text(item.changes)}")
    _more(to_restore, args.verbose)
    for item in items:
        if item.cannot_clear:
            print(f"  asset {item.asset_id}: cannot empty {', '.join(item.cannot_clear)} (no API to clear a property)")
    if missing:
        print(f"  Assets gone since the backup: {', '.join(map(str, missing))}")
    if created:
        action = "will be deleted" if args.delete_created else "are kept (use --delete-created to delete them)"
        print(f"  Assets created by the import {action}: {', '.join(map(str, created))}")

    if plan.delete_blocked:
        raise UsageError(f"Cannot delete assets: {plan.delete_blocked}")
    if not args.apply:
        print("\nDry run: nothing was written to QRadar. Re-run with --apply to restore.")
        return EXIT_OK

    outcomes = run_restore(client, plan, args.delete_created).outcomes
    failed = [o for o in outcomes if o.failed]
    for outcome in failed:
        logger.error("%s asset %s failed: %s", outcome.action, outcome.asset_id, outcome.message)
    print(f"\nRestore done: {len(outcomes) - len(failed)} succeeded, {len(failed)} failed")
    return EXIT_ERROR if failed else EXIT_OK


EXAMPLES_PER_CHECK = 5


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
    checks = parse_checks(args.checks) if args.checks else None
    skip = parse_checks(args.skip) if args.skip else []
    setup = prepare_report(
        client,
        checks=checks,
        skip=skip,
        no_nh=args.no_nh,
        owner_properties=args.owner_property,
        stale_days=args.stale_days,
        catch_all_groups=args.catch_all_group,
        domain=args.domain,
    )
    print("Please wait... reading assets.")
    outcome = run_report(client, setup, args.nh_file)
    if outcome.networks is not None:
        print(
            f"{outcome.assets} assets checked against {outcome.networks} Network Hierarchy networks "
            f"({outcome.nh_source}).\n"
        )
    else:
        print(f"{outcome.assets} assets checked.\n")

    findings = outcome.findings
    _print_report(findings, setup.enabled, args.verbose)

    output_format = args.format or ("json" if args.output and args.output.lower().endswith(".json") else "csv")
    output = args.output or default_export_path(client.config.host, output_format, prefix="report")
    if output_format == "json":
        write_json(output, [report_payload(client.config.host, outcome)])
    else:
        write_csv(output, REPORT_FINDING_COLUMNS, finding_rows(findings), delimiter=args.delimiter)
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
    except (ServiceError, LookupFailed, ImportFileError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_CONFIG
    except QRadarAPIError as e:
        logger.error("%s", e)
        return EXIT_ERROR
    except OSError as e:
        logger.error("Cannot write %s: %s", getattr(e, "filename", None) or "output file", e.strerror or e)
        return EXIT_ERROR
