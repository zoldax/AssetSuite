"""
quality.py

Asset data quality checks: duplicates, stale assets, missing names or
owners, identifiers QRadar leaves out of its asset reconciliation, and assets
carrying vulnerabilities. Network Hierarchy checks live in
network_hierarchy.py and produce the same Finding records.

Copyright 2026 Pascal Weber (zoldax) / Abakus Sécurité
Licensed under the Apache License, Version 2.0 (see LICENSE).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from assetsuite.assets import format_datetime, iter_ips, last_seen, property_values
from assetsuite.importer import NO_HOSTNAME, normalize_mac
from assetsuite.progress import Progress, or_none
from assetsuite.reconciliation import EXCLUDED, KIND_LABELS, ReconciliationLists, describe, for_asset

SEVERITIES = ("high", "medium", "low", "info")

# name -> (severity, description), in report order
CHECKS: Dict[str, Tuple[str, str]] = {
    "duplicate-ip": ("high", "IP address held by several assets of the same domain"),
    "nh-domain-mismatch": ("high", "IP in a Network Hierarchy network of another domain"),
    "duplicate-mac": ("medium", "MAC address held by several assets of the same domain"),
    "duplicate-hostname": ("medium", "DNS name held by several assets of the same domain"),
    "outside-nh": ("medium", "IP in no Network Hierarchy network"),
    "stale": ("medium", "Asset not seen for the stale period, or never seen"),
    "nh-catch-all": ("low", "IP only classified by a catch-all Network Hierarchy group"),
    "nh-network-changed": ("low", "IP recorded in another network than the current Network Hierarchy gives"),
    "unnamed": ("low", "Asset without Given Name nor hostname"),
    "no-owner": ("low", "Asset without owner"),
    "excluded": ("low", "Identifier of the asset left out of QRadar's asset reconciliation"),
    "empty-network": ("info", "Network Hierarchy network without any asset"),
    "vulnerable": ("info", "Asset with vulnerabilities or a risk score"),
}
NH_CHECKS = ("nh-domain-mismatch", "outside-nh", "nh-catch-all", "nh-network-changed", "empty-network")


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity)


@dataclass
class Finding:
    check: str
    asset_id: Optional[int]
    domain_id: Optional[int]
    target: str  # IP, MAC, hostname or CIDR the finding is about
    names: str  # hostnames / Given Name of the asset, to recognise it
    detail: str

    @property
    def severity(self) -> str:
        return CHECKS[self.check][0]


@dataclass
class ReportOptions:
    stale_days: int = 30
    owner_properties: Sequence[str] = ("Business Owner", "Technical Owner")
    catch_all_groups: Sequence[str] = ()
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def asset_names(asset: Mapping) -> str:
    names = [str(h.get("name")) for h in asset.get("hostnames") or [] if h.get("name") and h.get("name") != NO_HOSTNAME]
    given = property_values(asset).get("Given Name", "")
    if given and given not in names:
        names.insert(0, given)
    return ";".join(dict.fromkeys(names))


def _finding(check: str, asset: Mapping, target: str, detail: str) -> Finding:
    return Finding(check, asset.get("id"), asset.get("domain_id"), target, asset_names(asset), detail)


DUPLICATE_KINDS = {"duplicate-ip": "ip", "duplicate-mac": "mac", "duplicate-hostname": "dns"}


def _on_list(check: str, domain: object, value: str, lists: Optional[ReconciliationLists]) -> str:
    """The end of the detail of a duplicate whose shared value is on a reconciliation list, else ""."""
    entries = lists.lookup(DUPLICATE_KINDS[check], value, domain) if lists else []  # type: ignore[arg-type]
    entries.sort(key=lambda e: e.listed != EXCLUDED)
    return f"; {describe(entries[0])}" if entries else ""


def check_duplicates(
    assets: Sequence[Mapping], enabled: Set[str], lists: Optional[ReconciliationLists] = None
) -> List[Finding]:
    keys: Dict[str, Dict[Tuple[object, str], List[Mapping]]] = {
        "duplicate-ip": defaultdict(list),
        "duplicate-mac": defaultdict(list),
        "duplicate-hostname": defaultdict(list),
    }
    for asset in assets:
        domain = asset.get("domain_id")
        for value in {str(ip.get("value")) for ip, _ in iter_ips(asset)}:
            keys["duplicate-ip"][(domain, value)].append(asset)
        macs = {normalize_mac(str(i.get("mac_address"))) for i in asset.get("interfaces") or [] if i.get("mac_address")}
        for value in macs:
            keys["duplicate-mac"][(domain, value)].append(asset)
        dns = {
            str(h.get("name")).lower() for h in asset.get("hostnames") or [] if h.get("type") == "DNS" and h.get("name")
        }
        for value in dns:
            keys["duplicate-hostname"][(domain, value)].append(asset)

    findings = []
    for check, index in keys.items():
        if check not in enabled:
            continue
        for (domain, value), holders in index.items():
            if len(holders) < 2:
                continue
            ids = sorted(int(a["id"]) for a in holders)
            listed = _on_list(check, domain, value, lists)
            for asset in holders:
                others = ", ".join(str(i) for i in ids if i != asset["id"])
                findings.append(_finding(check, asset, value, f"also on asset(s) {others}{listed}"))
    return findings


def check_assets(
    assets: Sequence[Mapping],
    options: ReportOptions,
    enabled: Set[str],
    progress: Optional[Progress] = None,
    lists: Optional[ReconciliationLists] = None,
) -> List[Finding]:
    """The checks of each asset. lists: the reconciliation lists of QRadar, for the excluded check and the
    duplicates (None: not read)."""
    progress = or_none(progress)
    progress.set_total(len(assets))
    findings = check_duplicates(assets, enabled, lists)
    limit = options.now - timedelta(days=options.stale_days)
    for asset in assets:
        progress.advance()
        values = property_values(asset)
        if "stale" in enabled:
            seen = last_seen(asset)
            if seen is None:
                findings.append(_finding("stale", asset, "", "never seen"))
            elif seen < limit:
                days = (options.now - seen).days
                findings.append(_finding("stale", asset, "", f"last seen {format_datetime(seen)} ({days} days ago)"))
        if "unnamed" in enabled and not asset_names(asset):
            ips = ";".join(str(ip.get("value")) for ip, _ in iter_ips(asset))
            findings.append(_finding("unnamed", asset, ips, "no Given Name, no DNS or NETBIOS name"))
        if "no-owner" in enabled and not any(values.get(name, "").strip() for name in options.owner_properties):
            findings.append(_finding("no-owner", asset, "", f"empty: {', '.join(options.owner_properties)}"))
        if "excluded" in enabled and lists:
            for kind, value, entry in for_asset(asset, lists):
                if entry.listed == EXCLUDED:
                    findings.append(_finding("excluded", asset, value, f"{KIND_LABELS[kind]} {describe(entry)}"))
        vulnerabilities, risk = asset.get("vulnerability_count") or 0, asset.get("risk_score_sum") or 0
        if "vulnerable" in enabled and (vulnerabilities or risk):
            findings.append(_finding("vulnerable", asset, "", f"{vulnerabilities} vulnerabilities, risk score {risk}"))
    return findings


def sort_findings(findings: Iterable[Finding]) -> List[Finding]:
    order = {name: index for index, name in enumerate(CHECKS)}
    return sorted(findings, key=lambda f: (order[f.check], f.asset_id if f.asset_id is not None else -1, f.target))


def summary(findings: Sequence[Finding]) -> Dict[str, int]:
    counts = {name: 0 for name in CHECKS}
    for finding in findings:
        counts[finding.check] += 1
    return counts
