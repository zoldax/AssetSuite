"""
network_hierarchy.py

Cross-check of assets against the QRadar Network Hierarchy (NH), read from
the API or from a CSV exported by NHSuite.

Observed on QRadar 7.6.0 FP1: /config/network_hierarchy/networks does not
accept the Range header, so it is read in one request. Each NH entry has an
id and a network_id; several CIDRs can share one network_id, and the
network_id of an asset IP refers to that field, not to the id.

Copyright 2026 Pascal Weber (zoldax) / Abakus Sécurité
Licensed under the Apache License, Version 2.0 (see LICENSE).
"""

from __future__ import annotations

import csv
import ipaddress
from dataclasses import dataclass
from typing import List, Mapping, Optional, Sequence, Set

from assetsuite.assets import IPNetwork, iter_ips, parse_ip
from assetsuite.client import QRadarClient
from assetsuite.quality import Finding, ReportOptions, asset_names

NHSUITE_COLUMNS = ["id", "group", "name", "cidr", "description", "domain_id", "location", "country_code"]


class NetworkHierarchyError(Exception):
    """The Network Hierarchy file cannot be read."""


@dataclass(frozen=True)
class NHNetwork:
    id: int
    network_id: Optional[int]
    group: str
    name: str
    cidr: IPNetwork
    domain_id: Optional[int]

    @property
    def label(self) -> str:
        return f"{self.group}.{self.name} ({self.cidr})"

    def in_groups(self, groups: Sequence[str]) -> bool:
        return any(self.group == g or self.group.startswith(g + ".") for g in groups)


def _optional_int(value: object) -> Optional[int]:
    text = "" if value is None else str(value).strip()
    return int(text) if text.lstrip("-").isdigit() else None


def _network(raw: Mapping, where: str) -> NHNetwork:
    try:
        cidr = ipaddress.ip_network(str(raw.get("cidr", "")).strip(), strict=False)
    except ValueError as e:
        raise NetworkHierarchyError(f"{where}: invalid CIDR '{raw.get('cidr')}'") from e
    return NHNetwork(
        id=_optional_int(raw.get("id")) or 0,
        network_id=_optional_int(raw.get("network_id")),
        group=str(raw.get("group") or ""),
        name=str(raw.get("name") or ""),
        cidr=cidr,
        domain_id=_optional_int(raw.get("domain_id")),
    )


def load_from_api(client: QRadarClient) -> List[NHNetwork]:
    data = client.get("config/network_hierarchy/networks") or []
    return [_network(raw, f"network {raw.get('id')}") for raw in data]


def load_from_nhsuite_csv(path: str) -> List[NHNetwork]:
    """Network Hierarchy exported by NHSuite (no network_id in that format)."""
    try:
        with open(path, encoding="utf-8-sig", newline="") as file:
            reader = csv.DictReader(file)
            missing = [c for c in ("group", "name", "cidr") if c not in (reader.fieldnames or [])]
            if missing:
                raise NetworkHierarchyError(f"{path} is not an NHSuite export: missing {', '.join(missing)}")
            return [
                _network(row, f"{path} line {reader.line_num}") for row in reader if (row.get("cidr") or "").strip()
            ]
    except OSError as e:
        raise NetworkHierarchyError(f"Cannot read {path}: {e}") from e


class NHIndex:
    """Longest-prefix lookup of an IP in the Network Hierarchy."""

    def __init__(self, networks: Sequence[NHNetwork]):
        self.networks = sorted(networks, key=lambda n: n.cidr.prefixlen, reverse=True)

    def lookup(self, value: str) -> Optional[NHNetwork]:
        ip = parse_ip(value)
        if ip is None:
            return None
        for network in self.networks:
            if ip.version == network.cidr.version and ip in network.cidr:
                return network
        return None


def check_network_hierarchy(
    assets: Sequence[Mapping], index: NHIndex, options: ReportOptions, enabled: Set[str]
) -> List[Finding]:
    findings: List[Finding] = []
    used: Set[int] = set()
    for asset in assets:
        names = asset_names(asset)
        for ip, _ in iter_ips(asset):
            value = str(ip.get("value"))
            network = index.lookup(value)
            issues = []
            if network is None:
                issues.append(("outside-nh", "no Network Hierarchy network contains this IP"))
            else:
                used.add(id(network))
                if network.domain_id is not None and network.domain_id != asset.get("domain_id"):
                    issues.append(("nh-domain-mismatch", f"{network.label} is in domain {network.domain_id}"))
                if options.catch_all_groups and network.in_groups(options.catch_all_groups):
                    issues.append(("nh-catch-all", f"only in {network.label}"))
                recorded = ip.get("network_id")
                if network.network_id is not None and recorded is not None and recorded != network.network_id:
                    issues.append(
                        (
                            "nh-network-changed",
                            f"recorded network_id {recorded}, Network Hierarchy now gives {network.label}",
                        )
                    )
            findings.extend(
                Finding(check, asset.get("id"), asset.get("domain_id"), value, names, detail)
                for check, detail in issues
                if check in enabled
            )

    if "empty-network" in enabled:
        for network in index.networks:
            if id(network) not in used and not (
                options.catch_all_groups and network.in_groups(options.catch_all_groups)
            ):
                findings.append(Finding("empty-network", None, network.domain_id, str(network.cidr), "", network.label))
    return findings
