"""
assets.py

Read side of the QRadar asset model: property catalog, saved searches,
asset listing with filters, and flattening of assets into export rows.

Observed on QRadar 7.6.0 FP1: an asset holds interfaces (each with a MAC and
IP addresses), hostnames (DNS / NETBIOS), users, products and properties
({name, type_id, value}). Timestamps are epoch milliseconds. Saved search
results only carry id, domain_id, interfaces and properties, so full assets
are fetched again by id.

Copyright 2026 Pascal Weber (zoldax) / Abakus Sécurité
Licensed under the Apache License, Version 2.0 (see LICENSE).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterator, List, Mapping, Optional, Sequence, Tuple, Union

from assetsuite.client import QRadarClient

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# Asset ids per "id IN (...)" filter, to keep URLs short.
ID_CHUNK = 100

ASSET_COLUMNS = [
    "id",
    "domain_id",
    "domain_name",
    "ip_addresses",
    "mac_addresses",
    "dns_names",
    "netbios_names",
    "users",
    "products",
    "vulnerability_count",
    "risk_score_sum",
    "first_seen",
    "last_seen",
]
# Extra columns in one-row-per-IP mode, inserted after domain_name.
IP_COLUMNS = ["ip_address", "ip_type", "network_id", "mac_address"]

MULTI_VALUE_SEPARATOR = ";"


class LookupFailed(Exception):
    """A domain, property or saved search given by the user does not exist."""


# --- API reads ---------------------------------------------------------------


def list_properties(client: QRadarClient) -> List[dict]:
    return client.get_all("asset_model/properties")


def list_saved_searches(client: QRadarClient) -> List[dict]:
    return client.get_all("asset_model/saved_searches")


def find_saved_search(client: QRadarClient, ref: str) -> dict:
    """Saved search by id or by name (case-insensitive)."""
    searches = list_saved_searches(client)
    if ref.isdigit():
        matches = [s for s in searches if s.get("id") == int(ref)]
    else:
        matches = [s for s in searches if str(s.get("name", "")).casefold() == ref.casefold()]
    if not matches:
        raise LookupFailed(f"No asset saved search '{ref}' (see the saved-searches command)")
    if len(matches) > 1:
        ids = ", ".join(str(s.get("id")) for s in matches)
        raise LookupFailed(f"Several saved searches are named '{ref}' (ids {ids}): use the id")
    return matches[0]


def saved_search_asset_ids(client: QRadarClient, search_id: int) -> List[int]:
    results = client.get_all(f"asset_model/saved_searches/{search_id}/results", params={"fields": "id"})
    return [int(r["id"]) for r in results if r.get("id") is not None]


def fetch_assets(
    client: QRadarClient, domain_id: Optional[int] = None, asset_ids: Optional[Sequence[int]] = None
) -> List[dict]:
    """All assets, optionally restricted to a domain and/or a set of ids (filtered by QRadar)."""
    domain_filter = f"domain_id = {int(domain_id)}" if domain_id is not None else None
    if asset_ids is None:
        return client.get_all("asset_model/assets", params={"filter": domain_filter} if domain_filter else None)

    assets: List[dict] = []
    for start in range(0, len(asset_ids), ID_CHUNK):
        chunk = ",".join(str(int(i)) for i in asset_ids[start : start + ID_CHUNK])
        conditions = [f"id IN ({chunk})"] + ([domain_filter] if domain_filter else [])
        assets.extend(client.get_all("asset_model/assets", params={"filter": " and ".join(conditions)}))
    return assets


# --- Asset helpers -----------------------------------------------------------


def ms_to_datetime(value: object) -> Optional[datetime]:
    if value in (None, ""):
        return None
    try:
        return datetime.fromtimestamp(int(value) / 1000, tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def format_datetime(value: Optional[datetime]) -> str:
    return value.isoformat(timespec="seconds") if value else ""


def iter_ips(asset: Mapping) -> Iterator[Tuple[dict, dict]]:
    """(ip_address, interface) pairs of an asset."""
    for interface in asset.get("interfaces") or []:
        for ip in interface.get("ip_addresses") or []:
            yield ip, interface


def _timestamps(asset: Mapping, keys: Sequence[str]) -> List[datetime]:
    records: List[Mapping] = []
    for interface in asset.get("interfaces") or []:
        records.append(interface)
        records.extend(interface.get("ip_addresses") or [])
    records.extend(asset.get("hostnames") or [])
    values = (ms_to_datetime(record.get(key)) for record in records for key in keys)
    return [value for value in values if value is not None]


def last_seen(asset: Mapping) -> Optional[datetime]:
    """Latest passive (profiler) or scanner sighting of an interface, IP or hostname."""
    return max(_timestamps(asset, ("last_seen_profiler", "last_seen_scanner")), default=None)


def first_seen(asset: Mapping) -> Optional[datetime]:
    return min(_timestamps(asset, ("created", "first_seen_profiler", "first_seen_scanner")), default=None)


def property_values(asset: Mapping) -> Dict[str, str]:
    return {
        str(p.get("name")): "" if p.get("value") is None else str(p.get("value")) for p in asset.get("properties") or []
    }


def parse_ip(value: str) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


# --- Filtering ---------------------------------------------------------------


@dataclass
class AssetFilter:
    """Filters applied locally, after the domain / saved search filtering done by QRadar."""

    networks: List[IPNetwork] = field(default_factory=list)
    seen_within_days: Optional[int] = None
    not_seen_for_days: Optional[int] = None
    properties: Dict[str, str] = field(default_factory=dict)  # name -> value, "" = empty or missing
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def ip_matches(self, value: str) -> bool:
        if not self.networks:
            return True
        ip = parse_ip(value)
        return ip is not None and any(ip.version == net.version and ip in net for net in self.networks)

    def matches(self, asset: Mapping) -> bool:
        if self.networks and not any(self.ip_matches(str(ip.get("value"))) for ip, _ in iter_ips(asset)):
            return False

        seen = last_seen(asset)
        if self.seen_within_days is not None:
            if seen is None or seen < self.now - timedelta(days=self.seen_within_days):
                return False
        if self.not_seen_for_days is not None:
            if seen is not None and seen >= self.now - timedelta(days=self.not_seen_for_days):
                return False

        values = property_values(asset)
        for name, expected in self.properties.items():
            actual = values.get(name, "")
            if expected == "" and actual.strip():
                return False
            if expected != "" and actual != expected:
                return False
        return True


# --- Flattening --------------------------------------------------------------


def export_columns(property_names: Sequence[str], per_ip: bool) -> List[str]:
    base = list(ASSET_COLUMNS)
    if per_ip:
        position = base.index("domain_name") + 1
        base[position:position] = IP_COLUMNS
    return base + list(property_names)


def _join(values: Sequence[object]) -> str:
    unique: List[str] = []
    for value in values:
        text = "" if value is None else str(value)
        if text and text not in unique:
            unique.append(text)
    return MULTI_VALUE_SEPARATOR.join(unique)


def _product(product: Mapping) -> str:
    return " ".join(str(product.get(key)) for key in ("vendor", "name", "version") if product.get(key))


def asset_rows(
    asset: Mapping,
    property_names: Sequence[str],
    domain_names: Mapping[int, str],
    per_ip: bool = False,
    asset_filter: Optional[AssetFilter] = None,
) -> Iterator[Dict[str, object]]:
    """
    Export rows for one asset: a single row, or one row per IP address.

    In per-IP mode, only the IPs inside the filter networks are kept, and an
    asset without any IP still gets one row so that it is not lost.
    """
    hostnames = asset.get("hostnames") or []
    values = property_values(asset)
    row: Dict[str, object] = {
        "id": asset.get("id"),
        "domain_id": asset.get("domain_id"),
        "domain_name": domain_names.get(asset.get("domain_id"), ""),
        "ip_addresses": _join([ip.get("value") for ip, _ in iter_ips(asset)]),
        "mac_addresses": _join([i.get("mac_address") for i in asset.get("interfaces") or []]),
        "dns_names": _join([h.get("name") for h in hostnames if h.get("type") == "DNS"]),
        "netbios_names": _join([h.get("name") for h in hostnames if h.get("type") == "NETBIOS"]),
        "users": _join([u.get("username") for u in asset.get("users") or []]),
        "products": _join([_product(p) for p in asset.get("products") or []]),
        "vulnerability_count": asset.get("vulnerability_count"),
        "risk_score_sum": asset.get("risk_score_sum"),
        "first_seen": format_datetime(first_seen(asset)),
        "last_seen": format_datetime(last_seen(asset)),
    }
    row.update({name: values.get(name, "") for name in property_names})

    if not per_ip:
        yield row
        return

    ips = [(ip, interface) for ip, interface in iter_ips(asset)]
    if asset_filter is not None:
        ips = [(ip, interface) for ip, interface in ips if asset_filter.ip_matches(str(ip.get("value")))]
    if not ips:
        yield {**row, "ip_address": "", "ip_type": "", "network_id": "", "mac_address": ""}
        return
    for ip, interface in ips:
        yield {
            **row,
            "ip_address": ip.get("value"),
            "ip_type": ip.get("type"),
            "network_id": ip.get("network_id"),
            "mac_address": interface.get("mac_address") or "",
        }
