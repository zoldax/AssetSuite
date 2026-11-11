"""
reconciliation.py

The identifiers QRadar leaves out of its asset reconciliation, read only.

QRadar builds its assets from what it observes (IP and MAC addresses, DNS and
NetBIOS names). An identifier seen with too many others (a DHCP or NAT
address, a generic name, a shared virtual MAC) would merge several machines
into one asset: the system rules "AssetExclusion: Exclude <X> By <Y>" put it in
a reference set "Asset Reconciliation <IPv4|DNS|MAC|NetBIOS> Blacklist", and
QRadar no longer uses it to match an asset. The "... Whitelist" sets hold the
identifiers the rules must leave alone. Observed on QRadar 7.6.0 FP1: the
blacklists expire 7 days after an element was last seen, the whitelists never;
no IPv6 set. The newer names "Blocklist" and "Allowlist" are read too.

Read with /reference_data_collections (API 17.0+), or /reference_data/sets on
an older QRadar. Changed (an entry added to a list, or removed from it) with
/reference_data_collections only, by plan_change then apply_change: the CLI
with --apply, the QRadar App with the session of an administrator.

Copyright 2026 Pascal Weber (zoldax) / Abakus Sécurité
Licensed under the Apache License, Version 2.0 (see LICENSE).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Mapping, Optional, Tuple
from urllib.parse import quote

from assetsuite.assets import format_datetime, iter_ips
from assetsuite.client import QRadarAPIError, QRadarClient
from assetsuite.importer import NO_HOSTNAME, normalize_mac

PREFIX = "Asset Reconciliation "
SET_NAME = re.compile(
    r"^Asset Reconciliation (IPv4|IPv6|DNS|MAC|NetBIOS) (Blacklist|Blocklist|Whitelist|Allowlist)$", re.I
)
KINDS = {"ipv4": "ip", "ipv6": "ip", "dns": "dns", "mac": "mac", "netbios": "netbios"}
KIND_LABELS = {"ip": "IP address", "mac": "MAC address", "dns": "DNS name", "netbios": "NetBIOS name"}
EXCLUDED, KEPT = "excluded", "kept"  # on a blacklist / on a whitelist
ADD, REMOVE = "add", "remove"
LIST_NAMES = {EXCLUDED: "blacklist", KEPT: "whitelist"}
_MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
_NAME = re.compile(r"^[^\s,;]{1,255}$")
LEGACY_PAGE = 1000
_UNITS = {"year": 365 * 86400, "mon": 30 * 86400, "week": 7 * 86400, "day": 86400, "hour": 3600, "min": 60, "sec": 1}


@dataclass(frozen=True)
class Exclusion:
    kind: str  # ip, mac, dns, netbios
    value: str
    listed: str  # EXCLUDED (blacklist) or KEPT (whitelist)
    set_name: str
    source: str  # the rule, or what added it by hand
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    expires: Optional[datetime]  # None: never
    domain_id: Optional[int]  # None: every domain
    entry_id: Optional[int] = None  # to remove it (collections API only)
    notes: str = ""


class ReconciliationError(Exception):
    """A change of a reconciliation list that cannot be made: nothing was written."""


@dataclass
class ReconciliationLists:
    sets: List[str] = field(default_factory=list)  # the names found on this QRadar
    entries: List[Exclusion] = field(default_factory=list)
    set_ids: Dict[str, int] = field(default_factory=dict)  # name -> id, to write (collections API only)
    _index: Dict[Tuple[str, str], List[Exclusion]] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        for entry in self.entries:
            self._index.setdefault((entry.kind, key(entry.kind, entry.value)), []).append(entry)

    def lookup(self, kind: str, value: str, domain_id: Optional[int] = None) -> List[Exclusion]:
        """The entries of this identifier that apply to an asset of this domain."""
        found = self._index.get((kind, key(kind, value)), [])
        return [e for e in found if e.domain_id is None or e.domain_id == domain_id]


def key(kind: str, value: str) -> str:
    """The form two identifiers are compared in: MAC normalized, names ignoring case (the sets ignore it)."""
    value = str(value).strip()
    if kind == "mac":
        return normalize_mac(value)
    return value if kind == "ip" else value.lower()


def _time(ms: object) -> Optional[datetime]:
    try:
        return datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc) if ms else None  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return None


def ttl_seconds(value: object) -> Optional[int]:
    """The time to live of a set: milliseconds (collections API) or an interval text such as "7 days" (older API)."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return int(value) // 1000 or None
    total = 0
    for number, unit in re.findall(r"(\d+)\s*([a-z]+)", str(value).lower()):
        seconds = next((s for name, s in _UNITS.items() if unit.startswith(name)), None)
        if seconds is None:
            return None
        total += int(number) * seconds
    return total or None


def _expires(
    first: Optional[datetime], last: Optional[datetime], ttl: Optional[int], expiry: str
) -> Optional[datetime]:
    if not ttl:
        return None
    since = last if expiry.upper() == "LAST_SEEN" else first if expiry.upper() == "FIRST_SEEN" else None
    return since + timedelta(seconds=ttl) if since else None


def _set_type(name: str) -> Tuple[str, str, str]:
    """(kind, listed, IP version or "") of a reconciliation set name."""
    match = SET_NAME.match(name)
    family, list_type = match.group(1).lower(), match.group(2).lower()  # type: ignore[union-attr]
    listed = EXCLUDED if list_type in ("blacklist", "blocklist") else KEPT
    return KINDS[family], listed, family if family.startswith("ipv") else ""


def _entry(meta: Mapping, item: Mapping, ttl: Optional[int], expiry: str) -> Exclusion:
    kind, listed, _ = _set_type(meta["name"])
    first, last = _time(item.get("first_seen")), _time(item.get("last_seen"))
    domain = item.get("domain_id")
    return Exclusion(
        kind,
        str(item.get("value", "")),
        listed,
        meta["name"],
        str(item.get("source") or ""),
        first,
        last,
        _expires(first, last, ttl, expiry),
        int(domain) if domain is not None else None,
        int(item["id"]) if item.get("id") is not None else None,
        str(item.get("notes") or ""),
    )


def _read_collections(client: QRadarClient) -> ReconciliationLists:
    found = client.get_all("reference_data_collections/sets", params={"filter": f'name ILIKE "{PREFIX}%"'})
    sets = {int(s["id"]): s for s in found if SET_NAME.match(str(s.get("name", "")))}
    entries: List[Exclusion] = []
    if sets:
        ids = ", ".join(str(i) for i in sorted(sets))
        for item in client.get_all(
            "reference_data_collections/set_entries", params={"filter": f"collection_id IN ({ids})"}
        ):
            meta = sets.get(int(item.get("collection_id", -1)))
            if meta:
                entries.append(
                    _entry(meta, item, ttl_seconds(meta.get("time_to_live")), str(meta.get("expiry_type", "")))
                )
    names = sorted(s["name"] for s in sets.values())
    return ReconciliationLists(names, entries, {s["name"]: set_id for set_id, s in sets.items()})


def _read_legacy(client: QRadarClient) -> ReconciliationLists:
    found = client.get("reference_data/sets", params={"filter": f'name ILIKE "{PREFIX}%"'}) or []
    sets = [s for s in found if SET_NAME.match(str(s.get("name", "")))]
    entries: List[Exclusion] = []
    for meta in sets:
        ttl, expiry = ttl_seconds(meta.get("time_to_live")), str(meta.get("timeout_type", ""))
        offset = 0
        while True:
            page = client.get(
                f"reference_data/sets/{quote(meta['name'])}", params={"limit": LEGACY_PAGE, "offset": offset}
            )
            data = (page or {}).get("data") or []
            entries += [_entry(meta, item, ttl, expiry) for item in data]
            if len(data) < LEGACY_PAGE:
                break
            offset += LEGACY_PAGE
    return ReconciliationLists(sorted(s["name"] for s in sets), entries)


def read_lists(client: QRadarClient) -> ReconciliationLists:
    """The reconciliation blacklists and whitelists of this QRadar. QRadarAPIError when it refuses to give them."""
    try:
        return _read_collections(client)
    except QRadarAPIError as e:
        if e.status != 404:  # 404: no collections API in this version
            raise
    return _read_legacy(client)


def identifiers(asset: Mapping) -> List[Tuple[str, str]]:
    """The (kind, value) identifiers of an asset that QRadar reconciles on, each once."""
    found: Dict[Tuple[str, str], str] = {}
    for ip, _ in iter_ips(asset):
        if ip.get("value"):
            found.setdefault(("ip", key("ip", ip["value"])), str(ip["value"]))
    for interface in asset.get("interfaces") or []:
        if interface.get("mac_address"):
            found.setdefault(("mac", key("mac", interface["mac_address"])), str(interface["mac_address"]))
    for hostname in asset.get("hostnames") or []:
        kind = {"DNS": "dns", "NETBIOS": "netbios"}.get(str(hostname.get("type", "")).upper())
        if kind and hostname.get("name") and hostname["name"] != NO_HOSTNAME:  # "-": QRadar's empty name
            found.setdefault((kind, key(kind, hostname["name"])), str(hostname["name"]))
    return [(kind, value) for (kind, _), value in found.items()]


def for_asset(asset: Mapping, lists: ReconciliationLists) -> List[Tuple[str, str, Exclusion]]:
    """(kind, value of the asset, entry) for each identifier of the asset on a list, excluded ones first."""
    matches = [
        (kind, value, entry)
        for kind, value in identifiers(asset)
        for entry in lists.lookup(kind, value, asset.get("domain_id"))
    ]
    return sorted(matches, key=lambda m: (m[2].listed != EXCLUDED, list(KIND_LABELS).index(m[0]), m[1]))


def when(value: Optional[datetime]) -> str:
    return value.strftime("%Y-%m-%d %H:%M UTC") if value else ""


def describe(entry: Exclusion) -> str:
    """One line on an entry, for a finding: since when, by what, until when (ISO dates, as the other findings)."""
    if entry.listed == KEPT:
        text = "on the reconciliation whitelist"
        if entry.first_seen:
            text += f" since {format_datetime(entry.first_seen)}"
        return text + (f", by {entry.source}" if entry.source else "")
    text = "excluded from reconciliation"
    if entry.first_seen:
        text += f" since {format_datetime(entry.first_seen)}"
    if entry.source:
        text += f", by {entry.source}"
    if entry.expires:
        text += f", until {format_datetime(entry.expires)}"
    return text


# --- Changes -----------------------------------------------------------------


@dataclass
class ListChange:
    """An entry to add to a reconciliation list, or to remove from it."""

    action: str  # ADD or REMOVE
    kind: str
    value: str  # as it is written (normalized)
    listed: str  # the list changed: EXCLUDED (blacklist) or KEPT (whitelist)
    set_name: str
    set_id: int
    existing: Optional[Exclusion]  # the entry already on that list, if any

    def text(self) -> str:
        """What the change does, in one sentence."""
        what = f"{KIND_LABELS[self.kind]} {self.value}"
        if self.action == REMOVE:
            effect = (
                "QRadar matches assets on it again, unless its rules exclude it again"
                if self.listed == EXCLUDED
                else "QRadar's exclusion rules may exclude it again"
            )
            return f"Remove {what} from {self.set_name}: {effect}."
        if self.listed == EXCLUDED:
            again = " again (its time to live starts over)" if self.existing else ""
            return f"Add {what} to {self.set_name}{again}: QRadar no longer matches assets on it."
        return f"Add {what} to {self.set_name}: QRadar's exclusion rules leave it alone."


def normalize_value(kind: str, value: str) -> str:
    """The value of an identifier as it is written to a list; ReconciliationError when it is not one."""
    value = str(value or "").strip()
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as e:
            raise ReconciliationError(f"Not an IP address: {value!r}") from e
    if kind == "mac":
        mac = normalize_mac(value)
        if not _MAC.match(mac):
            raise ReconciliationError(f"Not a MAC address: {value!r}")
        return mac
    if kind in ("dns", "netbios"):
        if not _NAME.match(value):
            raise ReconciliationError(f"Not a {KIND_LABELS[kind]}: {value!r}")
        return value
    raise ReconciliationError(f"Unknown identifier kind {kind!r}: {', '.join(KIND_LABELS)}")


def plan_change(lists: ReconciliationLists, action: str, kind: str, value: str, listed: str) -> ListChange:
    """
    The change to make, checked against the lists as QRadar has them now:
    ReconciliationError when it cannot be made (no such list, nothing to
    remove, already on the other list). Adding a value already on the same
    blacklist adds it again: its time to live starts over.
    """
    if action not in (ADD, REMOVE) or listed not in LIST_NAMES:
        raise ReconciliationError(f"Unknown change: {action} {listed}")
    value = normalize_value(kind, value)
    family = f"ipv{ipaddress.ip_address(value).version}" if kind == "ip" else ""
    sets = [n for n in lists.sets if _set_type(n) == (kind, listed, family)]
    if not sets:
        wanted = f"{family.replace('ipv', 'IPv') or KIND_LABELS[kind]} {LIST_NAMES[listed]}"
        raise ReconciliationError(f"This QRadar has no asset reconciliation {wanted}")
    if sets[0] not in lists.set_ids:
        raise ReconciliationError("Changing the lists needs the reference data collections API (QRadar API 17.0+)")
    found = [e for e in lists.lookup(kind, value) if e.set_name == sets[0] and e.domain_id is None]
    existing = found[0] if found else None
    if action == REMOVE and not existing:
        raise ReconciliationError(f"{KIND_LABELS[kind]} {value} is not on {sets[0]}: nothing to remove")
    if action == ADD:
        other = [e for e in lists.lookup(kind, value) if e.listed != listed]
        if other:
            raise ReconciliationError(
                f"{KIND_LABELS[kind]} {value} is on {other[0].set_name}: remove it from there first"
            )
    return ListChange(action, kind, value, listed, sets[0], lists.set_ids[sets[0]], existing)


def apply_change(client: QRadarClient, change: ListChange, note: str = "") -> Dict[str, object]:
    """Write the change to QRadar. The entry added (as QRadar returns it), or the entry removed."""
    if change.action == REMOVE:
        if change.existing is None or change.existing.entry_id is None:
            raise ReconciliationError(f"No entry to remove for {change.value}")
        # QRadar 7.6 answers this DELETE in text/plain only: HTTP 406 when asked for JSON (seen on the lab).
        client.request(
            "DELETE",
            f"reference_data_collections/set_entries/{change.existing.entry_id}",
            headers={"Accept": "text/plain"},
        )
        return {"id": change.existing.entry_id, "value": change.existing.value, "source": change.existing.source}
    body: Dict[str, object] = {"collection_id": change.set_id, "value": change.value}
    if note:
        body["notes"] = note[:255]
    added = client.post("reference_data_collections/set_entries", json_body=body)
    return dict(added) if isinstance(added, dict) else {"value": change.value}
