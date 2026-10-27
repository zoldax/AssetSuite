"""
importer.py

Turns a CSV file into an import plan: which existing assets get which
property changes, which rows describe assets QRadar does not know yet, and
which rows are invalid. Nothing is written to QRadar here (see writer.py), so
the plan doubles as the dry run.

The CSV format is the one produced by the export command, so an export can be
edited and imported back. Rows are matched to assets by, in this order:
id, IP address, MAC address, DNS name, NETBIOS name, within the row's domain
when one is given. An empty property cell means "leave unchanged".

Copyright 2026 Pascal Weber (zoldax) / Abakus Sécurité
Licensed under the Apache License, Version 2.0 (see LICENSE).
"""

from __future__ import annotations

import csv
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from assetsuite.assets import iter_ips, parse_ip, property_values
from assetsuite.export import FORMULA_PREFIXES

IDENTITY_COLUMNS = (
    "id",
    "domain_id",
    "domain_name",
    "ip_address",
    "ip_addresses",
    "mac_address",
    "mac_addresses",
    "dns_names",
    "netbios_names",
)
MATCH_COLUMNS = ("id", "ip_address", "ip_addresses", "mac_address", "mac_addresses", "dns_names", "netbios_names")
# Export columns computed by QRadar: accepted in the file, never imported.
READ_ONLY_COLUMNS = (
    "users",
    "products",
    "vulnerability_count",
    "risk_score_sum",
    "first_seen",
    "last_seen",
    "ip_type",
    "network_id",
)
DEFAULT_DOMAIN_NAME = "DEFAULT_DOMAIN"

# Limits of the asset creation API (POST and PATCH /asset_model/assets).
MAX_CREATE_IPS = 2
MAX_HOSTNAME_LENGTH = 255
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
NO_IP_REASON = "the asset has no IP address: QRadar refuses property updates on it (HTTP 422)"
# Hostname placeholder QRadar stores when a NETBIOS name is unknown.
NO_HOSTNAME = "-"


class ImportFileError(Exception):
    """The file as a whole cannot be imported (format, header, columns)."""


class RowError(Exception):
    """One row cannot be imported."""


@dataclass
class ImportRow:
    line: int
    values: Dict[str, str]


@dataclass
class PropertyChange:
    name: str
    type_id: int
    old: str
    new: str


@dataclass
class Update:
    asset_id: int
    domain_id: Optional[int]
    label: str
    lines: List[int] = field(default_factory=list)
    changes: Dict[str, PropertyChange] = field(default_factory=dict)


@dataclass
class Creation:
    line: int
    domain_id: int
    ips: List[str]
    mac: Optional[str]
    dns: Optional[str]
    netbios: Optional[str]
    properties: Dict[str, str]

    @property
    def label(self) -> str:
        return ", ".join([*self.ips, *(name for name in (self.dns, self.netbios) if name)])


@dataclass
class RowIssue:
    line: int
    message: str


@dataclass
class ImportPlan:
    header: List[str]
    property_columns: List[str]
    updates: Dict[int, Update] = field(default_factory=dict)
    creations: List[Creation] = field(default_factory=list)
    unchanged: List[Tuple[int, int]] = field(default_factory=list)  # (line, asset_id)
    not_found: List[Tuple[ImportRow, str]] = field(default_factory=list)  # rows left aside, with the reason
    errors: List[RowIssue] = field(default_factory=list)
    # Rows matching an asset that QRadar will not let us update: (line, asset_id, reason).
    skipped: List[Tuple[int, int, str]] = field(default_factory=list)

    @property
    def has_writes(self) -> bool:
        return bool(self.updates or self.creations)


# --- Reading -----------------------------------------------------------------


def unescape(value: str) -> str:
    """Undo the formula escaping of the export ("'=x" -> "=x")."""
    if value.startswith("'") and len(value) > 1 and (value[1] in FORMULA_PREFIXES or value[1] == "-"):
        return value[1:]
    return value


def _guess_delimiter(header_line: str) -> str:
    counts = {delimiter: header_line.count(delimiter) for delimiter in (",", ";", "\t")}
    return max(counts, key=lambda delimiter: counts[delimiter]) if any(counts.values()) else ","


def read_import_file(path: str, delimiter: Optional[str] = None) -> Tuple[List[str], List[ImportRow]]:
    """Header and rows of a CSV file (UTF-8, with or without BOM; delimiter guessed from the header)."""
    try:
        with open(path, encoding="utf-8-sig", newline="") as file:
            header_line = file.readline()
            file.seek(0)
            reader = csv.DictReader(file, delimiter=delimiter or _guess_delimiter(header_line))
            header = [name.strip() for name in reader.fieldnames or []]
            if not header or not any(header):
                raise ImportFileError(f"{path} is empty or has no header line")
            duplicates = sorted({name for name in header if header.count(name) > 1})
            if duplicates:
                raise ImportFileError(f"Duplicate column(s) in {path}: {', '.join(duplicates)}")
            reader.fieldnames = header

            rows = []
            for raw in reader:
                if None in raw:
                    raise ImportFileError(f"Line {reader.line_num} has more fields than the header")
                values = {name: unescape((value or "").strip()) for name, value in raw.items()}
                if any(values.values()):
                    rows.append(ImportRow(reader.line_num, values))
            return header, rows
    except UnicodeDecodeError as e:
        raise ImportFileError(f"{path} is not UTF-8 encoded: {e}") from e
    except csv.Error as e:
        raise ImportFileError(f"{path} is not a valid CSV file: {e}") from e


def _split(value: str) -> List[str]:
    return [part.strip() for part in value.split(";") if part.strip()]


def normalize_mac(value: str) -> str:
    return value.strip().lower().replace("-", ":")


def _row_names(names: Sequence[str]) -> set:
    """Hostnames of a row, lower-case, as given and without domain ("ai-lab.example.lan" -> "ai-lab")."""
    result = set()
    for name in names:
        name = name.strip().lower()
        if name and name != NO_HOSTNAME:
            result.update({name, name.split(".")[0]})
    return result


def _host_names(asset: Mapping) -> set:
    return _row_names([str(h.get("name") or "") for h in asset.get("hostnames") or []])


def _break_tie(candidates: Sequence[Mapping], macs: Sequence[str], names: Sequence[str]) -> Optional[Mapping]:
    """
    One asset among several sharing a key (e.g. an IP reused by DHCP): the
    asset with the row's MAC, else the first row name (in the row's order,
    full then short) carried by exactly one of them.
    """
    if macs:
        with_mac = [
            a
            for a in candidates
            if {normalize_mac(str(i.get("mac_address") or "")) for i in a.get("interfaces") or []} & set(macs)
        ]
        if len(with_mac) == 1:
            return with_mac[0]
    for name in names:
        name = name.strip().lower()
        if not name or name == NO_HOSTNAME:
            continue
        for variant in dict.fromkeys((name, name.split(".")[0])):
            holders = [a for a in candidates if variant in _host_names(a)]
            if len(holders) == 1:
                return holders[0]
    return None


# --- Planning ----------------------------------------------------------------


class Planner:
    """Builds an ImportPlan from the current assets, the property catalog and the domains."""

    def __init__(
        self,
        assets: Sequence[Mapping],
        catalog: Sequence[Mapping],
        domains: Sequence[Mapping],
        default_domain_id: Optional[int] = None,
        can_create: bool = False,
        create_blocked_reason: str = "",
        fill_empty_only: bool = False,
    ):
        self.catalog = {str(p["name"]): p for p in catalog}
        self.domains = {int(d["id"]): str(d.get("name") or "") for d in domains if d.get("id") is not None}
        self.default_domain_id = default_domain_id
        self.can_create = can_create
        self.create_blocked_reason = create_blocked_reason
        # Only set properties that are empty in QRadar, never overwrite a value.
        self.fill_empty_only = fill_empty_only

        self.by_id: Dict[int, Mapping] = {}
        self.by_ip: Dict[str, List[Mapping]] = defaultdict(list)
        self.by_mac: Dict[str, List[Mapping]] = defaultdict(list)
        self.by_dns: Dict[str, List[Mapping]] = defaultdict(list)
        self.by_netbios: Dict[str, List[Mapping]] = defaultdict(list)
        for asset in assets:
            self.by_id[int(asset["id"])] = asset
            for ip, _ in iter_ips(asset):
                self._index(self.by_ip, str(ip.get("value", "")), asset)
            for interface in asset.get("interfaces") or []:
                self._index(self.by_mac, normalize_mac(str(interface.get("mac_address") or "")), asset)
            for hostname in asset.get("hostnames") or []:
                index = self.by_dns if hostname.get("type") == "DNS" else self.by_netbios
                self._index(index, str(hostname.get("name") or ""), asset)

        self._seen_values: Dict[int, Dict[str, Tuple[str, int]]] = defaultdict(dict)
        self._created_keys: Dict[str, int] = {}

    @staticmethod
    def _index(index: Dict[str, List[Mapping]], key: str, asset: Mapping) -> None:
        key = key.strip().lower()
        if key and key != NO_HOSTNAME and asset not in index[key]:
            index[key].append(asset)

    def plan(self, header: Sequence[str], rows: Sequence[ImportRow]) -> ImportPlan:
        unknown = [
            c for c in header if c not in IDENTITY_COLUMNS and c not in READ_ONLY_COLUMNS and c not in self.catalog
        ]
        if unknown:
            raise ImportFileError(
                f"Unknown column(s): {', '.join(unknown)}. Property columns must be named exactly as in "
                "the properties command (case-sensitive)"
            )
        if not any(c in header for c in MATCH_COLUMNS):
            raise ImportFileError(
                f"The file needs at least one of these columns to find assets: {', '.join(MATCH_COLUMNS)}"
            )

        plan = ImportPlan(header=list(header), property_columns=[c for c in header if c in self.catalog])
        for row in rows:
            try:
                self._plan_row(plan, row)
            except RowError as e:
                plan.errors.append(RowIssue(row.line, str(e)))
        return plan

    def _plan_row(self, plan: ImportPlan, row: ImportRow) -> None:
        values = row.values
        domain_id = self._row_domain(values)
        properties = self._row_properties(values, plan.property_columns)
        ips = list(dict.fromkeys(_split(values.get("ip_address", "")) + _split(values.get("ip_addresses", ""))))
        macs = list(
            dict.fromkeys(
                normalize_mac(m)
                for m in _split(values.get("mac_address", "")) + _split(values.get("mac_addresses", ""))
            )
        )
        dns = [name for name in _split(values.get("dns_names", "")) if name != NO_HOSTNAME]
        netbios = [name for name in _split(values.get("netbios_names", "")) if name != NO_HOSTNAME]

        asset = self._match(values.get("id", ""), domain_id, ips, macs, dns, netbios)
        if asset is None:
            self._plan_creation(plan, row, domain_id, ips, macs, dns, netbios, properties)
        else:
            self._plan_update(plan, row.line, asset, properties)

    def _row_domain(self, values: Mapping[str, str]) -> Optional[int]:
        domain_id = None
        raw_id = values.get("domain_id", "")
        if raw_id:
            if not raw_id.isdigit() or int(raw_id) not in self.domains:
                raise RowError(f"unknown domain_id '{raw_id}'")
            domain_id = int(raw_id)

        name = values.get("domain_name", "")
        if name:
            matches = [
                i
                for i, n in self.domains.items()
                if name.casefold() == (n or (DEFAULT_DOMAIN_NAME if i == 0 else "")).casefold()
            ]
            if not matches:
                raise RowError(f"unknown domain_name '{name}'")
            if domain_id is not None and domain_id != matches[0]:
                raise RowError(f"domain_id {domain_id} and domain_name '{name}' do not match")
            domain_id = matches[0]

        return domain_id if domain_id is not None else self.default_domain_id

    def _row_properties(self, values: Mapping[str, str], columns: Sequence[str]) -> Dict[str, str]:
        properties = {}
        for name in columns:
            value = values.get(name, "")
            if not value:
                continue
            data_type = str(self.catalog[name].get("data_type", "TEXT")).upper()
            if data_type == "NUMERIC":
                try:
                    float(value)
                except ValueError:
                    raise RowError(f"'{name}' must be a number, got '{value}'") from None
            elif data_type == "BOOLEAN":
                if value.lower() not in ("true", "false"):
                    raise RowError(f"'{name}' must be true or false, got '{value}'")
                value = value.lower()
            properties[name] = value
        return properties

    def _match(
        self,
        raw_id: str,
        domain_id: Optional[int],
        ips: Sequence[str],
        macs: Sequence[str],
        dns: Sequence[str],
        netbios: Sequence[str],
    ) -> Optional[Mapping]:
        if raw_id:
            if not raw_id.isdigit():
                raise RowError(f"invalid asset id '{raw_id}'")
            asset = self.by_id.get(int(raw_id))
            if asset is None:
                raise RowError(f"asset id {raw_id} does not exist")
            if domain_id is not None and asset.get("domain_id") != domain_id:
                raise RowError(f"asset {raw_id} is in domain {asset.get('domain_id')}, not {domain_id}")
            return asset

        for label, keys, index in (
            ("IP", ips, self.by_ip),
            ("MAC", macs, self.by_mac),
            ("DNS name", dns, self.by_dns),
            ("NETBIOS name", netbios, self.by_netbios),
        ):
            found = {
                int(asset["id"]): asset
                for key in keys
                for asset in index.get(key.lower(), [])
                if domain_id is None or asset.get("domain_id") == domain_id
            }
            if len(found) == 1:
                return next(iter(found.values()))
            if len(found) > 1:
                chosen = _break_tie(list(found.values()), macs, [*dns, *netbios])
                if chosen is not None:
                    return chosen
                ids = ", ".join(str(i) for i in sorted(found))
                raise RowError(f"{label} {', '.join(keys)} matches several assets ({ids}): add the id or domain column")
        return None

    def _plan_update(self, plan: ImportPlan, line: int, asset: Mapping, properties: Mapping[str, str]) -> None:
        asset_id = int(asset["id"])
        seen = self._seen_values[asset_id]
        for name, value in properties.items():
            if name in seen and not self._same(name, seen[name][0], value):
                raise RowError(f"'{name}' of asset {asset_id} is set to '{seen[name][0]}' on line {seen[name][1]}")
        for name, value in properties.items():
            seen.setdefault(name, (value, line))

        current = property_values(asset)
        changes = {
            name: PropertyChange(name, int(self.catalog[name]["id"]), current.get(name, ""), value)
            for name, value in properties.items()
            if not self._same(name, current.get(name, ""), value)
            and not (self.fill_empty_only and current.get(name, "").strip())
        }

        if changes and not any(True for _ in iter_ips(asset)):
            # QRadar checks permissions on the asset's domain and IP: without an IP it answers
            # HTTP 422 "Could not get domainId or ipAddress for asset" to any property update.
            plan.skipped.append((line, asset_id, NO_IP_REASON))
            return

        update = plan.updates.get(asset_id)
        if not changes and update is None:
            plan.unchanged.append((line, asset_id))
            return
        if update is None:
            label = ", ".join(str(ip.get("value")) for ip, _ in iter_ips(asset)) or str(
                next((h.get("name") for h in asset.get("hostnames") or []), "")
            )
            update = plan.updates[asset_id] = Update(asset_id, asset.get("domain_id"), label)
        update.lines.append(line)
        update.changes.update(changes)

    def _same(self, name: str, old: str, new: str) -> bool:
        if str(self.catalog[name].get("data_type", "")).upper() == "NUMERIC":
            try:
                return float(old) == float(new)
            except ValueError:
                return old == new
        return old == new

    def _plan_creation(
        self,
        plan: ImportPlan,
        row: ImportRow,
        domain_id: Optional[int],
        ips: Sequence[str],
        macs: Sequence[str],
        dns: Sequence[str],
        netbios: Sequence[str],
        properties: Mapping[str, str],
    ) -> None:
        if not self.can_create:
            plan.not_found.append((row, self.create_blocked_reason))
            return

        problems = []
        if not ips:
            problems.append("an IP address is required to create an asset")
        if len(ips) > MAX_CREATE_IPS:
            problems.append(f"QRadar accepts at most {MAX_CREATE_IPS} IPs for a new asset, got {len(ips)}")
        for value in ips:
            ip = parse_ip(value)
            if ip is None:
                problems.append(f"invalid IP '{value}'")
            elif ip.version == 6 and ip.is_link_local:
                problems.append(f"IPv6 link-local {value} is not accepted by QRadar")
        if len(macs) > 1:
            problems.append("a new asset has one interface, so one MAC address")
        if macs and not _MAC.match(macs[0]):
            problems.append(f"invalid MAC '{macs[0]}'")
        for label, names in (("DNS", dns), ("NETBIOS", netbios)):
            if len(names) > 1:
                problems.append(f"a new asset takes one {label} name, got {len(names)}")
            if any(len(name) > MAX_HOSTNAME_LENGTH for name in names):
                problems.append(f"{label} name longer than {MAX_HOSTNAME_LENGTH} characters")
        if domain_id is None:
            if len(self.domains) > 1:
                problems.append("domain unknown: add a domain_id or domain_name column, or use --domain")
            else:
                domain_id = next(iter(self.domains), 0)
        for value in ips:
            if value in self._created_keys:
                problems.append(f"IP {value} is already created by line {self._created_keys[value]}")
        if problems:
            raise RowError("; ".join(problems))

        for value in ips:
            self._created_keys[value] = row.line
        plan.creations.append(
            Creation(
                line=row.line,
                domain_id=int(domain_id),
                ips=list(ips),
                mac=macs[0] if macs else None,
                dns=dns[0] if dns else None,
                netbios=netbios[0] if netbios else None,
                properties=dict(properties),
            )
        )


# --- Payloads ----------------------------------------------------------------


def creation_payload(
    creation: Creation, catalog: Mapping[str, Mapping], domains: Mapping[int, str], bulk: bool
) -> dict:
    """
    Body for POST /asset_model/assets (bulk=False) or one item of PATCH /asset_model/assets (bulk=True).

    The single create names the domain and the properties; the bulk API uses their ids.
    """
    interface: dict = {"ip_addresses": [{"value": ip} for ip in creation.ips]}
    if creation.mac:
        interface["mac_address"] = creation.mac
    payload: dict = {"interfaces": [interface]}

    hostnames = [
        {"name": name, "type": kind} for name, kind in ((creation.dns, "DNS"), (creation.netbios, "NETBIOS")) if name
    ]
    if hostnames:
        payload["hostnames"] = hostnames

    if bulk:
        payload["domain_id"] = creation.domain_id
        properties = [
            {"type_id": int(catalog[name]["id"]), "value": value} for name, value in creation.properties.items()
        ]
    else:
        # The default domain (id 0) has no name in the API: leave it implicit.
        if creation.domain_id != 0 and domains.get(creation.domain_id):
            payload["domain_name"] = domains[creation.domain_id]
        properties = [{"name": name, "value": value} for name, value in creation.properties.items()]
    if properties:
        payload["properties"] = properties
    return payload
