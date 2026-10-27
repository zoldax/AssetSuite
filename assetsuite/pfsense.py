"""
pfsense.py

pfSense integration: reads configuration backups (Diagnostics > Backup &
Restore) offline, without touching the firewall, and turns the DNS Resolver
host overrides and the static DHCP mappings into rows of the AssetSuite import
format, one per IP address.

A backup can be complete (<pfsense> root) or limited to one area (<unbound>,
<dhcpd> root). Only the host overrides and the static mappings are read: the
rest of the file, which can hold secrets (DDNS keys, passwords), is ignored.

Copyright 2026 Pascal Weber (zoldax) / Abakus Sécurité
Licensed under the Apache License, Version 2.0 (see LICENSE).
"""

from __future__ import annotations

import glob
import ipaddress
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from assetsuite.assets import IPNetwork, parse_ip
from assetsuite.importer import ImportRow, normalize_mac
from assetsuite.mapping import MappingError, apply_rule, normalize_mapping

DEFAULT_FILES = ("private/*.xml",)

RECORD_FIELDS = (
    "ip",
    "dns_name",
    "host",
    "mac",
    "dns_description",
    "dhcp_description",
    "description",
    "category",
    "interface",
    "source",
)

DEFAULT_MAPPING: Dict[str, Any] = {
    "Given Name": {"first": ["dns_name"]},
    "Description": {"first": ["dns_description", "dhcp_description"]},
    "Asset Type": {"first": ["category"]},
}

# "NAS - DS212", "DOMOTIQUE - Netatmo": an upper-case category before " - ".
_CATEGORY = re.compile(r"^\s*([A-Z0-9][A-Z0-9 /&._]*?)\s*-\s+\S")


class PfSenseError(Exception):
    """The pfSense configuration or backup files cannot be used."""


@dataclass(frozen=True)
class PfSenseConfig:
    files: Tuple[str, ...] = DEFAULT_FILES
    domain: str = "DEFAULT_DOMAIN"
    dns_domain: str = ""
    networks: Tuple[IPNetwork, ...] = ()
    overwrite: bool = False
    mapping: Mapping[str, Mapping[str, Any]] = field(default_factory=lambda: dict(DEFAULT_MAPPING))


def load_pfsense_config(sections: Optional[Mapping[str, Any]]) -> PfSenseConfig:
    """pfSense settings from the "pfsense" section of config.json (all optional)."""
    raw = dict((sections or {}).get("pfsense") or {})
    known = {"files", "domain", "dns_domain", "networks", "overwrite", "mapping"}
    unknown = sorted(set(raw) - known)
    if unknown:
        raise PfSenseError(f"Unknown pfsense setting(s): {', '.join(unknown)}")

    files = raw.get("files", list(DEFAULT_FILES))
    if isinstance(files, str):
        files = [files]
    networks = raw.get("networks", [])
    if isinstance(networks, str):
        networks = [networks]
    try:
        parsed_networks = tuple(ipaddress.ip_network(str(n), strict=False) for n in networks)
    except ValueError as e:
        raise PfSenseError(f"Invalid pfsense.networks value: {e}") from e
    try:
        mapping = normalize_mapping("pfsense", raw.get("mapping", DEFAULT_MAPPING), RECORD_FIELDS)
    except MappingError as e:
        raise PfSenseError(str(e)) from e
    overwrite = raw.get("overwrite", False)
    if not isinstance(overwrite, bool):
        raise PfSenseError("'pfsense.overwrite' must be true or false")

    return PfSenseConfig(
        files=tuple(str(f) for f in files),
        domain=str(raw.get("domain") or "DEFAULT_DOMAIN"),
        dns_domain=str(raw.get("dns_domain") or "").strip("."),
        networks=parsed_networks,
        overwrite=overwrite,
        mapping=mapping,
    )


def resolve_files(patterns: Sequence[str]) -> List[str]:
    files: List[str] = []
    for pattern in patterns:
        matches = sorted(glob.glob(pattern)) if any(c in pattern for c in "*?[") else [pattern]
        files += [f for f in matches if f not in files]
    if not files:
        raise PfSenseError(
            f"No pfSense backup file found ({', '.join(patterns)}): export one from Diagnostics > Backup"
        )
    missing = [f for f in files if not os.path.isfile(f)]
    if missing:
        raise PfSenseError(f"pfSense backup file not found: {', '.join(missing)}")
    return files


# --- Reading -----------------------------------------------------------------


def _text(element: Optional[ET.Element], tag: str) -> str:
    return "" if element is None else (element.findtext(tag) or "").strip()


def _parse(path: str) -> ET.Element:
    with open(path, "rb") as file:
        data = file.read()
    # A pfSense backup never declares entities: refuse them rather than expand them.
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise PfSenseError(f"{path}: XML with a DOCTYPE or entities is refused")
    try:
        # Imported here so that a missing defusedxml only affects pfsense-sync, not the other commands.
        from defusedxml import ElementTree as SafeET
    except ImportError as e:
        raise PfSenseError(
            "The defusedxml package is missing: run 'pip install -r requirements.txt' "
            "with the Python that runs AssetSuite (e.g. in its .venv)"
        ) from e
    try:
        return SafeET.fromstring(data)
    except ET.ParseError as e:
        raise PfSenseError(f"{path} is not a valid XML file: {e}") from e


def _sections(root: ET.Element, path: str) -> Tuple[Optional[ET.Element], Optional[ET.Element]]:
    """(unbound, dhcpd) sections of a complete or partial backup."""
    if root.tag == "pfsense":
        return root.find("unbound"), root.find("dhcpd")
    if root.tag == "unbound":
        return root, None
    if root.tag == "dhcpd":
        return None, root
    raise PfSenseError(f"{path} is not a pfSense backup of the DNS Resolver or DHCP Server (root <{root.tag}>)")


def category(description: str) -> str:
    match = _CATEGORY.match(description or "")
    if not match:
        return ""
    value = match.group(1).strip()
    return value if any(c.isalpha() for c in value) else ""


@dataclass
class _Entry:
    dns_names: List[str] = field(default_factory=list)
    dns_description: str = ""
    host: str = ""
    dhcp_domain: str = ""
    mac: str = ""
    dhcp_description: str = ""
    interface: str = ""
    sources: List[str] = field(default_factory=list)


def read_backups(paths: Sequence[str]) -> Dict[str, _Entry]:
    entries: Dict[str, _Entry] = {}
    for path in paths:
        unbound, dhcpd = _sections(_parse(path), path)
        for host in unbound.findall("hosts") if unbound is not None else []:
            name = ".".join(part for part in (_text(host, "host"), _text(host, "domain")) if part)
            for ip in (part.strip() for part in _text(host, "ip").split(",")):
                if not ip:
                    continue
                entry = entries.setdefault(ip, _Entry())
                if name and name not in entry.dns_names:
                    entry.dns_names.append(name)
                entry.dns_description = entry.dns_description or _text(host, "descr")
                if "dns" not in entry.sources:
                    entry.sources.append("dns")
        for interface in list(dhcpd) if dhcpd is not None else []:
            for mapping in interface.findall("staticmap"):
                ip = _text(mapping, "ipaddr")
                if not ip:  # MAC-only reservation: nothing to match in QRadar
                    continue
                entry = entries.setdefault(ip, _Entry())
                entry.host = entry.host or _text(mapping, "hostname")
                entry.dhcp_domain = entry.dhcp_domain or _text(mapping, "domain")
                entry.mac = entry.mac or normalize_mac(_text(mapping, "mac"))
                entry.dhcp_description = entry.dhcp_description or _text(mapping, "descr")
                entry.interface = entry.interface or interface.tag
                if "dhcp" not in entry.sources:
                    entry.sources.append("dhcp")
    return entries


def build_records(entries: Mapping[str, _Entry], config: PfSenseConfig) -> List[Dict[str, str]]:
    records = []
    for ip, entry in entries.items():
        address = parse_ip(ip)
        if address is None:
            continue
        if config.networks and not any(address.version == n.version and address in n for n in config.networks):
            continue
        if entry.dns_names:
            dns_name = entry.dns_names[0]
        elif entry.host:
            domain = entry.dhcp_domain or config.dns_domain
            dns_name = f"{entry.host}.{domain}" if domain else entry.host
        else:
            dns_name = ""
        description = entry.dns_description or entry.dhcp_description
        records.append(
            {
                "ip": ip,
                "dns_name": dns_name,
                "host": dns_name.split(".")[0] if dns_name else "",
                "mac": entry.mac,
                "dns_description": entry.dns_description,
                "dhcp_description": entry.dhcp_description,
                "description": description,
                "category": category(entry.dns_description) or category(entry.dhcp_description),
                "interface": entry.interface,
                "source": "+".join(entry.sources),
            }
        )
    return sorted(records, key=lambda r: _ip_key(r["ip"]))


def _ip_key(value: str) -> Tuple[int, int]:
    address = parse_ip(value)
    return (address.version, int(address)) if address else (9, 0)


def import_rows(
    records: Sequence[Mapping[str, str]], config: PfSenseConfig, domain: str
) -> Tuple[List[str], List[ImportRow]]:
    """Header and rows in the import format: one row per pfSense IP address."""
    properties = list(config.mapping)
    header = ["ip_address", "mac_address", "dns_names", "domain_name", *properties]
    rows = []
    for line, record in enumerate(records, start=2):
        values = {
            "ip_address": record["ip"],
            "mac_address": record["mac"],
            "dns_names": record["dns_name"],
            "domain_name": domain,
        }
        values.update({prop: apply_rule(record, rule) for prop, rule in config.mapping.items()})
        rows.append(ImportRow(line, values))
    return header, rows
