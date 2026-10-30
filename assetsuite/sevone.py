"""
sevone.py

IBM SevOne NPM integration: reads the devices SevOne monitors, with their
device types and metadata, and turns them into rows of the AssetSuite import
format. The import itself (dry run, backup, creation of missing assets,
restore) is the one of the import command. SevOne only fills empty QRadar
properties unless overwrite is set, so it completes NetBox without
contradicting it.

Observed on SevOne NPM 7.2.1: API keys (created with POST /api/v3/users/apikey)
sent in the X-AUTH-TOKEN header; devices, device groups and metadata in the v2
API, paginated with page / size and totalPages; device types of a device only
in the v3 API; "Unknown" used as an empty metadata value; synthetic devices
(HTTP or DNS probes, SevOne itself) polled on 127.0.0.1.

Copyright 2026 Pascal Weber (zoldax) / Abakus Sécurité
Licensed under the Apache License, Version 2.0 (see LICENSE).
"""

from __future__ import annotations

import ipaddress
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple, Union

import requests
import urllib3

from assetsuite.config import PLACEHOLDER_TOKEN
from assetsuite.importer import ImportRow
from assetsuite.mapping import MappingError, apply_rule, normalize_mapping

logger = logging.getLogger(__name__)

PAGE_SIZE = 200
MAX_PAGES = 1000  # safety net against a server that never reports the last page

# Fields of a SevOne record that the mapping can use.
RECORD_FIELDS = (
    "ip",
    "name",
    "alternate_name",
    "description",
    "device_description",
    "sys_name",
    "dns_name",
    "device_type",
    "device_types",
    "device_class",
    "vendor",
    "model",
    "os",
    "os_family",
    "os_version",
    "site",
    "sys_location",
    "sys_contact",
    "tenant",
    "status",
)
# Any metadata attribute by its full name, e.g. "md:Device.Serial Number".
METADATA_PREFIX = "md:"

# QRadar property -> SevOne fields. "first": first non-empty field; "join": all non-empty fields.
DEFAULT_MAPPING: Dict[str, Dict[str, Any]] = {
    "Given Name": {"first": ["name"]},
    "Description": {"first": ["description", "device_description"]},
    "Location": {"first": ["site", "sys_location"]},
    "Asset Type": {"first": ["device_type", "device_class"]},
    "Technical Contact": {"first": ["sys_contact"]},
    "User Supplied OS": {"first": ["os"]},
}

# Metadata attribute -> record field.
METADATA_FIELDS = {
    "Device.Description": "device_description",
    "{system}.sysName": "sys_name",
    "Device.Class": "device_class",
    "Device.Vendor": "vendor",
    "Device.Model": "model",
    "Device.OS Family": "os_family",
    "Device.OS Version": "os_version",
    "Location.Site Name": "site",
    "{system}.sysLocation": "sys_location",
    "{system}.sysContact": "sys_contact",
    "Device.Tenant": "tenant",
    "Device.Operational Status": "status",
}
EMPTY_VALUES = {"", "unknown"}
ROOT_TYPE = "All Device Types"
GENERIC_TYPE = "Generic"  # every device is in it: says nothing about the device


class SevOneError(Exception):
    """SevOne is not configured, not reachable, or answered with an error."""


@dataclass(frozen=True)
class SevOneConfig:
    url: str
    token: str
    verify_ssl: bool = True
    ssl_cert_path: Optional[str] = None
    timeout: float = 30.0
    domain: str = "DEFAULT_DOMAIN"
    device_groups: Tuple[str, ...] = ()
    overwrite: bool = False
    mapping: Mapping[str, Mapping[str, Any]] = field(default_factory=lambda: dict(DEFAULT_MAPPING))

    @property
    def verify(self) -> Union[bool, str]:
        if not self.verify_ssl:
            return False
        return self.ssl_cert_path or True

    def __repr__(self) -> str:
        return f"SevOneConfig(url={self.url!r}, verify={self.verify!r})"


def load_sevone_config(
    sections: Optional[Mapping[str, Any]], environ: Optional[Mapping[str, str]] = None
) -> SevOneConfig:
    """SevOne settings from the "sevone" section of config.json, SEVONE_URL / SEVONE_TOKEN winning."""
    environ = os.environ if environ is None else environ
    raw = dict((sections or {}).get("sevone") or {})
    for env_name, key in (("SEVONE_URL", "url"), ("SEVONE_TOKEN", "token"), ("SEVONE_SSL_CERT_PATH", "ssl_cert_path")):
        if environ.get(env_name):
            raw[key] = environ[env_name]

    known = {
        "url",
        "token",
        "verify_ssl",
        "ssl_cert_path",
        "timeout",
        "domain",
        "device_groups",
        "overwrite",
        "mapping",
    }
    unknown = sorted(set(raw) - known)
    if unknown:
        raise SevOneError(f"Unknown sevone setting(s): {', '.join(unknown)}")
    url = str(raw.get("url") or "").rstrip("/")
    if not url:
        raise SevOneError("SevOne is not configured: add a 'sevone' section with 'url' and 'token' to the config file")
    token = str(raw.get("token") or "")
    if not token or token == PLACEHOLDER_TOKEN:
        raise SevOneError(
            "'sevone.token' is not set: put a SevOne API key (POST /api/v3/users/apikey) "
            "in the config file or SEVONE_TOKEN"
        )

    verify_ssl = raw.get("verify_ssl", True)
    if isinstance(verify_ssl, str):
        verify_ssl = verify_ssl.strip().lower() in ("true", "on", "yes", "1")
    ssl_cert_path = raw.get("ssl_cert_path") or None
    if verify_ssl and ssl_cert_path and not os.path.isfile(str(ssl_cert_path)):
        raise SevOneError(f"sevone.ssl_cert_path {ssl_cert_path} does not exist")

    groups = raw.get("device_groups", [])
    if isinstance(groups, (str, int)):
        groups = [groups]
    if not isinstance(groups, list):
        raise SevOneError("'sevone.device_groups' must be a list of device group names, paths or ids")
    overwrite = raw.get("overwrite", False)
    if not isinstance(overwrite, bool):
        raise SevOneError("'sevone.overwrite' must be true or false")
    try:
        mapping = normalize_mapping(
            "sevone", raw.get("mapping", DEFAULT_MAPPING), RECORD_FIELDS, lambda f: f.startswith(METADATA_PREFIX)
        )
    except MappingError as e:
        raise SevOneError(f"{e} (or md:<Namespace.Attribute>)") from e

    try:
        timeout = float(raw.get("timeout", 30))
    except (TypeError, ValueError) as e:
        raise SevOneError("'sevone.timeout' must be a number") from e

    return SevOneConfig(
        url=url,
        token=token,
        verify_ssl=bool(verify_ssl),
        ssl_cert_path=str(ssl_cert_path) if ssl_cert_path else None,
        timeout=timeout,
        domain=str(raw.get("domain") or "DEFAULT_DOMAIN"),
        device_groups=tuple(str(g).strip("/") for g in groups),
        overwrite=overwrite,
        mapping=mapping,
    )


class SevOneClient:
    def __init__(self, config: SevOneConfig, session: Optional[requests.Session] = None):
        self.config = config
        self.session = session or requests.Session()
        self.session.headers.update({"X-AUTH-TOKEN": config.token, "Accept": "application/json"})
        self.session.verify = config.verify
        if not config.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning("TLS verification is disabled for SevOne %s", config.url)

    def get(self, path: str, params: Optional[Mapping[str, Any]] = None) -> Any:
        url = f"{self.config.url}/{path.lstrip('/')}"
        try:
            response = self.session.get(url, params=params, timeout=self.config.timeout)
        except requests.exceptions.SSLError as e:
            raise SevOneError(f"TLS verification failed for SevOne: {e} (see sevone.verify_ssl / ssl_cert_path)") from e
        except requests.RequestException as e:
            raise SevOneError(f"Cannot reach SevOne {self.config.url}: {e}") from e
        if response.status_code in (401, 403):
            raise SevOneError(
                f"SevOne refused the API key (HTTP {response.status_code}): check sevone.token "
                "(a key replaced by a new one for the same application is no longer valid)"
            )
        if response.status_code >= 400:
            try:
                body = response.json()
                detail = body.get("title") or body.get("error") or response.reason
            except (ValueError, AttributeError):
                detail = response.reason
            raise SevOneError(f"HTTP {response.status_code} from SevOne on {url}: {detail}")
        try:
            return response.json()
        except ValueError as e:
            raise SevOneError(f"Invalid JSON from SevOne on {url}") from e

    def get_pages(self, path: str, params: Optional[Mapping[str, Any]] = None) -> List[dict]:
        """All the items of a paginated v2 listing (content / totalPages)."""
        items: List[dict] = []
        for page in range(MAX_PAGES):
            data = self.get(path, {**(params or {}), "page": page, "size": PAGE_SIZE})
            if not isinstance(data, dict) or not isinstance(data.get("content"), list):
                raise SevOneError(f"Unexpected answer from SevOne for {path}")
            items.extend(data["content"])
            if not data["content"] or page + 1 >= int(data.get("totalPages") or 0):
                return items
        raise SevOneError(f"SevOne listing {path} did not end after {MAX_PAGES} pages")


# --- Records -----------------------------------------------------------------


def _clean(value: object) -> str:
    text = "" if value is None else str(value).strip()
    return "" if text.lower() in EMPTY_VALUES else text


def flatten_metadata(metadata: Mapping[str, Any]) -> Dict[str, str]:
    """{"Namespace.Attribute": "value"} from a v2 metadata answer; several values joined by '; '."""
    flat = {}
    for attribute, entry in (metadata or {}).items():
        values = entry.get("values") if isinstance(entry, Mapping) else None
        texts = []
        for value in values or []:
            text = _clean(value.get("value", value.get("label")) if isinstance(value, Mapping) else value)
            if text and text not in texts:
                texts.append(text)
        if texts:
            flat[str(attribute)] = "; ".join(texts)
    return flat


def device_types(definitions: Sequence[Mapping[str, Any]]) -> List[str]:
    """Paths of the most precise device types of a device, without the root and Generic branches."""
    by_id = {str(d.get("id")): d for d in definitions}
    parents = {str(d.get("parentId")) for d in definitions}
    paths = []
    for definition in definitions:
        if str(definition.get("id")) in parents:
            continue  # not a leaf
        names, node, seen = [], definition, set()
        while node and str(node.get("id")) not in seen:
            seen.add(str(node.get("id")))
            names.append(str(node.get("name") or ""))
            node = by_id.get(str(node.get("parentId")))
        names = [n for n in reversed(names) if n and n != ROOT_TYPE]
        if names and names[0] != GENERIC_TYPE:
            paths.append("/".join(names))
    return sorted(paths)


def _dns_name(sys_name: str) -> str:
    """The SNMP sysName as DNS name, only when it is a fully qualified name."""
    if "." not in sys_name or " " in sys_name:
        return ""
    try:
        ipaddress.ip_address(sys_name)
        return ""
    except ValueError:
        return sys_name.rstrip(".")


def build_record(device: Mapping[str, Any], metadata: Mapping[str, str], types: Sequence[str]) -> Dict[str, str]:
    record = {name: "" for name in RECORD_FIELDS}
    record.update({target: metadata.get(source, "") for source, target in METADATA_FIELDS.items()})
    record.update(
        {
            "ip": _clean(device.get("ipAddress")),
            "name": _clean(device.get("name")),
            "alternate_name": _clean(device.get("alternateName")),
            "description": _clean(device.get("description")),
            "dns_name": _dns_name(record["sys_name"]),
            "device_type": types[0].split("/")[0] if types else "",
            "device_types": ", ".join(types),
            "os": " ".join(v for v in (record["os_family"], record["os_version"]) if v),
        }
    )
    record.update({f"{METADATA_PREFIX}{name}": value for name, value in metadata.items()})
    return record


def skip_reason(device: Mapping[str, Any]) -> str:
    """Why a SevOne device does not become an asset, or ''."""
    if device.get("isDeleted") or device.get("isQueuedForDeletion"):
        return "deleted in SevOne"
    try:
        ip = ipaddress.ip_address(_clean(device.get("ipAddress")))
    except ValueError:
        return "no valid IP address"
    if ip.is_loopback or ip.is_unspecified:
        return f"polled on {ip} (probe or SevOne itself)"
    return ""


def _group_ids(groups: Sequence[Mapping[str, Any]], wanted: Sequence[str]) -> Tuple[Set[int], List[str]]:
    """Member device ids of the configured groups (by id, name or path), and the names not found."""
    by_id = {str(g.get("id")): g for g in groups}

    def path(group: Optional[Mapping[str, Any]]) -> str:
        names, seen = [], set()
        while group and str(group.get("id")) not in seen:
            seen.add(str(group.get("id")))
            names.append(str(group.get("name") or ""))
            group = by_id.get(str(group.get("parentId")))
        return "/".join(reversed(names))

    members: Set[int] = set()
    missing = []
    for want in wanted:
        matched = [g for g in groups if want in (str(g.get("id")), str(g.get("name")), path(g))]
        if not matched:
            missing.append(want)
        for group in matched:
            members |= {int(d["id"] if isinstance(d, Mapping) else d) for d in group.get("devices") or []}
    return members, missing


@dataclass
class SevOneDevices:
    records: List[Dict[str, str]]
    skipped: List[Tuple[str, str]]  # (device name, reason)
    total: int


def fetch_records(client: SevOneClient) -> SevOneDevices:
    devices = client.get_pages("api/v2/devices")
    total = len(devices)
    if client.config.device_groups:
        groups = client.get_pages("api/v2/devicegroups", {"includeMembers": "true"})
        members, missing = _group_ids(groups, client.config.device_groups)
        if missing:
            raise SevOneError(f"Unknown SevOne device group(s): {', '.join(missing)}")
        devices = [d for d in devices if d.get("id") in members]

    records, skipped = [], []
    for device in devices:
        reason = skip_reason(device)
        if reason:
            skipped.append((str(device.get("name") or device.get("id")), reason))
            continue
        metadata = flatten_metadata(client.get(f"api/v2/devices/{device['id']}/metadata"))
        types = client.get(f"api/v3/devicetypes/members/{device['id']}")
        definitions = types.get("deviceTypeDefinition") if isinstance(types, Mapping) else None
        records.append(build_record(device, metadata, device_types(definitions or [])))
    return SevOneDevices(records, skipped, total)


def import_rows(
    records: Sequence[Mapping[str, str]], config: SevOneConfig, domain: str
) -> Tuple[List[str], List[ImportRow]]:
    """Header and rows in the import format: one row per SevOne device."""
    properties = list(config.mapping)
    header = ["ip_address", "dns_names", "domain_name", *properties]
    rows = []
    for line, record in enumerate(sorted(records, key=lambda r: _ip_sort_key(r["ip"])), start=2):
        values = {"ip_address": record["ip"], "dns_names": record["dns_name"], "domain_name": domain}
        values.update({prop: apply_rule(record, rule) for prop, rule in config.mapping.items()})
        rows.append(ImportRow(line, values))
    return header, rows


def _ip_sort_key(value: str) -> Tuple[int, int]:
    try:
        ip = ipaddress.ip_address(value)
        return ip.version, int(ip)
    except ValueError:
        return 9, 0
