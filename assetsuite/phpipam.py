"""
phpipam.py

phpIPAM integration: reads the IP addresses of phpIPAM, with their status,
section, subnet, device and location, and turns them into rows of the
AssetSuite import format. The import itself (dry run, backup, creation of
missing assets, restore) is the one of the import command.

Observed on phpIPAM 1.8.3: an API "App" with a static app code token sent in
the "token" header ("SSL with App code token"), answers as
{"code", "success", "data"} without pagination, every address in one answer
(addresses/all), and an empty list answered as HTTP 404 with success false
and a message such as "No devices configured".

Copyright 2026 Pascal Weber (zoldax) / Abakus Sécurité
Licensed under the Apache License, Version 2.0 (see LICENSE).
"""

from __future__ import annotations

import ipaddress
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

import requests
import urllib3

from assetsuite.config import PLACEHOLDER_TOKEN
from assetsuite.importer import ImportRow, normalize_mac
from assetsuite.mapping import MappingError, apply_rule, normalize_mapping
from assetsuite.progress import Progress, or_none

logger = logging.getLogger(__name__)

# Fields of a phpIPAM record that the mapping can use.
RECORD_FIELDS = (
    "ip",
    "hostname",
    "description",
    "note",
    "mac",
    "owner",
    "status",
    "section",
    "subnet",
    "subnet_description",
    "location",
    "port",
    "device_name",
    "device_description",
    "device_type",
)
CUSTOM_FIELD_PREFIX = "custom_"
# The description phpIPAM gives the addresses its scans discover: no description.
AUTODISCOVERED = "-- autodiscovered --"

# QRadar property -> phpIPAM fields. "first": first non-empty field; "join": all non-empty fields.
DEFAULT_MAPPING: Dict[str, Dict[str, Any]] = {
    "Given Name": {"first": ["hostname", "device_name"]},
    "Description": {"first": ["description", "device_description"]},
    "Location": {"first": ["location"]},
    "Asset Type": {"first": ["device_type"]},
    "Business Owner": {"first": ["owner"]},
}


class PhpIpamError(Exception):
    """phpIPAM is not configured, not reachable, or answered with an error."""


@dataclass(frozen=True)
class PhpIpamConfig:
    url: str
    app_id: str
    token: str
    verify_ssl: bool = True
    ssl_cert_path: Optional[str] = None
    timeout: float = 30.0
    domain: str = "DEFAULT_DOMAIN"
    statuses: Tuple[str, ...] = ("Used",)
    sections: Tuple[str, ...] = ()
    mapping: Mapping[str, Mapping[str, Any]] = field(default_factory=lambda: dict(DEFAULT_MAPPING))

    @property
    def verify(self) -> Union[bool, str]:
        if not self.verify_ssl:
            return False
        return self.ssl_cert_path or True

    def __repr__(self) -> str:
        return f"PhpIpamConfig(url={self.url!r}, app_id={self.app_id!r}, verify={self.verify!r})"


def _names(value: Any, key: str) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)) or not all(isinstance(v, str) and v.strip() for v in value):
        raise PhpIpamError(f"'phpipam.{key}' must be a list of names")
    return tuple(v.strip() for v in value)


def load_phpipam_config(
    sections: Optional[Mapping[str, Any]], environ: Optional[Mapping[str, str]] = None
) -> PhpIpamConfig:
    """phpIPAM settings from the "phpipam" section of config.json, PHPIPAM_URL / PHPIPAM_TOKEN winning."""
    environ = os.environ if environ is None else environ
    raw = dict((sections or {}).get("phpipam") or {})
    for env_name, key in (
        ("PHPIPAM_URL", "url"),
        ("PHPIPAM_APP_ID", "app_id"),
        ("PHPIPAM_TOKEN", "token"),
        ("PHPIPAM_SSL_CERT_PATH", "ssl_cert_path"),
    ):
        if environ.get(env_name):
            raw[key] = environ[env_name]

    known = {
        "url",
        "app_id",
        "token",
        "verify_ssl",
        "ssl_cert_path",
        "timeout",
        "domain",
        "statuses",
        "sections",
        "mapping",
    }
    unknown = sorted(set(raw) - known)
    if unknown:
        raise PhpIpamError(f"Unknown phpipam setting(s): {', '.join(unknown)}")
    url = str(raw.get("url") or "").rstrip("/")
    if url.endswith("/api"):
        url = url[: -len("/api")]
    app_id = str(raw.get("app_id") or "").strip().strip("/")
    if not url or not app_id:
        raise PhpIpamError(
            "phpIPAM is not configured: add a 'phpipam' section with 'url', 'app_id' and 'token' to the config file"
        )
    token = str(raw.get("token") or "")
    if not token or token == PLACEHOLDER_TOKEN:
        raise PhpIpamError(
            "'phpipam.token' is not set: put the app code token of a read-only phpIPAM API app in the config file "
            "or PHPIPAM_TOKEN"
        )

    verify_ssl = raw.get("verify_ssl", True)
    if isinstance(verify_ssl, str):
        verify_ssl = verify_ssl.strip().lower() in ("true", "on", "yes", "1")
    ssl_cert_path = raw.get("ssl_cert_path") or None
    if verify_ssl and ssl_cert_path and not os.path.isfile(str(ssl_cert_path)):
        raise PhpIpamError(f"phpipam.ssl_cert_path {ssl_cert_path} does not exist")

    try:
        mapping = normalize_mapping(
            "phpipam", raw.get("mapping", DEFAULT_MAPPING), RECORD_FIELDS, lambda f: f.startswith(CUSTOM_FIELD_PREFIX)
        )
    except MappingError as e:
        raise PhpIpamError(f"{e} (or custom_<custom field>)") from e

    try:
        timeout = float(raw.get("timeout", 30))
    except (TypeError, ValueError) as e:
        raise PhpIpamError("'phpipam.timeout' must be a number") from e

    return PhpIpamConfig(
        url=url,
        app_id=app_id,
        token=token,
        verify_ssl=bool(verify_ssl),
        ssl_cert_path=str(ssl_cert_path) if ssl_cert_path else None,
        timeout=timeout,
        domain=str(raw.get("domain") or "DEFAULT_DOMAIN"),
        statuses=_names(raw.get("statuses", ["Used"]), "statuses"),
        sections=_names(raw.get("sections"), "sections"),
        mapping=mapping,
    )


class PhpIpamClient:
    def __init__(self, config: PhpIpamConfig, session: Optional[requests.Session] = None):
        self.config = config
        self.session = session or requests.Session()
        self.session.headers.update({"token": config.token, "Accept": "application/json"})
        self.session.verify = config.verify
        if not config.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning("TLS verification is disabled for phpIPAM %s", config.url)

    def get_list(self, path: str) -> List[dict]:
        """The objects of a phpIPAM list; an empty list when phpIPAM answers that there are none."""
        data = self.get(path, empty=[])
        if isinstance(data, Mapping):  # some lists come keyed by id
            data = list(data.values())
        if not isinstance(data, list):
            raise PhpIpamError(f"Unexpected answer from phpIPAM for {path}")
        return [item for item in data if isinstance(item, Mapping)]

    def get(self, path: str, empty: Any = None) -> Any:
        url = f"{self.config.url}/api/{self.config.app_id}/{path.strip('/')}/"
        try:
            # verify on each request: REQUESTS_CA_BUNDLE would override the session value, even False.
            response = self.session.get(url, timeout=self.config.timeout, verify=self.session.verify)
        except requests.exceptions.SSLError as e:
            raise PhpIpamError(
                f"TLS verification failed for phpIPAM: {e} (see phpipam.verify_ssl / ssl_cert_path)"
            ) from e
        except requests.RequestException as e:
            raise PhpIpamError(f"Cannot reach phpIPAM {self.config.url}: {e}") from e
        try:
            body = response.json()
        except ValueError:
            body = None
        message = str(body.get("message") or "") if isinstance(body, Mapping) else ""
        if response.status_code in (401, 403):
            raise PhpIpamError(
                f"phpIPAM refused the token (HTTP {response.status_code}{': ' + message if message else ''}): "
                "check phpipam.app_id and phpipam.token"
            )
        # "No devices configured", "No objects found", "No custom fields defined": nothing, not an error.
        if response.status_code == 404 and message.startswith("No "):
            return empty
        if response.status_code >= 400:
            raise PhpIpamError(
                f"HTTP {response.status_code} from phpIPAM on {path}: {message or response.reason or 'error'}"
            )
        if not isinstance(body, Mapping) or "data" not in body:
            raise PhpIpamError(f"Invalid answer from phpIPAM on {path}")
        return body["data"] if body["data"] is not None else empty


# --- Records -----------------------------------------------------------------


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _description(value: Any) -> str:
    text = _text(value)
    return "" if text.casefold() == AUTODISCOVERED else text


def _id(value: Any) -> Optional[str]:
    """An id of phpIPAM ("12", 12), None for none ("0", 0, "", null)."""
    text = _text(value)
    return None if text in ("", "0") else text


def _by_id(items: Sequence[Mapping], *keys: str) -> Dict[str, Mapping]:
    found: Dict[str, Mapping] = {}
    for item in items:
        for key in keys:
            if _id(item.get(key)) is not None:
                found[_text(item[key])] = item
                break
    return found


def _name(item: Optional[Mapping], *keys: str) -> str:
    for key in keys:
        if item and _text(item.get(key)):
            return _text(item.get(key))
    return ""


@dataclass
class PhpIpamData:
    """What phpIPAM answered, before any record is built."""

    addresses: List[dict]
    statuses: List[dict] = field(default_factory=list)  # addresses/tags
    sections: List[dict] = field(default_factory=list)
    subnets: List[dict] = field(default_factory=list)
    devices: List[dict] = field(default_factory=list)
    device_types: List[dict] = field(default_factory=list)
    locations: List[dict] = field(default_factory=list)


def build_records(data: PhpIpamData, config: PhpIpamConfig) -> Tuple[List[Dict[str, str]], int]:
    """
    One flat record per phpIPAM address kept (status and section of the
    config), enriched with its subnet, section, device and location; and the
    number of addresses read.
    """
    statuses = {_text(s.get("id")): _text(s.get("type")) for s in data.statuses}
    sections = _by_id(data.sections, "id")
    subnets = _by_id(data.subnets, "id")
    devices = _by_id(data.devices, "id")
    device_types = _by_id(data.device_types, "tid", "id")
    locations = _by_id(data.locations, "id")
    wanted_statuses = {s.casefold() for s in config.statuses}
    wanted_sections = {s.casefold() for s in config.sections}

    records = []
    for address in data.addresses:
        status = statuses.get(_text(address.get("tag")), "")
        if wanted_statuses and status.casefold() not in wanted_statuses:
            continue
        subnet = subnets.get(_id(address.get("subnetId")) or "")
        section = sections.get(_id((subnet or {}).get("sectionId")) or "")
        section_name = _name(section, "name")
        if wanted_sections and section_name.casefold() not in wanted_sections:
            continue
        device = devices.get(_id(address.get("deviceId")) or "")
        device_type = device_types.get(_id((device or {}).get("type")) or "")
        location = locations.get(_id(address.get("location")) or _id((device or {}).get("location")) or "")
        record = {
            "ip": _text(address.get("ip")),
            "hostname": _text(address.get("hostname")),
            "description": _description(address.get("description")),
            "note": _text(address.get("note")),
            "mac": normalize_mac(_text(address.get("mac"))) if _text(address.get("mac")) else "",
            "owner": _text(address.get("owner")),
            "status": status,
            "section": section_name,
            "subnet": f"{_text(subnet.get('subnet'))}/{_text(subnet.get('mask'))}" if subnet else "",
            "subnet_description": _name(subnet, "description"),
            "location": _name(location, "name"),
            "port": _text(address.get("port")),
            "device_name": _name(device, "hostname"),
            "device_description": _name(device, "description", "descriptuion"),  # sic in the API documentation
            "device_type": _name(device_type, "tname", "name"),
        }
        custom = {key: _text(value) for key, value in address.items() if key.startswith(CUSTOM_FIELD_PREFIX)}
        record.update({key: value for key, value in custom.items() if value})
        records.append(record)
    return records, len(data.addresses)


def import_rows(
    records: Sequence[Mapping[str, str]], config: PhpIpamConfig, domain: str
) -> Tuple[List[str], List[ImportRow]]:
    """Header and rows in the import format: one row per phpIPAM address."""
    properties = list(config.mapping)
    header = ["ip_address", "mac_address", "dns_names", "domain_name", *properties]
    rows = []
    for line, record in enumerate(sorted(records, key=lambda r: _ip_sort_key(r["ip"])), start=2):
        values = {
            "ip_address": record["ip"],
            "mac_address": record["mac"],
            "dns_names": record["hostname"],
            "domain_name": domain,
        }
        values.update({prop: apply_rule(record, rule) for prop, rule in config.mapping.items()})
        rows.append(ImportRow(line, values))
    return header, rows


def _ip_sort_key(value: str) -> Tuple[int, int]:
    try:
        ip = ipaddress.ip_address(value)
        return ip.version, int(ip)
    except ValueError:
        return 9, 0


def fetch_data(client: PhpIpamClient, progress: Optional[Progress] = None) -> PhpIpamData:
    """Every list a record needs: addresses, statuses, sections and their subnets, devices, locations."""
    progress = or_none(progress)
    progress.phase("phpIPAM addresses")
    addresses = client.get_list("addresses/all")
    progress.set_total(len(addresses))
    progress.advance(len(addresses))
    statuses = client.get_list("addresses/tags")
    progress.phase("phpIPAM sections and subnets")
    sections = client.get_list("sections")
    progress.set_total(len(sections))
    subnets: List[dict] = []
    for section in sections:
        progress.check_cancelled()
        if _id(section.get("id")) is not None:
            subnets += client.get_list(f"sections/{_text(section['id'])}/subnets")
        progress.advance()
    progress.phase("phpIPAM devices and locations")
    devices = client.get_list("devices") if any(_id(a.get("deviceId")) for a in addresses) else []
    device_types = client.get_list("tools/device_types") if devices else []
    used_locations = any(_id(a.get("location")) for a in addresses) or any(_id(d.get("location")) for d in devices)
    locations = client.get_list("tools/locations") if used_locations else []
    return PhpIpamData(addresses, statuses, sections, subnets, devices, device_types, locations)


def fetch_records(client: PhpIpamClient, progress: Optional[Progress] = None) -> Tuple[List[Dict[str, str]], int]:
    """The records of the addresses kept, and the number of addresses read."""
    return build_records(fetch_data(client, progress), client.config)
