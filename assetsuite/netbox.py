"""
netbox.py

NetBox integration: reads the IPAM IP addresses of NetBox, with the device or
virtual machine they are assigned to, and turns them into rows of the
AssetSuite import format. The import itself (dry run, backup, creation of
missing assets, restore) is the one of the import command.

Observed on NetBox 4.4: token authentication with "Authorization: Token ...",
pagination through the "next" URL, IP addresses with an assigned_object
(dcim.interface or virtualization.vminterface) pointing to their device or
virtual machine, and "-" used as an empty dns_name.

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
from assetsuite.importer import NO_HOSTNAME, ImportRow
from assetsuite.mapping import MappingError, apply_rule, normalize_mapping

logger = logging.getLogger(__name__)

PAGE_SIZE = 500

# Fields of a NetBox record that the mapping can use.
RECORD_FIELDS = (
    "ip",
    "dns_name",
    "ip_description",
    "object_type",
    "object_name",
    "object_description",
    "description",
    "role",
    "site",
    "location",
    "rack",
    "cluster",
    "tenant",
    "platform",
    "serial",
    "asset_tag",
    "status",
    "tags",
)
CUSTOM_FIELD_PREFIX = "cf_"

# QRadar property -> NetBox fields. "first": first non-empty field; "join": all non-empty fields.
DEFAULT_MAPPING: Dict[str, Dict[str, Any]] = {
    "Given Name": {"first": ["object_name", "dns_name"]},
    "Description": {"first": ["ip_description", "object_description"]},
    "Location": {"join": ["site", "location", "rack"], "separator": " / "},
    "Asset Type": {"first": ["role"]},
    "Business Owner": {"first": ["tenant"]},
    "User Supplied OS": {"first": ["platform"]},
}
VIRTUAL_MACHINE_ROLE = "Virtual machine"


class NetBoxError(Exception):
    """NetBox is not configured, not reachable, or answered with an error."""


@dataclass(frozen=True)
class NetBoxConfig:
    url: str
    token: str
    verify_ssl: bool = True
    ssl_cert_path: Optional[str] = None
    timeout: float = 30.0
    domain: str = "DEFAULT_DOMAIN"
    statuses: Tuple[str, ...] = ("active",)
    mapping: Mapping[str, Mapping[str, Any]] = field(default_factory=lambda: dict(DEFAULT_MAPPING))

    @property
    def verify(self) -> Union[bool, str]:
        if not self.verify_ssl:
            return False
        return self.ssl_cert_path or True

    def __repr__(self) -> str:
        return f"NetBoxConfig(url={self.url!r}, verify={self.verify!r})"


def load_netbox_config(
    sections: Optional[Mapping[str, Any]], environ: Optional[Mapping[str, str]] = None
) -> NetBoxConfig:
    """NetBox settings from the "netbox" section of config.json, NETBOX_URL / NETBOX_TOKEN winning."""
    environ = os.environ if environ is None else environ
    raw = dict((sections or {}).get("netbox") or {})
    for env_name, key in (("NETBOX_URL", "url"), ("NETBOX_TOKEN", "token"), ("NETBOX_SSL_CERT_PATH", "ssl_cert_path")):
        if environ.get(env_name):
            raw[key] = environ[env_name]

    known = {"url", "token", "verify_ssl", "ssl_cert_path", "timeout", "domain", "statuses", "mapping"}
    unknown = sorted(set(raw) - known)
    if unknown:
        raise NetBoxError(f"Unknown netbox setting(s): {', '.join(unknown)}")
    url = str(raw.get("url") or "").rstrip("/")
    if not url:
        raise NetBoxError("NetBox is not configured: add a 'netbox' section with 'url' and 'token' to the config file")
    token = str(raw.get("token") or "")
    if not token or token == PLACEHOLDER_TOKEN:
        raise NetBoxError(
            "'netbox.token' is not set: put a read-only NetBox API token in the config file or NETBOX_TOKEN"
        )

    verify_ssl = raw.get("verify_ssl", True)
    if isinstance(verify_ssl, str):
        verify_ssl = verify_ssl.strip().lower() in ("true", "on", "yes", "1")
    ssl_cert_path = raw.get("ssl_cert_path") or None
    if verify_ssl and ssl_cert_path and not os.path.isfile(str(ssl_cert_path)):
        raise NetBoxError(f"netbox.ssl_cert_path {ssl_cert_path} does not exist")

    statuses = raw.get("statuses", ["active"])
    if isinstance(statuses, str):
        statuses = [statuses]
    try:
        mapping = normalize_mapping(
            "netbox", raw.get("mapping", DEFAULT_MAPPING), RECORD_FIELDS, lambda f: f.startswith(CUSTOM_FIELD_PREFIX)
        )
    except MappingError as e:
        raise NetBoxError(f"{e} (or cf_<custom field>)") from e

    try:
        timeout = float(raw.get("timeout", 30))
    except (TypeError, ValueError) as e:
        raise NetBoxError("'netbox.timeout' must be a number") from e

    return NetBoxConfig(
        url=url,
        token=token,
        verify_ssl=bool(verify_ssl),
        ssl_cert_path=str(ssl_cert_path) if ssl_cert_path else None,
        timeout=timeout,
        domain=str(raw.get("domain") or "DEFAULT_DOMAIN"),
        statuses=tuple(str(s) for s in statuses),
        mapping=mapping,
    )


class NetBoxClient:
    def __init__(self, config: NetBoxConfig, session: Optional[requests.Session] = None):
        self.config = config
        self.session = session or requests.Session()
        # NetBox 4.5+ v2 tokens ("nbt_...") use Bearer, v1 tokens use Token.
        scheme = "Bearer" if config.token.startswith("nbt_") else "Token"
        self.session.headers.update({"Authorization": f"{scheme} {config.token}", "Accept": "application/json"})
        self.session.verify = config.verify
        if not config.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning("TLS verification is disabled for NetBox %s", config.url)

    def get_all(self, path: str, params: Optional[Mapping[str, Any]] = None) -> List[dict]:
        url: Optional[str] = f"{self.config.url}/api/{path.strip('/')}/"
        query: Optional[Dict[str, Any]] = {"limit": PAGE_SIZE, **(params or {})}
        results: List[dict] = []
        while url:
            data = self._get(url, query)
            if not isinstance(data, dict) or not isinstance(data.get("results"), list):
                raise NetBoxError(f"Unexpected answer from NetBox for {path}")
            results.extend(data["results"])
            url, query = data.get("next"), None  # "next" already carries the query
        return results

    def _get(self, url: str, params: Optional[Mapping[str, Any]]) -> Any:
        try:
            response = self.session.get(url, params=params, timeout=self.config.timeout)
        except requests.exceptions.SSLError as e:
            raise NetBoxError(f"TLS verification failed for NetBox: {e} (see netbox.verify_ssl / ssl_cert_path)") from e
        except requests.RequestException as e:
            raise NetBoxError(f"Cannot reach NetBox {self.config.url}: {e}") from e
        if response.status_code in (401, 403):
            raise NetBoxError(f"NetBox refused the token (HTTP {response.status_code}): check netbox.token")
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail") or response.reason
            except ValueError:
                detail = response.reason
            raise NetBoxError(f"HTTP {response.status_code} from NetBox on {url}: {detail}")
        try:
            return response.json()
        except ValueError as e:
            raise NetBoxError(f"Invalid JSON from NetBox on {url}") from e


# --- Records -----------------------------------------------------------------


def _name(value: object) -> str:
    if isinstance(value, Mapping):
        return str(value.get("name") or value.get("display") or "")
    return "" if value is None else str(value)


def _custom_fields(prefix_values: Mapping[str, Any]) -> Dict[str, str]:
    return {
        f"{CUSTOM_FIELD_PREFIX}{name}": _name(value)
        if not isinstance(value, (list, tuple))
        else ", ".join(map(_name, value))
        for name, value in (prefix_values or {}).items()
        if value not in (None, "", [])
    }


def build_records(ips: Sequence[Mapping], devices: Sequence[Mapping], vms: Sequence[Mapping]) -> List[Dict[str, str]]:
    """One flat record per NetBox IP address, enriched with its device or virtual machine."""
    devices_by_id = {d["id"]: d for d in devices}
    vms_by_id = {v["id"]: v for v in vms}
    records = []
    for ip in ips:
        assigned = ip.get("assigned_object") or {}
        obj: Mapping = {}
        object_type = ""
        if assigned.get("device"):
            obj, object_type = devices_by_id.get(assigned["device"]["id"], assigned["device"]), "device"
        elif assigned.get("virtual_machine"):
            obj, object_type = (
                vms_by_id.get(assigned["virtual_machine"]["id"], assigned["virtual_machine"]),
                "virtual machine",
            )

        dns_name = str(ip.get("dns_name") or "").strip()
        role = _name(obj.get("role"))
        if object_type == "virtual machine" and not role:
            role = VIRTUAL_MACHINE_ROLE
        record = {
            "ip": str(ip.get("address", "")).split("/")[0],
            "dns_name": "" if dns_name == NO_HOSTNAME else dns_name,
            "ip_description": str(ip.get("description") or "").strip(),
            "object_type": object_type,
            "object_name": _name(obj.get("name")),
            "object_description": str(obj.get("description") or "").strip(),
            "role": role,
            "site": _name(obj.get("site")),
            "location": _name(obj.get("location")),
            "rack": _name(obj.get("rack")),
            "cluster": _name(obj.get("cluster")),
            "tenant": _name(ip.get("tenant")) or _name(obj.get("tenant")),
            "platform": _name(obj.get("platform")),
            "serial": str(obj.get("serial") or "").strip(),
            "asset_tag": str(obj.get("asset_tag") or "").strip(),
            "status": _name(
                (ip.get("status") or {}).get("value") if isinstance(ip.get("status"), Mapping) else ip.get("status")
            ),
            "tags": ", ".join(_name(t) for t in ip.get("tags") or []),
        }
        record["description"] = record["ip_description"] or record["object_description"]
        record.update(_custom_fields(obj.get("custom_fields") or {}))
        record.update(_custom_fields(ip.get("custom_fields") or {}))
        records.append(record)
    return records


def import_rows(
    records: Sequence[Mapping[str, str]], config: NetBoxConfig, domain: str
) -> Tuple[List[str], List[ImportRow]]:
    """Header and rows in the import format: one row per NetBox IP address."""
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


ID_CHUNK = 100  # ids per request when fetching devices and virtual machines


def _by_ids(client: NetBoxClient, path: str, ids: Sequence[int]) -> List[dict]:
    objects: List[dict] = []
    for start in range(0, len(ids), ID_CHUNK):
        objects += client.get_all(path, params={"id": list(ids[start : start + ID_CHUNK])})
    return objects


def fetch_records(client: NetBoxClient) -> List[Dict[str, str]]:
    params = {"status": list(client.config.statuses)} if client.config.statuses else None
    ips = client.get_all("ipam/ip-addresses", params=params)
    assigned = [ip.get("assigned_object") or {} for ip in ips]
    device_ids = sorted({(a.get("device") or {}).get("id") for a in assigned} - {None})
    vm_ids = sorted({(a.get("virtual_machine") or {}).get("id") for a in assigned} - {None})
    devices = _by_ids(client, "dcim/devices", device_ids)
    vms = _by_ids(client, "virtualization/virtual-machines", vm_ids)
    return build_records(ips, devices, vms)
