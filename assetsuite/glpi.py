"""
glpi.py

GLPI integration: reads the assets of the GLPI CMDB (computers, network
equipment, printers, phones, peripherals), with their IP and MAC addresses,
groups, users and operating system, and turns them into rows of the AssetSuite
import format: one row per asset, every address of the asset in it. The import
itself (dry run, backup, creation of missing assets, restore) is the one of the
import command.

Observed on GLPI 12.0.1 through the legacy REST API (apirest.php): a session
opened by initSession with "Authorization: user_token ...", the App-Token of
an API client whose IP range covers the caller, then "Session-Token" on each
request and killSession at the end; sessions are read-only. Lists are paged
with "range" (up to the Accept-Range of the type, 5000) and "Content-Range";
expand_dropdowns gives names (the entity as its complete name, "Root entity >
Customer A"), but also replaces items_id by the name of the asset in Group_Item
and Item_OperatingSystem: those are read as they are, with the lists of groups
and systems. Since GLPI 11 the groups of an asset are in Group_Item (type 1:
group, 2: technical group). IPAddress points at the asset (mainitemtype,
mainitems_id) and at its NetworkName, whose NetworkPort holds the MAC; the
ports of containers and virtual bridges (docker0, br-..., veth...) are left out,
their addresses would match other hosts. Errors come as ["ERROR_NAME",
"message"].

Copyright 2026 Pascal Weber (zoldax) / Abakus Sécurité
Licensed under the Apache License, Version 2.0 (see LICENSE).
"""

from __future__ import annotations

import fnmatch
import ipaddress
import logging
import os
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

import requests
import urllib3

from assetsuite.config import PLACEHOLDER_TOKEN
from assetsuite.importer import ImportRow, normalize_mac
from assetsuite.mapping import MappingError, apply_rule, normalize_mapping
from assetsuite.progress import Progress, or_none

logger = logging.getLogger(__name__)

ITEMTYPES = {
    "Computer": "Computer",
    "NetworkEquipment": "Network equipment",
    "Printer": "Printer",
    "Phone": "Phone",
    "Peripheral": "Peripheral",
}
PAGE_SIZE = 1000
GROUP, TECHNICAL_GROUP = 1, 2  # Group_Item types
# Network ports whose addresses are not those of the asset on the network: containers, virtual bridges.
IGNORED_PORTS = ("docker*", "br-*", "veth*", "virbr*", "cni*", "flannel*", "vmnet*")

# Fields of a GLPI record that the mapping can use.
RECORD_FIELDS = (
    "itemtype",
    "name",
    "comment",
    "serial",
    "inventory_number",
    "uuid",
    "entity",
    "location",
    "type",
    "manufacturer",
    "model",
    "status",
    "user",
    "technician",
    "group",
    "technical_group",
    "contact",
    "os",
    "os_name",
    "os_version",
)

# QRadar property -> GLPI fields. "first": first non-empty field; "join": all non-empty fields.
DEFAULT_MAPPING: Dict[str, Dict[str, Any]] = {
    "Given Name": {"first": ["name"]},
    "Description": {"first": ["comment"]},
    "Location": {"first": ["location"]},
    "Asset Type": {"first": ["type", "itemtype"]},
    "Business Owner": {"first": ["group", "user"]},
    "Technical Owner": {"first": ["technical_group", "technician"]},
    "Technical Contact": {"first": ["contact"]},
    "User Supplied OS": {"first": ["os"]},
}

# GLPI errors and what to tell the user.
ERRORS = {
    "ERROR_NOT_ALLOWED_IP": "this machine is not in the IP range of a GLPI API client "
    "(Setup > General > API > API clients)",
    "ERROR_WRONG_APP_TOKEN_PARAMETER": "the App-Token is not the one of the API client covering this machine "
    "(check glpi.app_token)",
    "ERROR_APP_TOKEN_PARAMETERS_MISSING": "the API client of this machine needs an App-Token (glpi.app_token)",
    "ERROR_GLPI_LOGIN_USER_TOKEN": "GLPI refused the user token (check glpi.user_token)",
    "ERROR_LOGIN_PARAMETERS_MISSING": "GLPI refused the user token (check glpi.user_token)",
    "ERROR_GLPI_LOGIN": "GLPI refused the user token (check glpi.user_token)",
    "ERROR_LOGIN_WITH_TOKEN_DISABLED": "login with an external token is off in GLPI "
    "(Setup > General > API > Enable login with external token)",
    "ERROR_API_DISABLED": "the legacy REST API of GLPI is off (Setup > General > API)",
}


class GlpiError(Exception):
    """GLPI is not configured, not reachable, or answered with an error."""


@dataclass(frozen=True)
class GlpiConfig:
    url: str
    user_token: str
    app_token: str = ""
    verify_ssl: bool = True
    ssl_cert_path: Optional[str] = None
    timeout: float = 30.0
    domain: str = "DEFAULT_DOMAIN"
    entity_domains: Mapping[str, str] = field(default_factory=dict)  # entity complete name -> QRadar domain
    itemtypes: Tuple[str, ...] = tuple(ITEMTYPES)
    states: Tuple[str, ...] = ()
    ignore_ports: Tuple[str, ...] = IGNORED_PORTS
    overwrite: bool = False
    mapping: Mapping[str, Mapping[str, Any]] = field(default_factory=lambda: dict(DEFAULT_MAPPING))

    @property
    def verify(self) -> Union[bool, str]:
        if not self.verify_ssl:
            return False
        return self.ssl_cert_path or True

    def __repr__(self) -> str:
        return f"GlpiConfig(url={self.url!r}, verify={self.verify!r})"

    def domain_of(self, entity: str) -> str:
        """The QRadar domain of an entity: the most precise entry of entity_domains covering it, else domain."""
        best, depth = self.domain, -1
        for name, domain in self.entity_domains.items():
            key = _entity_path(name)
            path = _entity_path(entity)
            if path[: len(key)] == key and len(key) > depth:
                best, depth = domain, len(key)
        return best


def _entity_path(name: str) -> Tuple[str, ...]:
    return tuple(part.strip().casefold() for part in str(name).split(">") if part.strip())


def _flag(raw: Mapping[str, Any], key: str, default: bool) -> bool:
    value = raw.get(key, default)
    if isinstance(value, str):
        value = value.strip().lower() in ("true", "on", "yes", "1")
    return bool(value)


def _names(value: Any, key: str) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)) or not all(isinstance(v, str) and v.strip() for v in value):
        raise GlpiError(f"'glpi.{key}' must be a list of names")
    return tuple(v.strip() for v in value)


def load_glpi_config(sections: Optional[Mapping[str, Any]], environ: Optional[Mapping[str, str]] = None) -> GlpiConfig:
    """GLPI settings from the "glpi" section of config.json, GLPI_URL / GLPI_USER_TOKEN / GLPI_APP_TOKEN winning."""
    environ = os.environ if environ is None else environ
    raw = dict((sections or {}).get("glpi") or {})
    for env_name, key in (
        ("GLPI_URL", "url"),
        ("GLPI_USER_TOKEN", "user_token"),
        ("GLPI_APP_TOKEN", "app_token"),
        ("GLPI_SSL_CERT_PATH", "ssl_cert_path"),
    ):
        if environ.get(env_name):
            raw[key] = environ[env_name]

    known = {
        "url",
        "user_token",
        "app_token",
        "verify_ssl",
        "ssl_cert_path",
        "timeout",
        "domain",
        "entity_domains",
        "itemtypes",
        "states",
        "ignore_ports",
        "overwrite",
        "mapping",
    }
    unknown = sorted(set(raw) - known)
    if unknown:
        raise GlpiError(f"Unknown glpi setting(s): {', '.join(unknown)}")
    url = str(raw.get("url") or "").rstrip("/")
    if url.endswith("/apirest.php"):
        url = url[: -len("/apirest.php")]
    if not url:
        raise GlpiError("GLPI is not configured: add a 'glpi' section with 'url' and 'user_token' to the config file")
    user_token = str(raw.get("user_token") or "")
    if not user_token or user_token == PLACEHOLDER_TOKEN:
        raise GlpiError(
            "'glpi.user_token' is not set: put the API token of a read-only GLPI user in the config file "
            "or GLPI_USER_TOKEN"
        )
    app_token = str(raw.get("app_token") or "")
    if app_token == PLACEHOLDER_TOKEN:
        app_token = ""

    verify_ssl = _flag(raw, "verify_ssl", True)
    ssl_cert_path = raw.get("ssl_cert_path") or None
    if verify_ssl and ssl_cert_path and not os.path.isfile(str(ssl_cert_path)):
        raise GlpiError(f"glpi.ssl_cert_path {ssl_cert_path} does not exist")

    itemtypes = _names(raw.get("itemtypes", list(ITEMTYPES)), "itemtypes")
    unknown_types = [t for t in itemtypes if t not in ITEMTYPES]
    if unknown_types:
        raise GlpiError(f"Unknown glpi.itemtypes: {', '.join(unknown_types)} (known: {', '.join(ITEMTYPES)})")
    entity_domains = raw.get("entity_domains") or {}
    if not isinstance(entity_domains, Mapping) or not all(
        isinstance(k, str) and k.strip() and isinstance(v, str) and v.strip() for k, v in entity_domains.items()
    ):
        raise GlpiError("'glpi.entity_domains' must map GLPI entity names to QRadar domains")

    try:
        mapping = normalize_mapping("glpi", raw.get("mapping", DEFAULT_MAPPING), RECORD_FIELDS)
    except MappingError as e:
        raise GlpiError(str(e)) from e

    try:
        timeout = float(raw.get("timeout", 30))
    except (TypeError, ValueError) as e:
        raise GlpiError("'glpi.timeout' must be a number") from e

    return GlpiConfig(
        url=url,
        user_token=user_token,
        app_token=app_token,
        verify_ssl=verify_ssl,
        ssl_cert_path=str(ssl_cert_path) if ssl_cert_path else None,
        timeout=timeout,
        domain=str(raw.get("domain") or "DEFAULT_DOMAIN"),
        entity_domains={k.strip(): v.strip() for k, v in entity_domains.items()},
        itemtypes=itemtypes,
        states=_names(raw.get("states"), "states"),
        ignore_ports=_names(raw.get("ignore_ports", list(IGNORED_PORTS)), "ignore_ports"),
        overwrite=_flag(raw, "overwrite", False),
        mapping=mapping,
    )


class GlpiRightMissing(GlpiError):
    """The profile of the GLPI user cannot read a type of item."""


class GlpiClient:
    """A session of the GLPI legacy REST API, read only. Use as a context manager: the session is always closed."""

    def __init__(self, config: GlpiConfig, session: Optional[requests.Session] = None):
        self.config = config
        self.session = session or requests.Session()
        self.session.headers.update({"Accept": "application/json"})
        if config.app_token:
            self.session.headers["App-Token"] = config.app_token
        self.session.verify = config.verify
        self.session_token: Optional[str] = None
        if not config.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning("TLS verification is disabled for GLPI %s", config.url)

    def __enter__(self) -> GlpiClient:
        self.open()
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def _url(self, path: str) -> str:
        return f"{self.config.url}/apirest.php/{path.strip('/')}"

    def _send(self, path: str, params: Optional[Mapping[str, Any]] = None, headers=None) -> requests.Response:
        try:
            # verify on each request: REQUESTS_CA_BUNDLE would override the session value, even False.
            return self.session.get(
                self._url(path), params=params, headers=headers, timeout=self.config.timeout, verify=self.session.verify
            )
        except requests.exceptions.SSLError as e:
            raise GlpiError(f"TLS verification failed for GLPI: {e} (see glpi.verify_ssl / ssl_cert_path)") from e
        except requests.RequestException as e:
            raise GlpiError(f"Cannot reach GLPI {self.config.url}: {e}") from e

    @staticmethod
    def _error(response: requests.Response) -> Tuple[str, str]:
        try:
            body = response.json()
        except ValueError:
            return "", response.reason or ""
        if isinstance(body, list) and body and isinstance(body[0], str):
            return body[0], str(body[1]) if len(body) > 1 else ""
        return "", response.reason or ""

    def _check(self, response: requests.Response, path: str) -> None:
        if response.status_code < 400:
            return
        code, message = self._error(response)
        if code == "ERROR_RIGHT_MISSING":
            raise GlpiRightMissing(f"the GLPI user cannot read {path.split('/')[0]}")
        hint = ERRORS.get(code)
        raise GlpiError(
            f"GLPI {code or 'error'} (HTTP {response.status_code}) on {path}: {hint or message or response.reason}"
        )

    def open(self) -> None:
        headers = {"Authorization": f"user_token {self.config.user_token}"}
        response = self._send("initSession", headers=headers)
        self._check(response, "initSession")
        try:
            token = response.json()["session_token"]
        except (ValueError, KeyError, TypeError) as e:
            raise GlpiError("Invalid answer from GLPI to initSession") from e
        self.session_token = token
        self.session.headers["Session-Token"] = token

    def close(self) -> None:
        if self.session_token:
            try:
                self._send("killSession")
            except GlpiError:
                pass  # the session ends by itself in GLPI
            self.session_token = None
            self.session.headers.pop("Session-Token", None)

    def get_all(self, path: str, params: Optional[Mapping[str, Any]] = None, progress=None) -> List[dict]:
        """Every item of a list, page after page ("range"); the session is renewed once if GLPI ended it."""
        progress = or_none(progress)
        items: List[dict] = []
        start, size, renewed = 0, PAGE_SIZE, False
        while True:
            progress.check_cancelled()
            response = self._send(path, {**(params or {}), "range": f"{start}-{start + size - 1}"})
            code, _ = self._error(response) if response.status_code >= 400 else ("", "")
            if code == "ERROR_SESSION_TOKEN_INVALID" and not renewed:
                renewed = True
                self.open()
                continue
            if code == "ERROR_RANGE_EXCEED_TOTAL":
                return items
            self._check(response, path)
            try:
                page = response.json()
            except ValueError as e:
                raise GlpiError(f"Invalid JSON from GLPI on {path}") from e
            if not isinstance(page, list):
                raise GlpiError(f"Unexpected answer from GLPI for {path}")
            items += [item for item in page if isinstance(item, Mapping)]
            progress.advance(len(page))
            total = _total(response.headers.get("Content-Range"))
            accepted = _total(response.headers.get("Accept-Range"))
            if accepted and start == 0 and accepted < size:
                size = accepted
            if total is not None and start == 0:
                progress.set_total(total)
            start += len(page)
            if not page or total is None or start >= total:
                return items


def _total(header: Optional[str]) -> Optional[int]:
    """The number after the last "/" (Content-Range "0-49/120") or space (Accept-Range "Computer 5000")."""
    if not header:
        return None
    tail = header.replace(" ", "/").rsplit("/", 1)[-1]
    return int(tail) if tail.isdigit() else None


# --- Records -----------------------------------------------------------------


def _text(value: Any) -> str:
    text = "" if value is None else str(value).strip()
    return "" if text in ("0", "&nbsp;") else text


def _kept_ip(value: str) -> Optional[str]:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
        return None
    return str(ip)


def _system(name: str, version: str) -> str:
    """The name and the version, the version only when the name does not hold it ("Ubuntu 24.04.5 LTS")."""
    first = version.split()[0] if version else ""
    return name if first and first in name else " ".join(p for p in (name, version) if p)


def _ip_sort_key(values: Sequence[str]) -> Tuple[int, int]:
    try:
        ip = ipaddress.ip_address(values[0])
        return ip.version, int(ip)
    except (ValueError, IndexError):
        return 9, 0


@dataclass
class GlpiData:
    """What GLPI answered, before any record is built."""

    items: Dict[str, List[dict]]  # itemtype -> items (expanded dropdowns)
    addresses: List[dict] = field(default_factory=list)  # IPAddress
    names: List[dict] = field(default_factory=list)  # NetworkName: an address -> its port
    ports: List[dict] = field(default_factory=list)  # NetworkPort
    groups: List[dict] = field(default_factory=list)  # Group_Item
    group_names: List[dict] = field(default_factory=list)  # Group
    systems: List[dict] = field(default_factory=list)  # Item_OperatingSystem
    system_names: List[dict] = field(default_factory=list)  # OperatingSystem
    system_versions: List[dict] = field(default_factory=list)  # OperatingSystemVersion
    skipped: List[Tuple[str, str]] = field(default_factory=list)  # (itemtype, reason) not read


def _key(itemtype: Any, item_id: Any) -> Tuple[str, str]:
    return str(itemtype), str(item_id)


def build_records(data: GlpiData, config: GlpiConfig) -> Tuple[List[Dict[str, Any]], int, List[Tuple[str, str]]]:
    """
    One record per GLPI asset kept (no template, status of the config), with
    its addresses; the number of assets read; the assets left aside, with why.
    """
    ports = {str(port.get("id")): port for port in data.ports}
    port_of_name = {
        str(n.get("id")): ports.get(str(n.get("items_id"))) for n in data.names if n.get("itemtype") == "NetworkPort"
    }

    def ignored(port: Optional[Mapping]) -> bool:
        if not port:
            return False
        name = str(port.get("name") or "").lower()
        local = port.get("instantiation_type") == "NetworkPortLocal"
        return local or any(fnmatch.fnmatch(name, pattern.lower()) for pattern in config.ignore_ports)

    ips: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    for address in data.addresses:
        ip = _kept_ip(str(address.get("name") or ""))
        port = port_of_name.get(str(address.get("items_id"))) if address.get("itemtype") == "NetworkName" else None
        if ip and not _text(address.get("is_deleted")) and not ignored(port):
            ips[_key(address.get("mainitemtype"), address.get("mainitems_id"))].append(ip)
    macs: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    for port in data.ports:
        mac = normalize_mac(str(port.get("mac") or ""))
        if mac and mac != "00:00:00:00:00:00" and not ignored(port):
            macs[_key(port.get("itemtype"), port.get("items_id"))].append(mac)
    group_names = {str(g.get("id")): _text(g.get("name")) for g in data.group_names}
    groups: Dict[Tuple[str, str, int], List[str]] = defaultdict(list)
    for link in data.groups:
        name = group_names.get(str(link.get("groups_id")), "")
        if name:
            groups[(*_key(link.get("itemtype"), link.get("items_id")), int(link.get("type") or GROUP))].append(name)
    system_names = {str(o.get("id")): _text(o.get("name")) for o in data.system_names}
    system_versions = {str(v.get("id")): _text(v.get("name")) for v in data.system_versions}
    systems: Dict[Tuple[str, str], Tuple[str, str]] = {}
    for system in data.systems:
        os_name = system_names.get(str(system.get("operatingsystems_id")), "")
        os_version = system_versions.get(str(system.get("operatingsystemversions_id")), "")
        if os_name or os_version:
            systems[_key(system.get("itemtype"), system.get("items_id"))] = (os_name, os_version)

    wanted_states = {s.casefold() for s in config.states}
    records, skipped, read = [], list(data.skipped), 0
    for itemtype, items in data.items.items():
        type_field, model_field = f"{itemtype.lower()}types_id", f"{itemtype.lower()}models_id"  # computertypes_id
        for item in items:
            if _text(item.get("is_template")):
                continue
            read += 1
            name = _text(item.get("name"))
            label = f"{ITEMTYPES[itemtype]} {name or item.get('id')}"
            status = _text(item.get("states_id"))
            if wanted_states and status.casefold() not in wanted_states:
                skipped.append((label, f"status '{status or 'none'}' not in glpi.states"))
                continue
            key = _key(itemtype, item.get("id"))
            if not ips.get(key) and not macs.get(key):
                skipped.append((label, "no IP nor MAC address in GLPI"))
                continue
            entity = _text(item.get("entities_id"))
            records.append(
                {
                    "itemtype": ITEMTYPES[itemtype],
                    "name": name,
                    "comment": _text(item.get("comment")),
                    "serial": _text(item.get("serial")),
                    "inventory_number": _text(item.get("otherserial")),
                    "uuid": _text(item.get("uuid")),
                    "entity": entity,
                    "location": _text(item.get("locations_id")),
                    "type": _text(item.get(type_field)),
                    "manufacturer": _text(item.get("manufacturers_id")),
                    "model": _text(item.get(model_field)),
                    "status": status,
                    "user": _text(item.get("users_id")),
                    "technician": _text(item.get("users_id_tech")),
                    "group": "; ".join(groups.get((*key, GROUP), [])),
                    "technical_group": "; ".join(groups.get((*key, TECHNICAL_GROUP), [])),
                    "contact": _text(item.get("contact")),
                    "os": _system(*systems.get(key, ("", ""))),
                    "os_name": systems.get(key, ("", ""))[0],
                    "os_version": systems.get(key, ("", ""))[1],
                    "ips": list(dict.fromkeys(ips.get(key, []))),
                    "macs": list(dict.fromkeys(macs.get(key, []))),
                    "domain": config.domain_of(entity),
                }
            )
    return records, read, skipped


def import_rows(
    records: Sequence[Mapping[str, Any]], config: GlpiConfig, domain: Optional[str] = None
) -> Tuple[List[str], List[ImportRow]]:
    """
    Header and rows in the import format: one row per GLPI asset, its domain
    from entity_domains (domain, when given, replaces the default domain).
    """
    properties = list(config.mapping)
    header = ["ip_addresses", "mac_addresses", "dns_names", "domain_name", *properties]
    rows = []
    for line, record in enumerate(sorted(records, key=lambda r: _ip_sort_key(r["ips"])), start=2):
        row_domain = record["domain"]
        if domain is not None and row_domain == config.domain:
            row_domain = domain
        values = {
            "ip_addresses": ";".join(record["ips"]),
            "mac_addresses": ";".join(record["macs"]),
            "dns_names": record["name"],
            "domain_name": row_domain,
        }
        values.update({prop: apply_rule(record, rule) for prop, rule in config.mapping.items()})
        rows.append(ImportRow(line, values))
    return header, rows


def fetch_data(client: GlpiClient, progress: Optional[Progress] = None) -> GlpiData:
    """The assets of the types of the config, then their addresses, groups and operating systems, read in bulk."""
    progress = or_none(progress)
    expanded = {"expand_dropdowns": "true"}
    items: Dict[str, List[dict]] = {}
    skipped: List[Tuple[str, str]] = []
    for itemtype in client.config.itemtypes:
        progress.phase(f"GLPI {ITEMTYPES[itemtype].lower()}s")
        try:
            items[itemtype] = client.get_all(itemtype, {**expanded, "is_deleted": "false"}, progress)
        except GlpiRightMissing as e:
            skipped.append((ITEMTYPES[itemtype] + "s", str(e)))
    progress.phase("GLPI network addresses")
    addresses = client.get_all("IPAddress", progress=progress)
    names = client.get_all("NetworkName", progress=progress)
    ports = client.get_all("NetworkPort", progress=progress)
    progress.phase("GLPI groups and operating systems")
    # As they are: expand_dropdowns would replace items_id by the name of the asset.
    groups = client.get_all("Group_Item", progress=progress)
    group_names = client.get_all("Group", progress=progress) if groups else []
    systems = client.get_all("Item_OperatingSystem", progress=progress)
    system_names = client.get_all("OperatingSystem", progress=progress) if systems else []
    system_versions = client.get_all("OperatingSystemVersion", progress=progress) if systems else []
    return GlpiData(
        items, addresses, names, ports, groups, group_names, systems, system_names, system_versions, skipped
    )


def fetch_records(
    config: GlpiConfig, session: Optional[requests.Session] = None, progress: Optional[Progress] = None
) -> Tuple[List[Dict[str, Any]], int, List[Tuple[str, str]]]:
    """The records of the GLPI assets kept, the number read and those left aside; the session is always closed."""
    with GlpiClient(config, session=session) as client:
        data = fetch_data(client, progress)
    return build_records(data, config)
