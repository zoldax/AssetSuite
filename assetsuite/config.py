"""
config.py

Loads the AssetSuite configuration from a JSON file, with environment
variable overrides so the SEC token never has to live on disk.

Copyright 2026 Pascal Weber (zoldax) / Abakus Sécurité
Licensed under the Apache License, Version 2.0 (see LICENSE).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, fields
from typing import Any, Dict, Mapping, Optional, Union

DEFAULT_CONFIG_FILE = "config.json"
PLACEHOLDER_TOKEN = "CHANGE_ME"  # noqa: S105 - placeholder from config.example.json, not a secret

# NHSuite config.txt keys, accepted so an existing config can be reused as-is.
LEGACY_KEYS = {"ip_QRadar": "host", "auth": "token", "Version": "api_version"}
IGNORED_KEYS = {"Accept"}
# Settings of other systems, kept as is for the integration that uses them.
SECTIONS = ("netbox", "pfsense")

ENV_OVERRIDES = {
    "QRADAR_HOST": "host",
    "QRADAR_SEC_TOKEN": "token",
    "QRADAR_API_VERSION": "api_version",
    "QRADAR_SSL_CERT_PATH": "ssl_cert_path",
}

_TRUE = {"true", "on", "yes", "1"}
_FALSE = {"false", "off", "no", "0"}
_NONE = {"", "none", "null", "latest"}


class ConfigError(Exception):
    """Raised when the configuration is missing, malformed or inconsistent."""


@dataclass(frozen=True)
class Config:
    host: str
    token: str
    api_version: Optional[str] = None  # None = let QRadar use its latest version
    verify_ssl: bool = True
    ssl_cert_path: Optional[str] = None
    safety: bool = True
    timeout: float = 30.0
    page_size: int = 500
    log_file: str = "assetsuite.log"
    sections: Optional[Dict[str, Any]] = None

    @property
    def verify(self) -> Union[bool, str]:
        """Value for the requests 'verify' argument."""
        if not self.verify_ssl:
            return False
        return self.ssl_cert_path or True

    def __repr__(self) -> str:
        # Keep the token out of logs and tracebacks.
        return f"Config(host={self.host!r}, api_version={self.api_version!r}, verify={self.verify!r})"


def _to_bool(key: str, value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in _TRUE:
        return True
    if isinstance(value, str) and value.strip().lower() in _FALSE:
        return False
    raise ConfigError(f"'{key}' must be true/false (or on/off), got {value!r}")


def _to_optional_str(value: object) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return None if text.lower() in _NONE else text


def _read_file(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as file:
            data = json.load(file)
    except json.JSONDecodeError as e:
        raise ConfigError(f"{path} is not valid JSON: {e}") from e
    except OSError as e:
        raise ConfigError(f"Cannot read {path}: {e}") from e
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain a JSON object")
    return data


def load_config(path: Optional[str] = None, environ: Optional[Mapping[str, str]] = None) -> Config:
    """
    Build a Config from a JSON file and the environment.

    The file is optional when every required value comes from the environment,
    unless a path was given explicitly. Environment variables win over the file.
    """
    environ = os.environ if environ is None else environ

    raw: dict = {}
    if path is not None:
        if not os.path.exists(path):
            raise ConfigError(f"{path} does not exist")
        raw = _read_file(path)
    elif os.path.exists(DEFAULT_CONFIG_FILE):
        raw = _read_file(DEFAULT_CONFIG_FILE)

    sections = {key: raw.pop(key) for key in SECTIONS if key in raw}
    for key, section in sections.items():
        if not isinstance(section, dict):
            raise ConfigError(f"'{key}' must be a JSON object")
    values = {LEGACY_KEYS.get(key, key): value for key, value in raw.items() if key not in IGNORED_KEYS}
    for env_name, key in ENV_OVERRIDES.items():
        if environ.get(env_name):
            values[key] = environ[env_name]

    known = {f.name for f in fields(Config)} - {"sections"}
    unknown = sorted(set(values) - known)
    if unknown:
        raise ConfigError(f"Unknown configuration key(s): {', '.join(unknown)}")

    host = _to_optional_str(values.get("host"))
    if not host:
        raise ConfigError("'host' is required (config file or QRADAR_HOST)")
    host = host.removeprefix("https://").removeprefix("http://").rstrip("/")

    token = _to_optional_str(values.get("token"))
    if not token or token == PLACEHOLDER_TOKEN:
        raise ConfigError("'token' is not set: put your SEC token in the config file or in QRADAR_SEC_TOKEN")

    verify_ssl = _to_bool("verify_ssl", values.get("verify_ssl", True))
    ssl_cert_path = _to_optional_str(values.get("ssl_cert_path"))
    if verify_ssl and ssl_cert_path and not os.path.isfile(ssl_cert_path):
        raise ConfigError(f"ssl_cert_path {ssl_cert_path} does not exist")

    try:
        timeout = float(values.get("timeout", Config.timeout))
        page_size = int(values.get("page_size", Config.page_size))
    except (TypeError, ValueError) as e:
        raise ConfigError(f"'timeout' and 'page_size' must be numbers: {e}") from e
    if timeout <= 0 or page_size <= 0:
        raise ConfigError("'timeout' and 'page_size' must be positive")

    return Config(
        host=host,
        token=token,
        api_version=_to_optional_str(values.get("api_version")),
        verify_ssl=verify_ssl,
        ssl_cert_path=ssl_cert_path,
        safety=_to_bool("safety", values.get("safety", True)),
        timeout=timeout,
        page_size=page_size,
        log_file=_to_optional_str(values.get("log_file")) or Config.log_file,
        sections=sections,
    )
