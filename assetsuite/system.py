"""
system.py

QRadar system and domain information, as offered by NHSuite's
--check-version and --check-domain.

Copyright 2026 Pascal Weber (zoldax) / Abakus Sécurité
Licensed under the Apache License, Version 2.0 (see LICENSE).
"""

from __future__ import annotations

from typing import List

from assetsuite.client import QRadarClient

DEFAULT_DOMAIN_NAME = "DEFAULT_DOMAIN"


def get_system_about(client: QRadarClient) -> dict:
    return client.get("system/about") or {}


def list_domains(client: QRadarClient) -> List[dict]:
    """Domains with the default domain (id 0, unnamed in the API) labelled explicitly."""
    domains = client.get_all("config/domain_management/domains")
    for domain in domains:
        if domain.get("id") == 0:
            domain["name"] = DEFAULT_DOMAIN_NAME
    return domains
