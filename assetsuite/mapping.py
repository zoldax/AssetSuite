"""
mapping.py

Property mapping rules shared by the integrations (NetBox, pfSense, SevOne): a QRadar
property is filled from the fields of a source record.

Rule forms in the configuration:
    "field"                                   first non-empty of one field
    ["field1", "field2"]                      first non-empty field
    {"first": ["field1", "field2"]}           same
    {"join": ["f1", "f2"], "separator": " / "}  all non-empty fields, joined

Copyright 2026 Pascal Weber (zoldax) / Abakus Sécurité
Licensed under the Apache License, Version 2.0 (see LICENSE).
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Mapping, Sequence


class MappingError(Exception):
    """A mapping rule of the configuration is invalid."""


def normalize_rule(
    section: str, prop: str, rule: object, fields: Sequence[str], extra_field: Callable[[str], bool] = lambda f: False
) -> Dict[str, Any]:
    where = f"{section}.mapping['{prop}']"
    if isinstance(rule, str):
        rule = {"first": [rule]}
    elif isinstance(rule, list):
        rule = {"first": rule}
    if not isinstance(rule, dict) or len({"first", "join"} & set(rule)) != 1:
        raise MappingError(f"{where} must be a field name, a list, or {{'first'|'join': [fields]}}")
    names = rule.get("first") or rule.get("join")
    if not isinstance(names, list) or not names:
        raise MappingError(f"{where} needs at least one field")
    unknown = [name for name in names if name not in fields and not extra_field(str(name))]
    if unknown:
        raise MappingError(f"{where}: unknown field(s) {', '.join(map(str, unknown))}. Fields: {', '.join(fields)}")
    return dict(rule)


def normalize_mapping(
    section: str, mapping: object, fields: Sequence[str], extra_field: Callable[[str], bool] = lambda f: False
) -> Dict[str, Dict[str, Any]]:
    if not isinstance(mapping, dict) or not mapping:
        raise MappingError(f"'{section}.mapping' must map QRadar properties to {section} fields")
    return {prop: normalize_rule(section, prop, rule, fields, extra_field) for prop, rule in mapping.items()}


def apply_rule(record: Mapping[str, str], rule: Mapping[str, Any]) -> str:
    if "first" in rule:
        return next((record.get(f, "") for f in rule["first"] if record.get(f, "")), "")
    values = [record.get(f, "") for f in rule["join"] if record.get(f, "")]
    return str(rule.get("separator", " / ")).join(values)
