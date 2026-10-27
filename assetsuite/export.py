"""
export.py

Writes assets to CSV (flattened rows) or JSON (assets as returned by the API).

Asset data partly comes from the network (hostnames, user names), so CSV
cells that a spreadsheet would run as a formula are prefixed with a quote.

Copyright 2026 Pascal Weber (zoldax) / Abakus Sécurité
Licensed under the Apache License, Version 2.0 (see LICENSE).
"""

from __future__ import annotations

import csv
import json
import os
import re
from datetime import datetime
from typing import Iterable, Mapping, Sequence

EXPORT_DIR = "exports"
FORMULA_PREFIXES = ("=", "+", "@", "\t", "\r")
_NUMBER = re.compile(r"^-?\d+(\.\d+)?$")


def csv_safe(value: object) -> str:
    """Neutralize spreadsheet formulas (CSV injection). Plain negative numbers and a lone '-' stay as is."""
    text = "" if value is None else str(value)
    if text.startswith(FORMULA_PREFIXES) or (text.startswith("-") and len(text) > 1 and not _NUMBER.match(text)):
        return "'" + text
    return text


def default_export_path(host: str, extension: str, prefix: str = "assets") -> str:
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    return os.path.join(EXPORT_DIR, f"{prefix}-{host}-{timestamp}.{extension}")


def _prepare(path: str) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, mode=0o700, exist_ok=True)


def write_csv(path: str, columns: Sequence[str], rows: Iterable[Mapping[str, object]], delimiter: str = ",") -> int:
    """Write rows to a CSV file and return the number of data rows."""
    _prepare(path)
    count = 0
    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file, delimiter=delimiter, quotechar='"', quoting=csv.QUOTE_MINIMAL)
        writer.writerow(columns)
        for row in rows:
            writer.writerow([csv_safe(row.get(column)) for column in columns])
            count += 1
    return count


def write_json(path: str, assets: Sequence[Mapping]) -> int:
    """Write assets exactly as returned by QRadar and return their number."""
    _prepare(path)
    with open(path, "w", encoding="utf-8") as file:
        json.dump(list(assets), file, indent=2, ensure_ascii=False)
        file.write("\n")
    return len(assets)
