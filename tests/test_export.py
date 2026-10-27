import csv
import json

import pytest

from assetsuite.export import csv_safe, default_export_path, write_csv, write_json


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("=cmd|' /C calc'!A0", "'=cmd|' /C calc'!A0"),
        ("+33 1 02 03", "'+33 1 02 03"),
        ("@SUM(A1)", "'@SUM(A1)"),
        ("-2+3", "'-2+3"),
        ("-", "-"),
        ("-12.5", "-12.5"),
        ("srv-db01", "srv-db01"),
        (None, ""),
        (0, "0"),
    ],
)
def test_csv_safe(value, expected):
    assert csv_safe(value) == expected


def test_write_csv(tmp_path):
    path = tmp_path / "out" / "assets.csv"
    count = write_csv(str(path), ["id", "users"], [{"id": 1, "users": "admin;=evil()"}, {"id": 2}], delimiter=";")
    assert count == 2
    with open(path, encoding="utf-8", newline="") as file:
        rows = list(csv.reader(file, delimiter=";"))
    assert rows == [["id", "users"], ["1", "admin;=evil()"], ["2", ""]]


def test_formula_cell_is_escaped(tmp_path):
    path = tmp_path / "assets.csv"
    write_csv(str(path), ["users"], [{"users": "=1+1"}])
    assert path.read_text(encoding="utf-8").splitlines()[1] == "'=1+1"


def test_write_json_keeps_api_payload(tmp_path):
    path = tmp_path / "assets.json"
    assets = [{"id": 1, "hostnames": [{"name": "é"}]}]
    assert write_json(str(path), assets) == 1
    assert json.loads(path.read_text(encoding="utf-8")) == assets


def test_default_export_path():
    path = default_export_path("qradar.example.lan", "csv")
    assert path.startswith("exports/assets-qradar.example.lan-") and path.endswith(".csv")
