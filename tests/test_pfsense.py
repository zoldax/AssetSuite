"""pfSense integration, with backups shaped like pfSense exports (values anonymized)."""

import ipaddress
import os

import pytest

from assetsuite.pfsense import (
    DEFAULT_MAPPING,
    PfSenseConfig,
    PfSenseError,
    build_records,
    category,
    import_rows,
    load_pfsense_config,
    read_backups,
    resolve_files,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
UNBOUND = os.path.join(FIXTURES, "pfsense-unbound.xml")
DHCPD = os.path.join(FIXTURES, "pfsense-dhcpd.xml")


def records(config=None, files=(UNBOUND, DHCPD)):
    return {r["ip"]: r for r in build_records(read_backups(list(files)), config or PfSenseConfig())}


# --- Configuration -----------------------------------------------------------


def test_config_defaults():
    config = load_pfsense_config({})
    assert config.files == ("private/*.xml",)
    assert config.domain == "DEFAULT_DOMAIN" and not config.overwrite and config.networks == ()
    assert list(config.mapping) == list(DEFAULT_MAPPING)


def test_config_values():
    config = load_pfsense_config(
        {"pfsense": {"files": "a.xml", "networks": ["192.0.2.0/24"], "dns_domain": "example.lan.", "overwrite": True}}
    )
    assert config.files == ("a.xml",)
    assert config.networks == (ipaddress.ip_network("192.0.2.0/24"),)
    assert config.dns_domain == "example.lan" and config.overwrite


@pytest.mark.parametrize(
    ("section", "message"),
    [
        ({"filez": []}, "Unknown pfsense setting"),
        ({"networks": ["192.0.2.0/33"]}, "Invalid pfsense.networks"),
        ({"overwrite": "yes"}, "must be true or false"),
        ({"mapping": {"Given Name": "hostname"}}, "unknown field"),
    ],
)
def test_config_errors(section, message):
    with pytest.raises(PfSenseError, match=message):
        load_pfsense_config({"pfsense": section})


def test_resolve_files(tmp_path):
    (tmp_path / "b.xml").write_text("<unbound/>")
    (tmp_path / "a.xml").write_text("<unbound/>")
    assert [os.path.basename(f) for f in resolve_files([str(tmp_path / "*.xml")])] == ["a.xml", "b.xml"]
    with pytest.raises(PfSenseError, match="No pfSense backup file found"):
        resolve_files([str(tmp_path / "*.json")])
    with pytest.raises(PfSenseError, match="not found"):
        resolve_files([str(tmp_path / "missing.xml")])


# --- Reading -----------------------------------------------------------------


def test_dns_and_dhcp_merged_by_ip():
    ws = records()["192.0.2.143"]
    assert ws["dns_name"] == "ws01.example.lan"  # host override wins over the DHCP hostname
    assert ws["mac"] == "a4:fc:14:00:00:01"  # normalized
    assert ws["dns_description"] == "PC FIXE - Workstation 01"
    assert ws["dhcp_description"] == "MAC Fixe - ethernet"
    assert ws["category"] == "PC FIXE"
    assert (ws["interface"], ws["source"]) == ("lan", "dns+dhcp")


def test_first_host_override_is_the_name():
    assert records()["192.0.2.26"]["dns_name"] == "docker.example.lan"


def test_dhcp_only_names():
    by_ip = records(PfSenseConfig(dns_domain="example.lan"))
    assert by_ip["192.0.2.70"]["dns_name"] == "diskstation.example.lan"  # configured domain
    assert by_ip["198.51.100.90"]["dns_name"] == "scale.iot.example.lan"  # static mapping domain wins
    assert records()["192.0.2.70"]["dns_name"] == "diskstation"  # no domain known
    assert "reserved-only" not in {r["host"] for r in by_ip.values()}  # MAC-only reservation skipped


def test_networks_filter():
    by_ip = records(PfSenseConfig(networks=(ipaddress.ip_network("192.0.2.0/24"),)))
    assert sorted(by_ip) == ["192.0.2.143", "192.0.2.26", "192.0.2.70", "192.0.2.71"]


def test_full_backup_root(tmp_path):
    unbound = open(UNBOUND, encoding="utf-8").read().replace('<?xml version="1.0"?>', "")
    dhcpd = open(DHCPD, encoding="utf-8").read().replace('<?xml version="1.0"?>', "")
    full = tmp_path / "config.xml"
    full.write_text(
        f'<?xml version="1.0"?>\n<pfsense><system><password>x</password></system>{unbound}{dhcpd}</pfsense>'
    )
    assert records(files=[str(full)]) == records()


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><unbound/>', "DOCTYPE or entities is refused"),
        ("<unbound><hosts>", "not a valid XML file"),
        ("<system/>", "not a pfSense backup of the DNS Resolver or DHCP Server"),
    ],
)
def test_bad_files(tmp_path, content, message):
    path = tmp_path / "bad.xml"
    path.write_text(content)
    with pytest.raises(PfSenseError, match=message):
        read_backups([str(path)])


@pytest.mark.parametrize(
    ("description", "expected"),
    [
        ("NAS - DS212", "NAS"),
        ("PC FIXE - NUC", "PC FIXE"),
        ("DOMOTIQUE - Bridge lumière", "DOMOTIQUE"),
        ("MAX Fixe - Pascal", ""),  # not upper-case
        ("VMWare- ESX02", ""),
        ("Docker host", ""),
        ("123 - x", ""),
        ("", ""),
    ],
)
def test_category(description, expected):
    assert category(description) == expected


# --- Rows --------------------------------------------------------------------


def test_import_rows():
    header, rows = import_rows(build_records(read_backups([UNBOUND, DHCPD]), PfSenseConfig()), PfSenseConfig(), "PROD1")
    assert header == ["ip_address", "mac_address", "dns_names", "domain_name", *DEFAULT_MAPPING]
    by_ip = {r.values["ip_address"]: r.values for r in rows}
    ws = by_ip["192.0.2.143"]
    assert (ws["mac_address"], ws["dns_names"], ws["domain_name"]) == ("a4:fc:14:00:00:01", "ws01.example.lan", "PROD1")
    assert (ws["Given Name"], ws["Description"], ws["Asset Type"]) == (
        "ws01.example.lan",
        "PC FIXE - Workstation 01",
        "PC FIXE",
    )
    assert by_ip["192.0.2.70"]["Description"] == "NAS - DiskStation"  # DHCP description when no override
    assert [r.line for r in rows] == list(range(2, len(rows) + 2))


def test_missing_defusedxml_is_a_clear_error(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "defusedxml", None)
    with pytest.raises(PfSenseError, match="defusedxml package is missing"):
        read_backups([UNBOUND])
