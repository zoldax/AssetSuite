import json

import pytest

from assetsuite.config import ConfigError, load_config


def write(tmp_path, data):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def test_minimal_config_defaults(tmp_path):
    config = load_config(write(tmp_path, {"host": "qradar.lan", "token": "abc"}), environ={})
    assert config.host == "qradar.lan"
    assert config.api_version is None
    assert config.verify is True
    assert config.safety is True


def test_nhsuite_legacy_config_is_accepted(tmp_path):
    legacy = {
        "ip_QRadar": "qradar.lan",
        "auth": "abc",
        "Version": "17.0",
        "Accept": "application/json",
        "verify_ssl": "False",
        "ssl_cert_path": "None",
        "safety": "on",
    }
    config = load_config(write(tmp_path, legacy), environ={})
    assert (config.host, config.token, config.api_version) == ("qradar.lan", "abc", "17.0")
    assert config.verify is False
    assert config.safety is True


def test_verify_true_without_cert_keeps_verification(tmp_path):
    # NHSuite returned False here, silently disabling TLS verification.
    config = load_config(
        write(tmp_path, {"host": "q", "token": "t", "verify_ssl": "True", "ssl_cert_path": "None"}), {}
    )
    assert config.verify is True


def test_verify_with_custom_ca(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("pem", encoding="utf-8")
    config = load_config(write(tmp_path, {"host": "q", "token": "t", "ssl_cert_path": str(ca)}), {})
    assert config.verify == str(ca)


def test_missing_ca_file_is_an_error(tmp_path):
    with pytest.raises(ConfigError, match="does not exist"):
        load_config(write(tmp_path, {"host": "q", "token": "t", "ssl_cert_path": "/nope.pem"}), {})


def test_environment_overrides_file(tmp_path):
    path = write(tmp_path, {"host": "file.lan", "token": "CHANGE_ME"})
    config = load_config(path, {"QRADAR_HOST": "https://env.lan/", "QRADAR_SEC_TOKEN": "secret"})
    assert config.host == "env.lan"
    assert config.token == "secret"


@pytest.mark.parametrize("token", [None, "", "CHANGE_ME"])
def test_token_required(tmp_path, token):
    with pytest.raises(ConfigError, match="token"):
        load_config(write(tmp_path, {"host": "q", "token": token}), {})


def test_unknown_key_rejected(tmp_path):
    with pytest.raises(ConfigError, match="Unknown configuration key"):
        load_config(write(tmp_path, {"host": "q", "token": "t", "hots": "typo"}), {})


def test_bad_boolean_rejected(tmp_path):
    with pytest.raises(ConfigError, match="safety"):
        load_config(write(tmp_path, {"host": "q", "token": "t", "safety": "maybe"}), {})


def test_invalid_json(tmp_path):
    path = tmp_path / "config.json"
    path.write_text('{"host": "q",}', encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid JSON"):
        load_config(str(path), {})


def test_explicit_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="does not exist"):
        load_config(str(tmp_path / "missing.json"), {})


def test_token_not_in_repr(tmp_path):
    config = load_config(write(tmp_path, {"host": "q", "token": "very-secret"}), {})
    assert "very-secret" not in repr(config)


def test_ca_file_from_environment(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("pem", encoding="utf-8")
    config = load_config(None, {"QRADAR_HOST": "q", "QRADAR_SEC_TOKEN": "t", "QRADAR_SSL_CERT_PATH": str(ca)})
    assert config.verify == str(ca)


def test_integration_sections_kept(tmp_path):
    config = load_config(
        write(tmp_path, {"host": "q", "token": "t", "netbox": {"url": "https://nb", "token": "x"}}), {}
    )
    assert config.sections == {"netbox": {"url": "https://nb", "token": "x"}}
    assert "nb" not in repr(config)


def test_section_must_be_an_object(tmp_path):
    with pytest.raises(ConfigError, match="'netbox' must be a JSON object"):
        load_config(write(tmp_path, {"host": "q", "token": "t", "netbox": "https://nb"}), {})


def test_config_example_is_valid_and_generic():
    """config.example.json loads once the tokens are set, and only uses documentation values."""
    import ipaddress
    import pathlib

    from assetsuite.netbox import load_netbox_config
    from assetsuite.pfsense import load_pfsense_config
    from assetsuite.sevone import DEFAULT_MAPPING as SEVONE_MAPPING
    from assetsuite.sevone import load_sevone_config

    path = pathlib.Path(__file__).resolve().parent.parent / "config.example.json"
    text = path.read_text(encoding="utf-8")
    config = load_config(str(path), {"QRADAR_SEC_TOKEN": "t"})
    assert config.host.endswith(".example.lan")
    netbox = load_netbox_config(config.sections, {"NETBOX_TOKEN": "t"})
    assert netbox.url.endswith(".example.lan")
    sevone = load_sevone_config(config.sections, {"SEVONE_TOKEN": "t"})
    assert sevone.url.endswith(".example.lan") and list(sevone.mapping) == list(SEVONE_MAPPING)
    documentation = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    networks = load_pfsense_config(config.sections).networks
    assert networks and all(any(n.subnet_of(d) for d in documentation) for n in networks)
    assert "zoldax" not in text
