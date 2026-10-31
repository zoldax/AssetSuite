"""TLS settings win over REQUESTS_CA_BUNDLE (set in QRadar App containers), for QRadar, NetBox and SevOne.

requests lets REQUESTS_CA_BUNDLE replace a session-level verify, even verify=False: the clients pass verify on
each request.
"""

import dataclasses

import pytest
import responses

from assetsuite.client import QRadarClient
from tests.conftest import BASE


@pytest.fixture(autouse=True)
def container_bundle(monkeypatch, tmp_path):
    bundle = tmp_path / "container-bundle.crt"
    bundle.write_text("# container bundle\n")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(bundle))
    return str(bundle)


def sent_verify():
    return responses.calls[-1].request.req_kwargs["verify"]


@responses.activate
@pytest.mark.parametrize("verify_ssl", [False, True])
def test_qradar_client(config, tmp_path, verify_ssl):
    ca = tmp_path / "qradar-ca.pem"
    ca.write_text("x")
    client = QRadarClient(dataclasses.replace(config, verify_ssl=verify_ssl, ssl_cert_path=str(ca)))
    responses.get(f"{BASE}/help/versions", json=[])
    client.get("help/versions")
    assert sent_verify() == (str(ca) if verify_ssl else False)


@responses.activate
@pytest.mark.parametrize("verify_ssl", [False, True])
def test_netbox_client(tmp_path, verify_ssl):
    from assetsuite.netbox import NetBoxClient
    from tests.test_netbox import NB
    from tests.test_netbox import config as netbox_config

    ca = tmp_path / "netbox-ca.pem"
    ca.write_text("x")
    responses.get(f"{NB}/api/ipam/ip-addresses/", json={"next": None, "results": []})
    NetBoxClient(netbox_config(verify_ssl=verify_ssl, ssl_cert_path=str(ca))).get_all("ipam/ip-addresses")
    assert sent_verify() == (str(ca) if verify_ssl else False)


@responses.activate
@pytest.mark.parametrize("verify_ssl", [False, True])
def test_sevone_client(tmp_path, verify_ssl):
    from assetsuite.sevone import SevOneClient
    from tests.test_sevone import SO
    from tests.test_sevone import config as sevone_config

    ca = tmp_path / "sevone-ca.pem"
    ca.write_text("x")
    responses.get(f"{SO}/api/v3/health/version", json={"version": "7.2.1"})
    SevOneClient(sevone_config(verify_ssl=verify_ssl, ssl_cert_path=str(ca))).get("api/v3/health/version")
    assert sent_verify() == (str(ca) if verify_ssl else False)
