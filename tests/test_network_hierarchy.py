import ipaddress

import pytest
import responses

from assetsuite.network_hierarchy import (
    NetworkHierarchyError,
    NHIndex,
    NHNetwork,
    check_network_hierarchy,
    load_from_api,
    load_from_nhsuite_csv,
)
from assetsuite.quality import CHECKS, ReportOptions
from tests.conftest import BASE
from tests.fixtures import HOSTNAME_ONLY, NOW, SERVER, WORKSTATION

ALL = set(CHECKS)


def net(id_, cidr, group="Servers", name="net", domain_id=0, network_id=None):
    return NHNetwork(id_, network_id, group, name, ipaddress.ip_network(cidr), domain_id)


NETWORKS = [
    net(1, "192.0.2.0/24", "Z_Catch", "doc", network_id=254),
    net(2, "192.0.2.143/32", "Workstations", "ws01", network_id=300),
    net(3, "10.1.0.0/16", "Servers", "db", domain_id=1, network_id=310),
    net(4, "10.2.0.0/16", "Servers", "backup", domain_id=2, network_id=320),
    net(5, "198.51.100.0/24", "Z_Catch.Lab", "lab", network_id=330),
]


def run(assets, **kwargs):
    findings = check_network_hierarchy(assets, NHIndex(NETWORKS), ReportOptions(now=NOW, **kwargs), ALL)
    return {(f.check, f.asset_id, f.target) for f in findings}


def test_longest_prefix_lookup():
    index = NHIndex(NETWORKS)
    assert index.lookup("192.0.2.143").id == 2
    assert index.lookup("192.0.2.9").id == 1
    assert index.lookup("172.16.0.1") is None
    assert index.lookup("not-an-ip") is None


def test_outside_and_domain_mismatch():
    findings = run([SERVER])
    assert ("outside-nh", 3001, "2001:db8::24") in findings
    assert ("nh-domain-mismatch", 3001, "10.2.0.5") in findings
    assert not any(check == "nh-domain-mismatch" and target == "10.1.1.24" for check, _, target in findings)


def test_network_changed_uses_network_id():
    # WORKSTATION's IP was recorded in network_id 254, the /32 now gives 300.
    assert ("nh-network-changed", 2723, "192.0.2.143") in run([WORKSTATION])


def test_catch_all_groups_and_sub_groups():
    moved = {**WORKSTATION, "interfaces": [{"ip_addresses": [{"value": "192.0.2.9", "network_id": 254}]}]}
    lab = {**WORKSTATION, "id": 9003, "interfaces": [{"ip_addresses": [{"value": "198.51.100.4"}]}]}
    findings = run([moved, lab], catch_all_groups=["Z_Catch"])
    assert ("nh-catch-all", 2723, "192.0.2.9") in findings
    assert ("nh-catch-all", 9003, "198.51.100.4") in findings
    assert not run([moved]) & {("nh-catch-all", 2723, "192.0.2.9")}


def test_empty_networks_skip_catch_all():
    findings = run([WORKSTATION, HOSTNAME_ONLY], catch_all_groups=["Z_Catch"])
    empty = {target for check, _, target in findings if check == "empty-network"}
    assert empty == {"10.1.0.0/16", "10.2.0.0/16"}


@responses.activate
def test_load_from_api_single_request(client):
    responses.get(
        f"{BASE}/config/network_hierarchy/networks",
        json=[{"id": 252, "network_id": 239, "group": "Z", "name": "c", "cidr": "198.51.100.0/24", "domain_id": 0}],
        match=[responses.matchers.header_matcher({"Accept": "application/json"})],
    )
    [network] = load_from_api(client)
    assert (network.id, network.network_id, str(network.cidr)) == (252, 239, "198.51.100.0/24")
    assert "Range" not in responses.calls[0].request.headers


def test_load_nhsuite_csv(tmp_path):
    path = tmp_path / "nh.csv"
    path.write_text(
        "id,group,name,cidr,description,domain_id,location,country_code\n"
        "245,DMZ,dmz,192.0.2.0/24,,0,N/A,N/A\n"
        "244,dom.b,hyperv,203.0.113.0/24,,1,N/A,FR\n",
        encoding="utf-8",
    )
    networks = load_from_nhsuite_csv(str(path))
    assert [(n.group, str(n.cidr), n.domain_id, n.network_id) for n in networks] == [
        ("DMZ", "192.0.2.0/24", 0, None),
        ("dom.b", "203.0.113.0/24", 1, None),
    ]


@pytest.mark.parametrize(
    ("content", "message"),
    [("id,name\n1,x\n", "not an NHSuite export"), ("group,name,cidr\nA,b,10.0.0.300/8\n", "invalid CIDR")],
)
def test_load_nhsuite_csv_errors(tmp_path, content, message):
    path = tmp_path / "nh.csv"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(NetworkHierarchyError, match=message):
        load_from_nhsuite_csv(str(path))
