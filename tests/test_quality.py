import copy

from assetsuite.quality import CHECKS, ReportOptions, check_assets, severity_rank, sort_findings, summary
from tests.fixtures import HOSTNAME_ONLY, NOW, SERVER, WORKSTATION

ALL = set(CHECKS)


def options(**kwargs):
    return ReportOptions(now=NOW, **kwargs)


def by_check(findings, check):
    return [(f.asset_id, f.target, f.detail) for f in findings if f.check == check]


def clone(asset, asset_id, domain_id=None):
    copy_ = copy.deepcopy(asset)
    copy_["id"] = asset_id
    if domain_id is not None:
        copy_["domain_id"] = domain_id
    return copy_


def test_duplicate_ip_mac_hostname_in_same_domain():
    twin = clone(WORKSTATION, 9001)
    findings = check_assets([WORKSTATION, twin, SERVER], options(), ALL)
    assert by_check(findings, "duplicate-ip") == [
        (2723, "192.0.2.143", "also on asset(s) 9001"),
        (9001, "192.0.2.143", "also on asset(s) 2723"),
    ]
    assert {f[0] for f in by_check(findings, "duplicate-mac")} == {2723, 9001}
    assert by_check(findings, "duplicate-hostname")[0][1] == "ws01.example.lan"


def test_same_ip_in_other_domain_is_not_a_duplicate():
    findings = check_assets([WORKSTATION, clone(WORKSTATION, 9001, domain_id=2)], options(), ALL)
    assert not by_check(findings, "duplicate-ip")


def test_stale():
    findings = check_assets([WORKSTATION, SERVER, HOSTNAME_ONLY], options(stale_days=30), ALL)
    assert by_check(findings, "stale") == [
        (3001, "", "last seen 2026-08-28T12:00:00+00:00 (60 days ago)"),
        (2757, "", "never seen"),
    ]
    assert not by_check(check_assets([SERVER], options(stale_days=90), ALL), "stale")


def test_unnamed():
    nameless = clone(SERVER, 9002)
    nameless["hostnames"] = [{"name": "-", "type": "NETBIOS"}]
    nameless["properties"] = []
    findings = check_assets([nameless, SERVER], options(), ALL)
    assert by_check(findings, "unnamed") == [
        (9002, "10.1.1.24;2001:db8::24;10.2.0.5", "no Given Name, no DNS or NETBIOS name")
    ]


def test_no_owner_with_custom_properties():
    findings = check_assets([WORKSTATION, SERVER], options(), ALL)
    assert [f[0] for f in by_check(findings, "no-owner")] == [3001]
    findings = check_assets([WORKSTATION, SERVER], options(owner_properties=["MVS Status"]), ALL)
    assert [f[0] for f in by_check(findings, "no-owner")] == [2723, 3001]


def test_vulnerable():
    findings = check_assets([WORKSTATION, SERVER], options(), ALL)
    assert by_check(findings, "vulnerable") == [(3001, "", "4 vulnerabilities, risk score 12.5")]


def test_only_enabled_checks_run():
    findings = check_assets([WORKSTATION, SERVER, HOSTNAME_ONLY], options(), {"stale"})
    assert {f.check for f in findings} == {"stale"}


def test_sort_and_summary():
    findings = sort_findings(check_assets([WORKSTATION, clone(WORKSTATION, 9001), SERVER], options(), ALL))
    ranks = [severity_rank(f.severity) for f in findings]
    assert ranks == sorted(ranks)
    counts = summary(findings)
    assert counts["duplicate-ip"] == 2 and counts["outside-nh"] == 0
