"""
Live write test: create, update, restore and delete one temporary asset.

Needs ASSETSUITE_LIVE=1 and ASSETSUITE_LIVE_WRITE=1. The asset uses an IP of
the RFC 5737 documentation range (ASSETSUITE_LIVE_TEST_IP, default
192.0.2.250) and no existing asset is modified. If QRadar reconciles the test
asset with an existing one instead of creating it, the test stops without
deleting anything.
"""

import glob
import json
import os

import pytest

from assetsuite.assets import fetch_assets, property_values
from assetsuite.cli import EXIT_OK
from assetsuite.client import QRadarAPIError
from tests.live.conftest import skip_unless_live_write, wait_for

pytestmark = [pytest.mark.live, pytest.mark.live_write, skip_unless_live_write]

TEST_IP = os.environ.get("ASSETSUITE_LIVE_TEST_IP", "192.0.2.250")
TEST_HOSTNAME = "assetsuite-live-test.example.lan"
OWNER = "Business Owner"


def assets_with_ip(client, ip):
    flt = f'interfaces contains ip_addresses contains value = "{ip}"'
    return client.get_all("asset_model/assets", params={"filter": flt, "fields": "id"})


def owner_of(client, asset_id):
    found = fetch_assets(client, asset_ids=[asset_id])
    return property_values(found[0]).get(OWNER) if found else None


def newest_backup(workdir):
    return json.loads(open(sorted(glob.glob(str(workdir / "safety" / "*.json")))[-1], encoding="utf-8").read())


def test_create_update_restore_delete(run, workdir, live_client):
    if assets_with_ip(live_client, TEST_IP):
        pytest.fail(f"{TEST_IP} is already used by an asset: set ASSETSUITE_LIVE_TEST_IP to a free address")

    (workdir / "create.csv").write_text(
        f"ip_addresses,dns_names,domain_name,{OWNER}\n{TEST_IP},{TEST_HOSTNAME},DEFAULT_DOMAIN,AssetSuite live A\n",
        encoding="utf-8",
    )
    code, out, err = run("import", "create.csv", "--allow-create", "--apply")
    assert code == EXIT_OK, out + err
    created = newest_backup(workdir)["created_asset_ids"]
    assert len(created) == 1, f"no asset created (reconciled with an existing one?): {out}"
    asset_id = created[0]
    os.rename(sorted(glob.glob(str(workdir / "safety" / "*.json")))[-1], workdir / "backup-create.json")

    try:
        assert wait_for(lambda: owner_of(live_client, asset_id) == "AssetSuite live A"), "created asset not visible"

        (workdir / "update.csv").write_text(f"id,{OWNER}\n{asset_id},AssetSuite live B\n", encoding="utf-8")
        code, out, err = run("import", "update.csv", "--apply")
        assert code == EXIT_OK, out + err
        assert "1 update submitted" in out
        assert wait_for(lambda: owner_of(live_client, asset_id) == "AssetSuite live B"), "update not applied"

        backup_update = sorted(glob.glob(str(workdir / "safety" / "*.json")))[-1]
        code, out, err = run("restore", backup_update, "--apply")
        assert code == EXIT_OK, out + err
        assert wait_for(lambda: owner_of(live_client, asset_id) == "AssetSuite live A"), "restore not applied"

        code, out, err = run("restore", str(workdir / "backup-create.json"), "--delete-created", "--apply")
        assert code == EXIT_OK, out + err
        assert wait_for(lambda: not assets_with_ip(live_client, TEST_IP)), "test asset not deleted"
    finally:
        # Never leave the test asset behind, whatever failed above.
        if fetch_assets(live_client, asset_ids=[asset_id]):
            try:
                live_client.request("DELETE", f"asset_model/assets/{asset_id}", headers={"Accept": "text/plain"})
            except QRadarAPIError:
                pass
