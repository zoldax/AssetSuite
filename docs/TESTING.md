# AssetSuite tests

Two suites, both run with pytest:

| Suite | Where | QRadar needed | Runs by default |
|---|---|---|---|
| Unit tests | `tests/` | no, the QRadar API is mocked with `responses` | yes (and in GitLab CI) |
| Live tests | `tests/live/` | yes | no: `ASSETSUITE_LIVE=1` |

```bash
pip install -r requirements-dev.txt
pytest                                              # unit tests; live tests are reported as skipped
ASSETSUITE_LIVE=1 pytest tests/live                 # read-only live tests
ASSETSUITE_LIVE=1 ASSETSUITE_LIVE_WRITE=1 pytest tests/live   # + the write test
```

## Unit tests (214)

The mocked responses follow what QRadar 7.6.0 FP1 returns (shapes checked on the lab), with anonymized values (RFC 5737 IPs, `example.lan` names).

| File | Tests | Covers |
|---|---|---|
| `test_config.py` | 17 | JSON config, NHSuite keys, environment overrides, TLS verification rules (including the NHSuite case where `verify_ssl: true` without CA disabled verification), validation errors, token kept out of `repr` |
| `test_client.py` | 10 | Headers, `Range` pagination with and without `Content-Range`, a server ignoring `Range`, QRadar error messages and hints, network errors |
| `test_capabilities.py` | 10 | API versions and asset endpoints from `/help`, features per pinned API version (create 24.0+, bulk 29.0+), `caller_has_access`, removed versions, `ILIKE` fallback |
| `test_assets.py` | 18 | Timestamps, CIDR / seen / property filters, export rows (per asset, per IP), saved search lookup, `id IN` chunks |
| `test_export.py` | 13 | CSV formula escaping, CSV and JSON writers, default paths |
| `test_importer.py` | 49 | CSV reading (BOM, delimiters, unescaping), import template (plans without errors, documentation values only), column checks, matching order and ambiguity, tie-break by MAC then DNS / NETBIOS names in order, `--fill-empty-only`, assets without IP skipped, numeric comparison, per-IP rows merged, conflicting rows, creation limits, single and bulk payloads |
| `test_writer.py` | 10 | Updates, single create (201 / 200 reconciled / errors), bulk task polling, split on "too large", 429 retry, timeout, `Accept: text/plain` on update / PATCH / DELETE, backup and restore planning, deletes |
| `test_quality.py` | 8 | Duplicates per domain, stale, unnamed, owners, vulnerable, ordering |
| `test_network_hierarchy.py` | 9 |
| `test_pfsense.py` | 25 | Partial (`<unbound>`, `<dhcpd>`) and complete (`<pfsense>`) backups, DNS and DHCP merged by IP, names and domains, MAC-only reservations, networks filter, `CATEGORY - text` descriptions, DOCTYPE / invalid / foreign files refused, clear error without `defusedxml`, config errors, rows; anonymized XML fixtures in `tests/fixtures/` |
| `test_netbox.py` | 17 | NetBox config and mapping rules, records from IPs / devices / VMs, `-` as empty DNS name, pagination through `next`, Token / Bearer, errors, only assigned devices and VMs fetched | Longest-prefix lookup, outside NH, domain mismatch, `network_id` change, catch-all groups and sub-groups, empty networks, API without `Range`, NHSuite CSV |
| `test_cli.py` | 30 | Every command end to end on a mocked API: exit codes, dry run sends no write, backup before apply, invalid rows block apply, restore, report files and `--fail-on` |

Bugs these tests caught during development: two infinite pagination loops in mocks that returned a full page without `Content-Range` (fixed in the client: a page larger than requested ends the listing), a report crash on a QRadar without `Technical Owner`, wrong expectations on CSV escaping.

## Live tests

The QRadar comes from `config.json`, the file in `ASSETSUITE_CONFIG`, or the `QRADAR_HOST` / `QRADAR_SEC_TOKEN` / `QRADAR_SSL_CERT_PATH` variables. Each test runs in a temporary directory: exports, reports, backups and logs never land in the project. The variant configurations of the error tests never contain the token, which goes through `QRADAR_SEC_TOKEN`.

### Read-only (18 tests, `test_live_read.py`)

Nothing is written to QRadar.

| Test | Checks |
|---|---|
| `test_check_version`, `test_check_domains`, `test_check_api` | The three `check` commands |
| `test_wrong_token` | Invalid token: exit 1, `HTTP 401` with the token hint |
| `test_unknown_host` | Unresolvable host: exit 1, `Cannot reach` |
| `test_missing_ca_file` | Missing `ssl_cert_path`: exit 2 before any call |
| `test_tls_without_internal_ca` | Internal certificate without its CA: exit 1, `TLS verification failed` (skipped if the QRadar does not use a custom CA) |
| `test_unsupported_api_version` | `api_version` 99.0: exit 1, HTTP 422 |
| `test_capabilities_follow_pinned_api_version` | API 24.0 can create but not bulk, 20.0 cannot create |
| `test_properties`, `test_saved_searches` | Listings |
| `test_export_csv_has_every_asset` | The CSV holds exactly the assets of the API |
| `test_export_json_and_per_ip` | JSON count, one row per IP (or one per asset without IP) |
| `test_export_import_round_trip_changes_nothing` | Export then import as a dry run: every row `unchanged`, no backup written |
| `test_report` | Report file and `--fail-on` exit code |
| `test_report_nhsuite_file_matches_api` | The NH read from an NHSuite CSV gives the same findings as the NH read from QRadar |
| `test_netbox_sync_dry_run` | `netbox-sync` dry run against the NetBox of the config (skipped without a `netbox` section) |
| `test_pfsense_sync_dry_run` | `pfsense-sync` dry run on the backups of `private/` (skipped without them) |

### Write (1 test, `test_live_write.py`)

Needs `ASSETSUITE_LIVE_WRITE=1` in addition. It only touches a temporary asset with an IP of the RFC 5737 documentation range (`192.0.2.250`, or `ASSETSUITE_LIVE_TEST_IP`), and no existing asset:

1. Stops if the test IP is already used by an asset.
2. `import --allow-create --apply`: creates the asset with `Business Owner = AssetSuite live A`; stops without deleting anything if QRadar reconciled it with an existing asset.
3. `import --apply`: sets `Business Owner = AssetSuite live B`, waits until QRadar shows it.
4. `restore --apply` of the update backup: back to A.
5. `restore --delete-created --apply` of the creation backup: the asset is deleted.
6. Whatever fails, the test asset is deleted at the end.

### Last run

2026-10-27, lab QRadar (7.6.0 FP1, API 29.0, about 85 assets):

| Suite | Result | Duration |
|---|---|---|
| Unit | 160 passed | 0.8 s |
| Live read-only | 16 passed | 16 s |
| Live write | 1 passed, test asset deleted, 84 assets after the run | 42 s |

## In GitLab CI

`lint`, `unit-tests` (Python 3.9 and 3.12) and secret detection run on every push. The `live-tests` job is manual and only exists when the `QRADAR_SEC_TOKEN` CI/CD variable is defined; it needs a runner that can reach the QRadar and these variables:

| Variable | Content |
|---|---|
| `QRADAR_HOST` | QRadar FQDN |
| `QRADAR_SEC_TOKEN` | Token of an authorized service, **masked and protected** |
| `QRADAR_SSL_CERT_PATH` | Variable of type *File* holding the PEM of the internal CA |

It runs the read-only live tests; the write test stays a manual run from a workstation.
