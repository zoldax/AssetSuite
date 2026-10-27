# 🛠️AssetSuite 🛠 for IBM QRadar SIEM

[![License](https://img.shields.io/github/license/zoldax/AssetSuite?color=44CC11)](LICENSE) [![Commit](https://img.shields.io/github/commit-activity/t/zoldax/AssetSuite)](https://github.com/zoldax/AssetSuite/commits/) [![Views](https://hits.sh/github.com/zoldax/AssetSuite.svg)](https://hits.sh/github.com/zoldax/AssetSuite/) [![Last commit](https://img.shields.io/github/last-commit/zoldax/AssetSuite/main)](https://github.com/zoldax/AssetSuite/commits/main) [![CI](https://github.com/zoldax/AssetSuite/actions/workflows/ci.yml/badge.svg)](https://github.com/zoldax/AssetSuite/actions/workflows/ci.yml) ![Python](https://img.shields.io/badge/python-3.9%20%7C%203.12-blue)

AssetSuite helps manage the IBM QRadar asset model from the command line: export assets, update their properties in bulk from CSV, report on asset data quality, and cross-check assets against the Network Hierarchy managed with [NHSuite](https://github.com/zoldax/NHSuite).

> **Status: v0.7.2.** Connection and API capability checks, property and saved search listing, asset export to CSV/JSON, import (property updates and creation of missing assets) with dry run, safety backup and restore, NetBox IPAM and pfSense DNS/DHCP synchronization, data quality report cross-checked with the Network Hierarchy, unit and live test suites.

> ⚠️ **Before we go further: AssetSuite is NOT meant to be installed on a QRadar console or any QRadar appliance.** It runs from an admin workstation or a small Linux VM and only talks to QRadar through the REST API. Installing it, or its Python packages, on QRadar is unsupported by IBM and can break QRadar components. [Details below](#-installation).

---

## 📌 Details
- **Name**: AssetSuite.py
- **Author**: Pascal Weber (zoldax) / Abakus Sécurité
- **License**: Apache 2.0
- **Python**: 3.9 or later

## 📦 Installation

**Run AssetSuite from an admin workstation or a small Linux VM with Python 3.9 or later, not on the QRadar console.** AssetSuite only talks to the QRadar REST API (and to NetBox), like NHSuite, so it does not need to be on QRadar:
- the console's system Python (3.6 on QRadar 7.5/7.6, RHEL 8) is too old: AssetSuite needs 3.9+, and on 3.6 `requests` would be stuck at 2.27.1, without its later security fixes;
- installing packages into that Python can break QRadar components, is not supported by IBM, and may be undone by a QRadar upgrade.

The machine needs HTTPS access to the console (and to NetBox), the PEM of the internal CA if the certificates come from one, and the `config.json` holding the token. On RHEL 8/9: `sudo dnf install python3.11`, then create the virtual environment below with `python3.11 -m venv .venv`. On macOS, prefer a recent Python (e.g. Homebrew) to `/usr/bin/python3`, which is built with LibreSSL 2.8.3 (urllib3 `NotOpenSSLWarning`, no TLS 1.3).

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config.example.json config.json   # then edit config.json
```

Run AssetSuite with the Python where the requirements are installed: `source .venv/bin/activate` first, or `.venv/bin/python AssetSuite.py ...`. With another Python (e.g. the macOS `/usr/bin/python3`), install them there: `python3 -m pip install --user -r requirements.txt`.

## 🛠️ Usage

```bash
python3 AssetSuite.py --help
python3 AssetSuite.py check version    # QRadar release (was NHSuite --check-version)
python3 AssetSuite.py check domains    # domains (was NHSuite --check-domain)
python3 AssetSuite.py check api        # API versions and asset capabilities of this QRadar
python3 AssetSuite.py properties       # asset property types (id, name, type)
python3 AssetSuite.py saved-searches   # asset saved searches and their filters
python3 AssetSuite.py export [options] # export assets to CSV or JSON
python3 AssetSuite.py import FILE      # update asset properties / create missing assets (dry run by default)
python3 AssetSuite.py restore BACKUP   # put back the values saved before an import (dry run by default)
python3 AssetSuite.py netbox-sync      # update / create assets from the NetBox IPAM (dry run by default)
python3 AssetSuite.py pfsense-sync     # name assets from pfSense DNS overrides and static DHCP mappings (dry run by default)
python3 AssetSuite.py report           # data quality report, cross-checked with the Network Hierarchy
```

Global options: `-c/--config FILE` (default `config.json`), `-v/--verbose` (debug messages on the console).

Exit codes: `0` success, `1` QRadar/API error, `2` configuration or usage error, `3` findings at or above `report --fail-on`.

### `check api`

Different QRadar releases expose different asset endpoints. In particular, **creating and deleting assets are recent API features** (create from API 24.0, delete from 26.0, bulk from 29.0). `check api` reads `/api/help/versions` and `/api/help/endpoints` and reports what the target QRadar can actually do with the API version in use, and whether the token is allowed to:

```
Capabilities with API 29.0:
  Read assets .................. yes
  Update asset properties ...... yes
  Create missing assets ........ yes
  Delete assets ................ yes
  Bulk create/delete (async) ... yes
```

AssetSuite never assumes a capability from a version number: the import commands rely on this detection, and report missing assets instead of creating them when the endpoint is not available.

### `export`

```bash
# All assets, one row per asset, all property columns (default file: exports/assets-HOST-TIMESTAMP.csv)
python3 AssetSuite.py export

# One row per IP for a network, a few properties, French Excel delimiter
python3 AssetSuite.py export --per-ip --cidr 10.0.0.0/8 --properties "Given Name,Business Owner" --delimiter ";" -o lan.csv

# Stale assets (not seen for 30 days, or never) of a domain
python3 AssetSuite.py export --domain PROD1 --not-seen-for 30 -o stale.csv

# Assets without a business owner
python3 AssetSuite.py export --property "Business Owner=" -o no-owner.csv

# Assets returned by an asset saved search, as raw JSON
python3 AssetSuite.py export --saved-search "Windows Assets" -o windows.json
```

| Option | Description |
|---|---|
| `-o FILE` | Output file. `.json` selects JSON. Default `exports/assets-HOST-TIMESTAMP.csv` |
| `-f csv\|json` | Output format |
| `--per-ip` | CSV: one row per IP (columns `ip_address`, `ip_type`, `network_id`, `mac_address`); an asset without IP keeps one row |
| `--properties NAMES` | CSV: property columns, comma-separated (default all, `""` for none) |
| `--delimiter C` | CSV delimiter (`,` by default, `;` for a French Excel, `tab`) |
| `--domain ID\|NAME` | Only this domain (filtered by QRadar) |
| `--saved-search ID\|NAME` | Only the assets returned by this asset saved search |
| `--cidr CIDR` | Only assets with an IP in this network, IPv4 or IPv6 (repeatable) |
| `--seen-within DAYS` | Only assets seen in the last DAYS days |
| `--not-seen-for DAYS` | Only assets not seen for DAYS days, including never seen |
| `--property NAME=VALUE` | Only assets whose property equals VALUE; `NAME=` for an empty or missing property (repeatable) |

Filters combine with AND.

**CSV columns**: `id`, `domain_id`, `domain_name`, `ip_addresses`, `mac_addresses`, `dns_names`, `netbios_names`, `users`, `products`, `vulnerability_count`, `risk_score_sum`, `first_seen`, `last_seen`, then one column per asset property, named as in `properties`. Multiple values are separated by `;`. Dates are ISO 8601 in UTC; `last_seen` is the latest passive or scanner sighting of an interface, IP or hostname.

**JSON** keeps the assets exactly as returned by QRadar (all fields and timestamps): use it as a backup.

**Security**: hostnames and user names come from the network. A CSV cell starting with `=`, `+`, `@` or a non-numeric `-` is prefixed with `'` so that a spreadsheet does not run it as a formula. Exports contain inventory data: the `exports/` folder is excluded from git.

### `import`

Imports a CSV in the export format, so the usual workflow is: export, edit in a spreadsheet, import back.

```bash
python3 AssetSuite.py import owners.csv                    # dry run: shows what would change, writes nothing
python3 AssetSuite.py import owners.csv --apply            # updates the properties of existing assets
python3 AssetSuite.py import new.csv --allow-create --apply  # also creates the assets QRadar does not know
```

**Nothing is written without `--apply`.** The dry run prints the plan and writes a report (`exports/import-report-HOST-TIMESTAMP.csv`) with one line per row: `update`, `create`, `unchanged`, `not_found` or `error`.

**Columns**
- At least one column to find the asset: `id`, `ip_address` / `ip_addresses`, `mac_address` / `mac_addresses`, `dns_names`, `netbios_names`.
- Optional `domain_id` or `domain_name` (`DEFAULT_DOMAIN` for domain 0); `--domain` sets it for rows without one.
- One column per property to set, named exactly as in the `properties` command. **An empty cell leaves the property unchanged** (the API cannot empty a property).
- The computed export columns (`users`, `products`, `last_seen`, ...) are accepted and ignored. Any other column is refused, so that a typo in a property name is not silently skipped.
- UTF-8 with or without BOM; `,`, `;` or tab delimiter, guessed from the header. Cells escaped by the export (`'=...`) are restored.

**Matching**: by `id`, else IP, else MAC, else DNS name, else NETBIOS name, within the row's domain when known. A row that matches an asset **without any IP** is `skipped`: QRadar refuses property updates on such assets (HTTP 422). A row matching several assets is an error (add the `id` or the domain). Only the properties whose value differs from QRadar are sent, so importing an unmodified export changes nothing.

**Assets QRadar does not know**
- Without `--allow-create`, or when `check api` reports that this QRadar cannot create assets, they are listed and saved to `exports/assets-not-found-HOST-TIMESTAMP.csv` (same columns as the input), to import later.
- With `--allow-create`: bulk creation (`PATCH`, asynchronous, polled every 5 s) on API 29.0+, one `POST` per asset on API 24.0 to 28.x. The API limits a new asset to one interface (one MAC), at most two IPs, one DNS and one NETBIOS name; an IP is required. These limits are checked before sending.
- QRadar may **reconcile** a new asset with an existing one instead of creating it: the report shows `reconciled` with the asset id.
- The maximum size of a bulk request is not documented: a request refused as too large is split in two and sent again (`--bulk-size` sets the initial size, 100 by default).

**Safety**
- Invalid rows block `--apply`: fix them, or add `--skip-invalid` to import the valid rows only.
- With `safety` on (default), the updated assets are saved to `safety/backup-before-import-HOST-TIMESTAMP.json` before any write, and the ids of the created assets are added to it. The import stops if the backup cannot be written.
- Property updates are **asynchronous** in QRadar (accepted, then applied by the asset profiler): run the same import again without `--apply` a few minutes later to check that nothing is left to change.

### `restore`

```bash
python3 AssetSuite.py restore safety/backup-before-import-HOST-TIMESTAMP.json                    # dry run
python3 AssetSuite.py restore safety/backup-before-import-HOST-TIMESTAMP.json --apply
python3 AssetSuite.py restore safety/backup-before-import-HOST-TIMESTAMP.json --delete-created --apply
```

Puts back the property values saved in the backup. A property that was empty before the import cannot be emptied again (no API for it): it is reported. `--delete-created` also deletes the assets created by the import (API 26.0+). A backup is only restored on the QRadar it was made on.

### `report`

Checks the asset data and cross-checks it with the Network Hierarchy (NH), read from QRadar or from a CSV exported by [NHSuite](https://github.com/zoldax/NHSuite).

```bash
python3 AssetSuite.py report                                    # all checks, findings in exports/report-HOST-TIMESTAMP.csv
python3 AssetSuite.py report --catch-all-group Z_CatchAll       # flag IPs only covered by catch-all networks
python3 AssetSuite.py report --nh-file planned-nh.csv           # check the assets against a planned NH before importing it with NHSuite
python3 AssetSuite.py report --checks duplicate-ip,outside-nh --fail-on high   # for a scheduled CI job
```

| Check | Severity | Finding |
|---|---|---|
| `duplicate-ip` | high | IP held by several assets of the same domain |
| `nh-domain-mismatch` | high | IP in an NH network of another domain |
| `duplicate-mac` | medium | MAC held by several assets of the same domain |
| `duplicate-hostname` | medium | DNS name held by several assets of the same domain |
| `outside-nh` | medium | IP in no NH network |
| `stale` | medium | Asset not seen for `--stale-days` (30 by default), or never seen |
| `nh-catch-all` | low | IP only classified by a `--catch-all-group` group (or one of its sub-groups) |
| `nh-network-changed` | low | IP recorded in another network than the current NH gives (NH changed since the asset was profiled) |
| `unnamed` | low | No Given Name and no hostname |
| `no-owner` | low | All owner properties empty (`--owner-property`, default `Business Owner` and `Technical Owner`) |
| `empty-network` | info | NH network without any asset (catch-all groups excluded) |
| `vulnerable` | info | Asset with vulnerabilities or a risk score |

The console shows a summary and the first findings of each check (`-v` for all); the file holds every finding with `severity`, `check`, `asset_id`, `domain_id`, `target` (IP, MAC, hostname or CIDR), `names` and `detail`. `--checks` / `--skip` select the checks, `--no-nh` skips the NH ones, `--domain` restricts to one domain, `-o report.json` writes JSON with the options and the summary.

The NH is matched by longest prefix, so a /32 entry wins over its /24. Which groups are catch-all depends on each NH, hence `--catch-all-group` instead of a guess.

### `netbox-sync`

Reads the IP addresses of the NetBox IPAM, with the device or virtual machine each one is assigned to, turns them into import rows (one per IP) with the property mapping of the `netbox` section of the configuration, and runs them through the import: same dry run, `--apply`, `--allow-create`, safety backup, report and `restore`.

```bash
python3 AssetSuite.py netbox-sync                              # dry run: what NetBox would change in QRadar
python3 AssetSuite.py netbox-sync --save-csv netbox.csv        # also keep the generated rows (to review, edit, import later)
python3 AssetSuite.py netbox-sync --apply                      # update the properties of the matching assets
python3 AssetSuite.py netbox-sync --fill-empty-only --apply    # only fill empty properties, never overwrite QRadar
python3 AssetSuite.py netbox-sync --allow-create --apply       # also create the assets QRadar does not know
```

**Configuration** (`netbox` section of `config.json`, see `config.example.json`): `url`, `token` (a **read-only** NetBox API token; `NETBOX_TOKEN` overrides it), `verify_ssl` / `ssl_cert_path`, `domain` (QRadar domain of the NetBox addresses, `DEFAULT_DOMAIN` by default, `--domain` overrides it), `statuses` (NetBox IP statuses to take, `["active"]` by default) and `mapping`.

**Mapping**: QRadar property -> NetBox fields. `{"first": [...]}` takes the first non-empty field, `{"join": [...], "separator": " / "}` joins all the non-empty ones; a field name or a list are shorthands for `first`.

| Default QRadar property | NetBox |
|---|---|
| `Given Name` | device / VM name, else the IP's DNS name |
| `Description` | IP description, else device / VM description |
| `Location` | site / location / rack |
| `Asset Type` | device role, VM role, or `Virtual machine` |
| `Business Owner` | tenant |
| `User Supplied OS` | platform |

NetBox fields available: `ip`, `dns_name`, `ip_description`, `object_type`, `object_name`, `object_description`, `description`, `role`, `site`, `location`, `rack`, `cluster`, `tenant`, `platform`, `serial`, `asset_tag`, `status`, `tags`, and `cf_<name>` for a custom field of the IP or of its device / VM (e.g. map `serial` to a custom QRadar asset property). A NetBox `dns_name` of `-` counts as empty.

Notes:
- NetBox is the reference for the mapped properties: a different value in QRadar is replaced, unless `--fill-empty-only`.
- An IP held by several QRadar assets is resolved with the row's MAC, then its DNS names in order (full or short name); this applies to every import.
- Properties that were empty before cannot be emptied again by `restore` (no API for it): review the dry run first.
- `User Supplied OS` can influence how QRadar relates vulnerabilities to the asset: remove it from the mapping if you do not want NetBox to set it.

### `pfsense-sync`

Reads pfSense configuration backups **offline** (nothing to install on the firewall): the DNS Resolver host overrides and the static DHCP mappings, merged into one import row per IP, then runs them through the import (dry run, `--apply`, `--allow-create`, backup, report, `restore`). **pfSense only fills empty properties** unless `--overwrite` (or `pfsense.overwrite: true`), so it completes NetBox without contradicting it.

```bash
python3 AssetSuite.py pfsense-sync                         # dry run on private/*.xml
python3 AssetSuite.py pfsense-sync --file backup.xml       # another backup (repeatable)
python3 AssetSuite.py pfsense-sync --apply                 # fill the empty properties of the matching assets
```

**Export from pfSense**: Diagnostics > Backup & Restore, *Backup area* = **DNS Resolver**, download, then again with **DHCP Server** (a complete backup works too), without encryption, into the `private/` folder. Only the host overrides and static mappings are read; the rest of the file (passwords, DDNS keys) is ignored. `private/` and `*.xml` are excluded from git. Files with a DOCTYPE or XML entities are refused, and parsing uses `defusedxml`.

**Configuration** (`pfsense` section, all optional): `files` (default `private/*.xml`), `domain` (QRadar domain, `DEFAULT_DOMAIN`), `dns_domain` (domain appended to DHCP hostnames that have none), `networks` (only these CIDRs, e.g. to leave out DNS entries of other sites), `overwrite`, `mapping`.

| Default QRadar property | pfSense |
|---|---|
| `Given Name` | first host override name of the IP (`host.domain`), else DHCP hostname + `dns_domain` |
| `Description` | host override description, else static mapping description |
| `Asset Type` | category of the description when it follows `CATEGORY - text` (`NAS - DS212` -> `NAS`) |

Fields available for the mapping: `ip`, `dns_name`, `host`, `mac`, `dns_description`, `dhcp_description`, `description`, `category`, `interface`, `source`. The MAC of the static mapping is used to match assets and for creations; aliases and extra host overrides of the same IP are not used (QRadar takes one DNS name per new asset). QRadar's API cannot change the hostnames of an existing asset: pfSense names go to `Given Name`, matching and creations.

Matching ties (an IP held by several assets) are broken by the row's MAC first, then by its names in order: the asset that carries the pfSense MAC is the physical device, even when another asset carries the DNS name.

## 🛠 Configuration: `config.json`

| Key | Default | Description |
|---|---|---|
| `host` | (required) | QRadar console FQDN or IP |
| `token` | (required) | Authorized service SEC token. Prefer the `QRADAR_SEC_TOKEN` environment variable |
| `api_version` | `null` | API version sent in the `Version` header. `null` uses the latest version offered by QRadar |
| `verify_ssl` | `true` | Verify the QRadar TLS certificate. Disable only in a lab |
| `ssl_cert_path` | `null` | PEM CA bundle (internal PKI) used when `verify_ssl` is `true` |
| `safety` | `true` | Back up the assets to `safety/` before an import writes to QRadar |
| `timeout` | `30` | HTTP timeout in seconds |
| `page_size` | `500` | Items per page when listing (QRadar `Range` header) |
| `log_file` | `assetsuite.log` | Log file |

Environment variables override the file: `QRADAR_HOST`, `QRADAR_SEC_TOKEN`, `QRADAR_API_VERSION`, `QRADAR_SSL_CERT_PATH`.

An NHSuite `config.txt` can be reused as is: `ip_QRadar`, `auth` and `Version` are accepted as aliases of `host`, `token` and `api_version`.

`config.json` is listed in `.gitignore`: **never commit a token.**

## 🔐 Required QRadar permissions

Create an authorized service with a security profile covering the domains to manage and a user role with the **Assets** permission (and **Vulnerability Management** for the vulnerability counts in the reports).

## 🧪 Tests

```bash
pip install -r requirements-dev.txt
pytest                                     # 214 unit tests, QRadar and NetBox APIs mocked
ASSETSUITE_LIVE=1 pytest tests/live        # 18 read-only tests against the QRadar (NetBox, pfSense backups) of config.json
ASSETSUITE_LIVE=1 ASSETSUITE_LIVE_WRITE=1 pytest tests/live   # + a write test on a temporary asset
ruff check .                               # lint
```

The live suite reproduces the NHSuite-testing approach (wrong token, unknown host, missing CA, unsupported API version...) and checks every command on a real QRadar. The write test only creates, updates and deletes its own temporary asset (IP `192.0.2.250`). Details, coverage and last results: [docs/TESTING.md](docs/TESTING.md).

GitHub Actions and GitLab CI run lint and unit tests (Python 3.9 and 3.12) on every push. GitLab CI adds secret detection and a manual `live-tests` job when the QRadar CI/CD variables are set.

## 🚫 Errors

Exit codes, error messages, their causes and fixes: [README-ERROR.md](README-ERROR.md). Errors are logged in `assetsuite.log`; `-v` also shows each API call.

## 📜 Disclaimer

All content is without warranty of any kind. Use at your own risk. Always test changes in a lab before production, and keep backups.

QRadar and IBM are trademarks or registered trademarks of International Business Machines Corp. All other trademarks are the property of their respective owners.
