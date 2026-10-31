# 🚫 AssetSuite error reference

Errors are printed on the console and logged in `assetsuite.log` (or the `log_file` of the configuration). Use `-v` to also see each API call.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success (also a dry run that found invalid rows: they are listed, nothing is written) |
| `1` | QRadar or network error, or at least one write failed during `import --apply` / `restore --apply` |
| `2` | Configuration or usage error: nothing was sent to QRadar beyond reads |
| `3` | `report --fail-on`: findings at or above the given severity |

## Configuration errors (exit 2)

Shown as `Configuration error: ...`.

| Message | Cause and fix |
|---|---|
| `config.json does not exist` | The file given with `-c` is missing. Without `-c`, `config.json` is optional when `QRADAR_HOST` and `QRADAR_SEC_TOKEN` are set |
| `... is not valid JSON` | Syntax error (often a trailing comma). The position is in the message |
| `... must contain a JSON object` | The file holds a list or a value instead of `{ ... }` |
| `Unknown configuration key(s): ...` | Typo in a key. Accepted keys: see the README. NHSuite keys `ip_QRadar`, `auth`, `Version`, `Accept` are accepted |
| `'host' is required` | No `host` in the file nor `QRADAR_HOST` |
| `'token' is not set` | No token, or still `CHANGE_ME` from `config.example.json` |
| `'verify_ssl' must be true/false` / `'safety' ...` | Use `true`/`false` (or `on`/`off`, `"True"`/`"False"`) |
| `ssl_cert_path ... does not exist` | The CA file is missing while `verify_ssl` is true |
| `'timeout' and 'page_size' must be ...` | Numbers greater than zero |

## Connection and API errors (exit 1)

Shown as `ERROR: ...`. AssetSuite retries reads (GET) up to 3 times on 429, 502, 503 and 504; writes are never replayed automatically, so that a change is not applied twice.

| Message | Cause and fix |
|---|---|
| `Cannot reach HOST: ...` | DNS, routing, firewall or QRadar down. Check `host` and that port 443 answers |
| `TLS verification failed for HOST` | The certificate is not trusted: set `ssl_cert_path` to the PEM of the internal CA. Use the name the certificate was issued for (FQDN or IP) |
| `HTTP 401 ... - check the SEC token` | Token missing, revoked or mistyped. QRadar answers `No SEC header present in request` even when the token is only invalid |
| `HTTP 403 ...` | The authorized service's user role or security profile lacks a permission (Assets, Network Hierarchy, the domain) |
| `HTTP 404 ... - not found` | Unknown object (asset, saved search, bulk task), or endpoint missing from the `api_version` used |
| `HTTP 422 ... Version (X) from header parameter (Version) is not a valid version` | `api_version` not offered by this QRadar: run `check api` for the supported versions, or set it to `null` |
| `HTTP 429` | Rate limited. Bulk creations wait 10 s and retry 3 times |
| `HTTP 5xx` | QRadar-side error: see QRadar's own logs. Retried for reads |
| `Invalid JSON returned by ...` / `Expected a list from ...` | Unexpected answer (proxy, maintenance page). Retry with `-v` |
| `Cannot write FILE: ...` | Output folder not writable or disk full |

IBM's list of API error messages: https://www.ibm.com/docs/en/qradar-common?topic=versions-api-error-messages

Two API behaviours that AssetSuite handles internally, documented here for anyone calling the API directly:
- `POST /asset_model/assets/{id}`, `PATCH /asset_model/assets` and `DELETE /asset_model/assets/{id}` only answer in `text/plain`: with `Accept: application/json`, QRadar refuses them with **HTTP 406**.
- `GET /config/network_hierarchy/networks` refuses the `Range` header with **HTTP 422** (`paging is not supported`).

## Command usage errors (exit 2)

Shown as `Error: ...`.

| Message | Command | Fix |
|---|---|---|
| `Unknown domain 'X'. Known domains: ...` | export, import, report | Use an id or name from the list (`DEFAULT_DOMAIN` for 0) |
| `Unknown asset property: X (see the properties command)` | export, report | Property names are case-sensitive |
| `Invalid --cidr value` | export | e.g. `10.0.0.0/8`, `2001:db8::/32` |
| `--property expects NAME=VALUE` | export | `"Business Owner=SOC"`, or `"Business Owner="` for empty |
| `No asset saved search 'X'` / `Several saved searches are named 'X' (ids ...)` | export | Use the id shown by `saved-searches` |
| `Unknown check(s): X` / `No check left to run` | report | Check names are listed in `report --help` |
| `... is not an NHSuite export: missing ...` / `invalid CIDR` | report `--nh-file` | The file needs `group`, `name` and `cidr` columns, as written by NHSuite |
| `Cannot read backup ...` / `The backup was made on X, not on Y` | restore | A backup only restores on the QRadar it was taken from |
| `Cannot update assets: ...` / `Cannot delete assets: ...` | import, restore | The endpoint is missing from the API version used or the token may not call it: see `check api` |

## Import errors

### File errors (exit 2, nothing imported)

| Message | Fix |
|---|---|
| `... is empty or has no header line` | The first line must hold the column names |
| `Duplicate column(s) in ...` | Each column once |
| `Line N has more fields than the header` | A value contains the delimiter without quotes, or the delimiter was guessed wrong: use `--delimiter` |
| `... is not UTF-8 encoded` | Save as "CSV UTF-8" in Excel |
| `Unknown column(s): X` | Property columns must be named exactly as in `properties`; the computed export columns are accepted and ignored |
| `The file needs at least one of these columns to find assets` | Add `id`, an IP, MAC or hostname column |

### Row errors (listed in the plan and the report as `error`)

Invalid rows block `--apply`; `--skip-invalid` imports the valid rows only.

| Message | Fix |
|---|---|
| `asset id N does not exist` / `invalid asset id` | The asset was deleted or merged: export again |
| `asset N is in domain X, not Y` | The row's domain disagrees with the asset |
| `unknown domain_id` / `unknown domain_name` / `... do not match` | Fix the domain columns |
| `'X' must be a number` / `must be true or false` | Value of a NUMERIC or BOOLEAN property |
| `IP ... matches several assets (ids): add the id or domain column` | The key is ambiguous: give the asset id |
| `'X' of asset N is set to 'A' on line L` | Two rows give different values for the same asset |

### Creation errors

Checked before sending (row errors):
`an IP address is required`, `at most 2 IPs`, `invalid IP`, `IPv6 link-local ... not accepted`, `one MAC address`, `invalid MAC`, `one DNS name` / `one NETBIOS name`, `name longer than 255 characters`, `domain unknown: add a domain_id or domain_name column, or use --domain`, `IP X is already created by line N`.

Assets not found and not created (rows saved to `exports/assets-not-found-*.csv`):
- `not created, use --allow-create ...`
- `not created, POST /asset_model/assets ... exists in API 24.0 -> ..., API X is used` or `is not offered by this QRadar` (see `check api`).

Returned by QRadar (report status `failed`, with the QRadar code):

| Code | Meaning |
|---|---|
| 1001 | No domain with this name (single create) |
| 1002 | Hostname longer than 255 characters (single create); list too large (bulk, split and retried automatically) |
| 1003-1004 | Hostname type must be DNS or NETBIOS, once each |
| 1005-1006 | Product: at least one of name, vendor, version; only one product |
| 1007-1009 | Property name or value empty, or unknown property |
| 1010-1015 | Invalid IP or MAC, IPv6 link-local, empty field, more than one interface, more than two IPs |

### Skipped rows

`the asset has no IP address: QRadar refuses property updates on it (HTTP 422)`: the row matched (by MAC or hostname) an asset that has no IP left. QRadar checks permissions on the asset's domain and IP, and answers `Could not verify if the current user has permission to access domainid: [0], ipaddress: [] ... Could not get domainId or ipAddress for asset` to any property update. The row is listed as `skipped` and does not block the other rows; such assets are usually stale (see `report --checks stale`).

Report status `reconciled`: QRadar merged the row into an existing asset (its id is in the report) instead of creating one. Status `timeout`: the bulk task was still running after 10 minutes; check it later in QRadar.

## Restore messages

| Message | Meaning |
|---|---|
| `cannot empty X (no API to clear a property)` | The property was empty before the import: clear it in the QRadar console if needed |
| `Assets gone since the backup: ...` | Deleted or merged by QRadar since: nothing to restore |
| `Assets created by the import are kept (use --delete-created ...)` | Created assets stay unless asked |

## NetBox errors (`netbox-sync`, exit 2)

| Message | Fix |
|---|---|
| `NetBox is not configured` | Add the `netbox` section (see `config.example.json`) |
| `'netbox.token' is not set` | Put a read-only NetBox API token in `netbox.token` or `NETBOX_TOKEN` |
| `Unknown netbox setting(s)` | Typo in the `netbox` section |
| `netbox.mapping['X']: unknown NetBox field(s)` / `must be a field name, a list, or ...` | Fields and rule syntax: see the README |
| `Unknown asset propert(y/ies): X` | A mapping key is not a property of this QRadar (case-sensitive, see `properties`) |
| `NetBox refused the token (HTTP 401/403)` | Token wrong, expired or without read permission |
| `TLS verification failed for NetBox` | Set `netbox.ssl_cert_path`, or `netbox.verify_ssl: false` in a lab |
| `Cannot reach NetBox ...` | URL, DNS, firewall |

`TLS verification is disabled for NetBox` is a warning printed when `netbox.verify_ssl` is false.

## pfSense errors (`pfsense-sync`, exit 2)

| Message | Fix |
|---|---|
| `The defusedxml package is missing` | Run `pip install -r requirements.txt` with the Python that runs AssetSuite (the project `.venv`, or `python3 -m pip install --user -r requirements.txt`). Only `pfsense-sync` needs it |
| `No pfSense backup file found (private/*.xml)` | Export the DNS Resolver and DHCP Server backups into `private/`, or give `--file` |
| `pfSense backup file not found: X` | Path given with `--file` or `pfsense.files` |
| `... is not a pfSense backup of the DNS Resolver or DHCP Server (root <X>)` | Export the *DNS Resolver* or *DHCP Server* area, or a complete backup (`<pfsense>` root) |
| `... XML with a DOCTYPE or entities is refused` | Not a pfSense export: pfSense never writes them |
| `... is not a valid XML file` | Truncated download, or an encrypted backup: export again without encryption |
| `Unknown pfsense setting(s)` / `Invalid pfsense.networks value` / `'pfsense.overwrite' must be true or false` | Fix the `pfsense` section |
| `pfsense.mapping['X']: unknown field(s)` | Fields: see the README |

## SevOne errors (`sevone-sync`, exit 2)

| Message | Fix |
|---|---|
| `SevOne is not configured` | Add the `sevone` section (see `config.example.json`) |
| `'sevone.token' is not set ... or a service account` | Put an API key in `sevone.token` / `SEVONE_TOKEN`, or a service account in `sevone.username` / `sevone.password` |
| `'sevone.username' and 'sevone.password' go together` | Set both, or neither |
| `SevOne refused the service account (HTTP 401)` | Wrong user name or password, or account disabled |
| `SevOne refused the service account session (HTTP 403)` | The account cannot read the devices: give it a read-only role on the device groups |
| `SevOne refused the API key (HTTP 401/403)` | Key wrong, deleted, expired, or replaced: a new key for the same application invalidates the previous one. Create one key with an expiration date (`POST /api/v2/users/api-keys`), or use a service account |
| `Unknown sevone setting(s)` / `'sevone.overwrite' must be true or false` / `'sevone.device_groups' must be a list ...` | Fix the `sevone` section |
| `sevone.mapping['X']: unknown field(s)` | Fields: see the README, or `md:<Namespace.Attribute>` for another metadata attribute |
| `Unknown SevOne device group(s): X` | Name, path (`All Device Groups/...`) or id of a SevOne device group |
| `Unknown asset propert(y/ies): X` | A mapping key is not a property of this QRadar (case-sensitive, see `properties`) |
| `TLS verification failed for SevOne` | Set `sevone.ssl_cert_path`, or `sevone.verify_ssl: false` in a lab (SevOne ships a self-signed certificate) |
| `Cannot reach SevOne ...` | URL, DNS, firewall |
| `HTTP 4xx/5xx from SevOne on ...` | The SevOne API answered with an error: check the SevOne version (tested on 7.2) |

`TLS verification is disabled for SevOne` is a warning printed when `sevone.verify_ssl` is false. `left aside: X: polled on 127.0.0.1` lists the devices that are not hosts (HTTP or DNS probes, SevOne itself) or are deleted in SevOne.

## Report warnings

| Message | Meaning |
|---|---|
| `Catch-all group 'X' is not in the Network Hierarchy` | Typo in `--catch-all-group`: no IP will be flagged for it |
| `No owner property on this QRadar: no-owner check skipped` | Neither `Business Owner` nor `Technical Owner` exists: use `--owner-property` |
