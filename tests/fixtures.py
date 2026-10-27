"""Asset payloads shaped like QRadar 7.6.0 FP1 responses (values anonymized)."""

from datetime import datetime, timezone

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)
DAY_MS = 86_400_000
NOW_MS = int(NOW.timestamp() * 1000)

PROPERTIES = [
    {"id": 1001, "name": "Given Name", "data_type": "TEXT", "custom": False, "display": True, "state": 0},
    {"id": 1002, "name": "Unified Name", "data_type": "TEXT", "custom": False, "display": True, "state": 0},
    {"id": 1005, "name": "Business Owner", "data_type": "TEXT", "custom": False, "display": True, "state": 0},
    {"id": 1000000000, "name": "MVS Status", "data_type": "TEXT", "custom": True, "display": True, "state": 0},
]

DOMAINS = [{"id": 0, "name": ""}, {"id": 1, "name": "PROD1"}, {"id": 2, "name": "PROD2"}]


def prop(type_id, name, value):
    return {"type_id": type_id, "name": name, "value": value, "id": type_id * 10, "last_reported": NOW_MS}


# Seen 2 days ago, one interface, one IPv4, DNS + NETBIOS names, two users.
WORKSTATION = {
    "id": 2723,
    "domain_id": 0,
    "vulnerability_count": 0,
    "risk_score_sum": 0.0,
    "interfaces": [
        {
            "id": 2427,
            "mac_address": "02:00:00:00:9b:6e",
            "created": NOW_MS - 400 * DAY_MS,
            "last_seen_profiler": NOW_MS - 2 * DAY_MS,
            "last_seen_scanner": None,
            "ip_addresses": [
                {
                    "id": 2563,
                    "value": "192.0.2.143",
                    "type": "IPV4",
                    "network_id": 254,
                    "created": NOW_MS - 400 * DAY_MS,
                    "last_seen_profiler": NOW_MS - 2 * DAY_MS,
                }
            ],
        }
    ],
    "hostnames": [
        {"name": "ws01.example.lan", "type": "DNS", "last_seen_profiler": NOW_MS - 3 * DAY_MS},
        {"name": "-", "type": "NETBIOS", "last_seen_profiler": NOW_MS - 5 * DAY_MS},
    ],
    "users": [{"username": "admin"}, {"username": "=cmd|' /C calc'!A0"}],
    "products": [],
    "properties": [prop(1002, "Unified Name", "ws01.example.lan"), prop(1005, "Business Owner", "SOC")],
}

# Seen 60 days ago, two interfaces, IPv4 + IPv6, in domain PROD1, no owner.
SERVER = {
    "id": 3001,
    "domain_id": 1,
    "vulnerability_count": 4,
    "risk_score_sum": 12.5,
    "interfaces": [
        {
            "mac_address": "00:14:22:01:23:44",
            "created": NOW_MS - 900 * DAY_MS,
            "ip_addresses": [
                {"value": "10.1.1.24", "type": "IPV4", "network_id": 7, "last_seen_scanner": NOW_MS - 60 * DAY_MS},
                {"value": "2001:db8::24", "type": "IPV6", "network_id": 8},
            ],
        },
        {"mac_address": "00:14:22:01:23:45", "ip_addresses": [{"value": "10.2.0.5", "type": "IPV4", "network_id": 9}]},
    ],
    "hostnames": [{"name": "srv-db01", "type": "NETBIOS"}],
    "users": [],
    "products": [{"vendor": "Microsoft", "name": "Windows Server", "version": "2022"}],
    "properties": [prop(1001, "Given Name", "SRV-DB01")],
}

# Known by hostname only, never seen with an IP.
HOSTNAME_ONLY = {
    "id": 2757,
    "domain_id": 0,
    "vulnerability_count": 0,
    "risk_score_sum": 0.0,
    "interfaces": [],
    "hostnames": [{"name": "gitlab", "type": "DNS"}],
    "users": [{"username": "git"}],
    "properties": [],
}

ASSETS = [WORKSTATION, SERVER, HOSTNAME_ONLY]
