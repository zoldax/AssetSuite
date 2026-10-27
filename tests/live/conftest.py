"""
Live test suite: runs AssetSuite against a real QRadar.

Skipped unless ASSETSUITE_LIVE=1. The QRadar comes from config.json (or the
file in ASSETSUITE_CONFIG, or the QRADAR_* environment variables). Tests that
write to QRadar also need ASSETSUITE_LIVE_WRITE=1 and only touch a temporary
asset they create and delete.

Every command runs in a temporary directory, so exports, reports, backups and
logs never land in the project. Configurations built for the error tests never
contain the token: it is passed through QRADAR_SEC_TOKEN.
"""

import json
import os
import time
from typing import Callable, List, Optional, Tuple

import pytest

from assetsuite.cli import main
from assetsuite.client import QRadarClient
from assetsuite.config import Config, ConfigError, load_config

LIVE = os.environ.get("ASSETSUITE_LIVE") == "1"
LIVE_WRITE = os.environ.get("ASSETSUITE_LIVE_WRITE") == "1"
CONFIG_PATH = os.path.abspath(os.environ.get("ASSETSUITE_CONFIG", "config.json"))

skip_unless_live = pytest.mark.skipif(not LIVE, reason="set ASSETSUITE_LIVE=1 to run against a real QRadar")
skip_unless_live_write = pytest.mark.skipif(
    not (LIVE and LIVE_WRITE), reason="set ASSETSUITE_LIVE=1 and ASSETSUITE_LIVE_WRITE=1 to test writes"
)


@pytest.fixture(scope="session")
def live_config() -> Config:
    try:
        return load_config(CONFIG_PATH if os.path.exists(CONFIG_PATH) else None)
    except ConfigError as e:
        pytest.skip(f"No usable QRadar configuration: {e}")


@pytest.fixture(scope="session")
def live_client(live_config: Config) -> QRadarClient:
    return QRadarClient(live_config)


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path


@pytest.fixture
def run(workdir, capsys) -> Callable[..., Tuple[int, str, str]]:
    """Run an AssetSuite command against the live QRadar: (exit code, stdout, stderr)."""
    config_args: List[str] = ["-c", CONFIG_PATH] if os.path.exists(CONFIG_PATH) else []

    def _run(*args: str) -> Tuple[int, str, str]:
        capsys.readouterr()
        code = main([*config_args, *args])
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return _run


@pytest.fixture
def run_with_config(workdir, capsys, monkeypatch, live_config):
    """Run a command with a variant of the live configuration (token from the environment only)."""

    def _run(*args: str, token: Optional[str] = None, **overrides) -> Tuple[int, str, str]:
        for name in ("QRADAR_HOST", "QRADAR_API_VERSION"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("QRADAR_SEC_TOKEN", token or live_config.token)
        data = {
            "host": live_config.host,
            "api_version": live_config.api_version,
            "verify_ssl": live_config.verify_ssl,
            "ssl_cert_path": live_config.ssl_cert_path,
            "timeout": 20,
        }
        data.update(overrides)
        path = workdir / "variant.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        capsys.readouterr()
        code = main(["-c", str(path), *args])
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return _run


def wait_for(condition: Callable[[], bool], timeout: float = 300, interval: float = 10) -> bool:
    """Poll until condition() is true: QRadar applies asset writes asynchronously."""
    deadline = time.monotonic() + timeout
    while True:
        if condition():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)
