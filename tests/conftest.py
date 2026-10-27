from dataclasses import replace

import pytest

from assetsuite.client import QRadarClient
from assetsuite.config import Config

HOST = "qradar.test.lan"
BASE = f"https://{HOST}/api"
TOKEN = "11111111-2222-3333-4444-555555555555"


@pytest.fixture
def config() -> Config:
    return Config(host=HOST, token=TOKEN, api_version="20.0", page_size=50)


@pytest.fixture
def client(config: Config) -> QRadarClient:
    return QRadarClient(config)


@pytest.fixture
def small_page_client(config: Config) -> QRadarClient:
    """Client with 2 items per page, for pagination tests."""
    return QRadarClient(replace(config, page_size=2))
