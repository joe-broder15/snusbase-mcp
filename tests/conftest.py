"""Shared fixtures. Network is blocked for every test."""

import pytest
import respx

from snusbase_client.client import ENV_API_KEY


@pytest.fixture(autouse=True)
def _no_ambient_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_API_KEY, raising=False)


@pytest.fixture(autouse=True)
def router():
    """Block every httpx call unless a test adds a route."""
    with respx.mock(assert_all_called=False) as mock:
        yield mock
