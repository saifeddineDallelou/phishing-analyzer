"""Shared test setup. pytest loads this file automatically before any test."""
import pytest

from app import config
from app.intel import CACHE


@pytest.fixture(autouse=True)
def no_real_api_calls(monkeypatch):
    """Tests must never reach the internet or spend your API quota, even if a real .env exists.
    Tests that exercise threat intel pass their own fake settings and a mocked HTTP client."""
    monkeypatch.setattr(config, "get_settings", lambda: config.Settings())
    CACHE.clear()
    yield
    CACHE.clear()
