import pytest

from scripts import cache, helpers


@pytest.fixture(autouse=True)
def isolate(monkeypatch, tmp_path):
    """
    Each test starts with empty KEV/EPSS caches, its own NVD cache file, and no real network.
    Tests that need HTTP patch helpers.http_get themselves.
    """
    helpers._kev_cache = None
    helpers._epss_cache.clear()
    cache.configure(enabled=True, ttl_hours=24, path=str(tmp_path / "nvd.sqlite"))

    def no_network(url, **kwargs):
        raise AssertionError(f"Unexpected network call in test: {url}")

    monkeypatch.setattr(helpers, "http_get", no_network)
    yield
    helpers._kev_cache = None
    helpers._epss_cache.clear()
