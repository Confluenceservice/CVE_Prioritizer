import requests

from scripts import helpers
from scripts.helpers import epss_check, prefetch_epss


class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(self.status_code)


def cve_ids(count):
    return [f"CVE-2024-{10000 + i}" for i in range(count)]


def test_prefetch_batches_100_cves_per_request(monkeypatch):
    urls = []

    def fake_get(url, **kwargs):
        urls.append(url)
        requested = url.split("cve=")[1].split("&")[0].split(",")
        # EPSS knows every CVE except the last one of each batch
        rows = [{"cve": c, "epss": "0.5", "percentile": "0.9"} for c in requested[:-1]]
        return FakeResponse({"data": rows})

    monkeypatch.setattr(helpers, "http_get", fake_get)
    ids = cve_ids(250)

    prefetch_epss(ids + ids[:10])  # duplicates are only requested once

    assert len(urls) == 3
    assert all(len(u.split("cve=")[1].split("&")[0].split(",")) <= 100 for u in urls)

    # Lookups are now served from memory: any further HTTP call would fail the test
    monkeypatch.setattr(helpers, "http_get", lambda *a, **k: (_ for _ in ()).throw(AssertionError("network")))
    assert epss_check(ids[0]) == {"epss": 0.5, "percentile": 0.9}
    assert epss_check(sorted(ids)[99]) == {"epss": None, "percentile": None}  # not in EPSS


def test_failed_batch_falls_back_to_single_lookup(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        if "," in url:
            raise requests.exceptions.ConnectionError("batch failed")
        return FakeResponse({"total": 1, "data": [{"cve": "CVE-2024-10000", "epss": "0.3", "percentile": "0.7"}]})

    monkeypatch.setattr(helpers, "http_get", fake_get)

    prefetch_epss(cve_ids(2))
    result = epss_check("CVE-2024-10000")

    assert result == {"epss": 0.3, "percentile": 0.7}
    assert len(calls) == 2  # the failed batch, then one single lookup
