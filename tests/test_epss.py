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
    assert epss_check(ids[0]) == {"epss": 0.5, "percentile": 0.9, "epss_change_7d": None}
    assert epss_check(sorted(ids)[99]) == {"epss": None, "percentile": None, "epss_change_7d": None}  # not in EPSS


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

    assert result == {"epss": 0.3, "percentile": 0.7, "epss_change_7d": None}
    assert len(calls) == 2  # the failed batch, then one single lookup


def test_epss_7_day_change_from_time_series(monkeypatch):
    row = {"cve": "CVE-2024-10000", "epss": "0.45", "percentile": "0.97", "date": "2026-09-27",
           "time-series": [{"epss": "0.40", "percentile": "0.96", "date": "2026-09-26"},
                           {"epss": "0.10", "percentile": "0.80", "date": "2026-09-20"},
                           {"epss": "0.05", "percentile": "0.70", "date": "2026-09-19"}]}

    def fake_get(url, **kwargs):
        assert "scope=time-series" in url
        return FakeResponse({"data": [row]})

    monkeypatch.setattr(helpers, "http_get", fake_get)
    prefetch_epss(["CVE-2024-10000"])

    # Compared with 2026-09-20, the point exactly 7 days earlier
    assert epss_check("CVE-2024-10000")["epss_change_7d"] == 0.35


def test_epss_change_unknown_without_old_enough_data():
    row = {"epss": "0.45", "percentile": "0.97", "date": "2026-09-27",
           "time-series": [{"epss": "0.40", "percentile": "0.96", "date": "2026-09-25"}]}

    assert helpers._parse_epss_row(row)["epss_change_7d"] is None
    assert helpers._parse_epss_row({"epss": "0.1", "percentile": "0.5"})["epss_change_7d"] is None
