import time

import requests

from scripts import cache, helpers
from scripts.helpers import nist_check, nvd_cached


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload
        self.status_code = 200

    def json(self):
        return self._payload

    def raise_for_status(self):
        pass


def nvd_payload(cve_id, scored=True):
    metrics = {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL",
                                               "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}
    return {"totalResults": 1, "vulnerabilities": [{"cve": {
        "id": cve_id,
        "vulnStatus": "Analyzed" if scored else "Awaiting Analysis",
        "metrics": metrics if scored else {},
    }}]}


def counting_get(monkeypatch, payload):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(kwargs)
        return FakeResponse(payload)

    monkeypatch.setattr(helpers, "http_get", fake_get)
    return calls


def test_second_lookup_is_served_from_cache(monkeypatch):
    calls = counting_get(monkeypatch, nvd_payload("CVE-2021-44228"))

    first = nist_check("CVE-2021-44228", None, 3)
    second = nist_check("CVE-2021-44228", None, 3)

    assert first == second
    assert first["cvss_baseScore"] == 9.8
    assert len(calls) == 1
    assert calls[0]["nvd"] is True  # NVD requests use the 403-retrying profile
    assert nvd_cached("CVE-2021-44228")


def test_expired_entry_is_refetched(monkeypatch, tmp_path):
    cache.configure(enabled=True, ttl_hours=1, path=str(tmp_path / "ttl.sqlite"))
    calls = counting_get(monkeypatch, nvd_payload("CVE-2021-44228"))

    nist_check("CVE-2021-44228", None, 3)
    real_time = time.time
    monkeypatch.setattr(cache.time, "time", lambda: real_time() + 2 * 3600)
    nist_check("CVE-2021-44228", None, 3)

    assert len(calls) == 2


def test_unscored_records_are_not_cached(monkeypatch):
    # "Awaiting Analysis" records gain scores soon, so they are always fetched fresh
    calls = counting_get(monkeypatch, nvd_payload("CVE-2026-0001", scored=False))

    nist_check("CVE-2026-0001", None, 3)
    nist_check("CVE-2026-0001", None, 3)

    assert len(calls) == 2
    assert not nvd_cached("CVE-2026-0001")


def test_no_cache_flag_disables_cache(monkeypatch, tmp_path):
    cache.configure(enabled=False, path=str(tmp_path / "off.sqlite"))
    calls = counting_get(monkeypatch, nvd_payload("CVE-2021-44228"))

    nist_check("CVE-2021-44228", None, 3)
    nist_check("CVE-2021-44228", None, 3)

    assert len(calls) == 2
    assert not (tmp_path / "off.sqlite").exists()


def test_unwritable_cache_does_not_break_the_scan(monkeypatch, tmp_path):
    blocker = tmp_path / "not_a_dir"
    blocker.write_text("")
    cache.configure(enabled=True, path=str(blocker / "nvd.sqlite"))
    counting_get(monkeypatch, nvd_payload("CVE-2021-44228"))

    try:
        result = nist_check("CVE-2021-44228", None, 3)
    except OSError:
        raise AssertionError("cache failure leaked out of nist_check")

    assert result["cvss_baseScore"] == 9.8
