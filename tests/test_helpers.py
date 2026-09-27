import json
import threading

import pytest
import requests

from scripts import helpers
from scripts.helpers import cvelist_check, is_valid_cve, kev_ransomware, parse_cpe


@pytest.mark.parametrize("cve, valid", [
    ("CVE-2021-44228", True),
    ("CVE-2024-1234567", True),
    ("CVE-garbage", False),     # used to pass: the old regex matched any text starting with "CVE"
    ("CVE-2021-123", False),    # sequence numbers have at least 4 digits
    ("cve-2021-44228", False),  # callers upper-case first
    ("CVE-2021-44228x", False),
])
def test_is_valid_cve(cve, valid):
    assert is_valid_cve(cve) is valid


@pytest.mark.parametrize("cpe, expected", [
    ("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", ("apache", "log4j")),
    ("cpe:2.3:::::::::::", ("", "")),
    ("", ("", "")),
    (None, ("", "")),
])
def test_parse_cpe(cpe, expected):
    assert parse_cpe(cpe) == expected


class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(self.status_code)


KEV_FEED = {"vulnerabilities": [
    {"cveID": "CVE-2021-44228", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2023-0001", "knownRansomwareCampaignUse": "Unknown"},
]}


def test_kev_catalog_downloaded_once_across_threads(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return FakeResponse(KEV_FEED)

    monkeypatch.setattr(helpers, "http_get", fake_get)

    out = []
    threads = [threading.Thread(target=lambda: out.append(kev_ransomware("CVE-2021-44228"))) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(calls) == 1
    assert out == ["KNOWN"] * 20
    assert kev_ransomware("CVE-2023-0001") == "UNKNOWN"
    assert kev_ransomware("CVE-1999-0001") == ""


def test_kev_download_failure_is_not_retried(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        raise requests.exceptions.ConnectionError("offline")

    monkeypatch.setattr(helpers, "http_get", fake_get)

    assert kev_ransomware("CVE-2021-44228") == ""
    assert kev_ransomware("CVE-2021-44228") == ""
    assert len(calls) == 1


def _write_cvelist_record(base, cve_id, containers):
    year, number = cve_id.split("-")[1:]
    block = "0xxx" if int(number) < 1000 else f"{number[:-3]}xxx"
    folder = base / "cves" / year / block
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{cve_id}.json").write_text(json.dumps({"containers": containers}))


def test_cvelist_detects_kev_from_cisa_adp(tmp_path):
    _write_cvelist_record(tmp_path, "CVE-2021-44228", {
        "cna": {
            "metrics": [{"cvssV3_1": {"baseScore": 10.0, "baseSeverity": "CRITICAL",
                                      "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}}],
            "affected": [{"vendor": "Apache", "product": "Log4j"}],
        },
        "adp": [{"metrics": [
            {"cvssV3_1": {"baseScore": 10.0}},        # metric without "other" used to crash the lookup
            {"other": {"type": "kev", "content": {}}},
        ]}],
    })

    result = cvelist_check("CVE-2021-44228", str(tmp_path))

    assert result["cisa_kev"] is True
    assert result["cvss_baseScore"] == 10.0
    assert result["cvss_severity"] == "CRITICAL"
    assert parse_cpe(result["cpe"]) == ("apache", "log4j")


def test_cvelist_missing_cvss_is_blank_not_zero(tmp_path):
    _write_cvelist_record(tmp_path, "CVE-2025-0042", {"cna": {"metrics": [], "affected": []}})

    result = cvelist_check("CVE-2025-0042", str(tmp_path))

    # A score of 0 would wrongly rank the CVE as P3/P4; blank makes it UNSCORED
    assert result["cvss_baseScore"] == ""
