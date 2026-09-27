import json
import sys
import types

import pytest
from click.testing import CliRunner

# The ASCII-art banner library is a CLI nicety that doesn't install everywhere; stub it for tests
sys.modules.setdefault("fade", types.SimpleNamespace(greenblue=lambda text: text))

from cve_prioritizer import cve_prioritizer as cli  # noqa: E402
from scripts import helpers  # noqa: E402
from scripts.constants import CISA_KEV_URL, EPSS_URL, NIST_BASE_URL, NUCLEI_BASE_URL  # noqa: E402

CVES = ["CVE-2021-44228", "CVE-2023-4863", "CVE-2019-0708"]


class FakeResponse:
    def __init__(self, payload, text=""):
        self._payload = payload
        self.text = text
        self.status_code = 200

    def json(self):
        return self._payload

    def raise_for_status(self):
        pass


@pytest.fixture
def fake_apis(monkeypatch):
    calls = {"nvd": 0, "epss": 0, "kev": 0, "nuclei": 0}

    def fake_get(url, **kwargs):
        if url.startswith(NIST_BASE_URL):
            calls["nvd"] += 1
            cve_id = url.split("cveId=")[1]
            return FakeResponse({"totalResults": 1, "vulnerabilities": [{"cve": {
                "id": cve_id, "vulnStatus": "Analyzed",
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL",
                                                            "vectorString": "CVSS:3.1/AV:N"}}]}}}]})
        if url.startswith(EPSS_URL):
            calls["epss"] += 1
            requested = url.split("cve=")[1].split("&")[0].split(",")
            return FakeResponse({"total": len(requested),
                                 "data": [{"cve": c, "epss": "0.9", "percentile": "0.99"} for c in requested]})
        if url == NUCLEI_BASE_URL:
            calls["nuclei"] += 1
            return FakeResponse(None, text='{"ID":"CVE-2021-44228","Info":{}}\n')
        if url == CISA_KEV_URL:
            calls["kev"] += 1
            return FakeResponse({"vulnerabilities": []})
        raise AssertionError(f"unexpected URL {url}")

    monkeypatch.setattr(helpers, "http_get", fake_get)
    monkeypatch.delenv("NIST_API", raising=False)
    return calls


@pytest.fixture
def sleeps(monkeypatch):
    recorded = []
    monkeypatch.setattr(cli.time, "sleep", recorded.append)
    return recorded


def run(tmp_path, *extra):
    out = tmp_path / "out.json"
    result = CliRunner().invoke(cli.main, ["-l", ",".join(CVES), "-j", str(out), *extra],
                                env={"XDG_CACHE_HOME": str(tmp_path / "cache")})
    assert result.exit_code == 0, result.output
    return json.loads(out.read_text())["cves"]


def test_second_run_uses_cache_and_skips_throttle(tmp_path, fake_apis, sleeps):
    first = run(tmp_path)
    # EPSS: one batch request for all 3 CVEs; Nuclei index: one download
    assert fake_apis == {"nvd": 3, "epss": 1, "kev": 0, "nuclei": 1}
    assert sleeps == [1, 1, 1]

    # A new CLI process starts with empty in-memory caches
    helpers._epss_cache.clear()
    helpers._nuclei_ids, helpers._nuclei_loaded = None, False
    sleeps.clear()
    second = run(tmp_path)

    assert fake_apis["nvd"] == 3     # no new NVD requests
    assert fake_apis["nuclei"] == 1  # Nuclei index reused from the disk cache
    assert fake_apis["epss"] == 2    # EPSS is always fresh: it changes daily
    assert sleeps == [0, 0, 0]     # nothing to rate-limit
    assert sorted(r["cve_id"] for r in second) == sorted(CVES)
    assert {r["priority"] for r in first} == {r["priority"] for r in second} == {"P1"}


def test_no_cache_flag_always_hits_nvd(tmp_path, fake_apis, sleeps):
    run(tmp_path, "--no-cache")
    run(tmp_path, "--no-cache")

    assert fake_apis["nvd"] == 6
    assert not (tmp_path / "cache").exists()


def test_output_explains_each_priority(tmp_path, fake_apis, sleeps):
    results = {r["cve_id"]: r for r in run(tmp_path)}

    log4shell = results["CVE-2021-44228"]
    assert log4shell["public_exploit"] == "TRUE"
    assert log4shell["reason"] == "CVSS 9.8 >= 6 and EPSS 0.9 >= 0.2; public exploit template (Nuclei)"
    assert results["CVE-2023-4863"]["public_exploit"] == "FALSE"


def test_csv_quotes_reason_and_keeps_existing_columns(tmp_path, fake_apis, sleeps):
    import csv

    out = tmp_path / "out.csv"
    result = CliRunner().invoke(cli.main, ["-l", "CVE-2021-44228", "-o", str(out)],
                                env={"XDG_CACHE_HOME": str(tmp_path / "cache")})
    assert result.exit_code == 0, result.output

    rows = list(csv.reader(out.open()))
    assert rows[0][:15] == ["cve_id", "priority", "epss", "epss_percentile", "cvss", "cvss_version",
                            "cvss_severity", "kev", "ransomware", "exploited", "kev_source", "cpe", "vendor",
                            "product", "vector"]  # original columns keep their positions
    assert rows[0][-1] == "reason"
    assert len(rows[1]) == len(rows[0])  # the "; " and "," inside reason didn't split the row
    assert rows[1][0] == "CVE-2021-44228" and rows[1][1] == "Priority 1"
