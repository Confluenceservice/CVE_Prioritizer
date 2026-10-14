"""CVEs that cannot be scored are reported with a reason instead of vanishing.

Before this, every fetcher signalled "no score" with the same empty-field dict,
and the worker swallowed the resulting TypeError: the CVE got no row and the
run still exited 0. A brand-new CVE that NVD has not published yet looked
exactly like one whose lookup was rate limited.
"""
from threading import Semaphore

import pytest
import requests
from click.testing import CliRunner

from scripts import helpers
from scripts.helpers import worker


class _Response:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"{self.status_code}")

    def json(self):
        return self._payload


def _nvd_record(vuln_status="Analyzed", metrics=None):
    return {
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2000-0001",
                "vulnStatus": vuln_status,
                "metrics": metrics or {},
                "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:v:p:1:*:*:*:*:*:*:*"}]}]}],
            }
        }],
    }


V40_ONLY = {"cvssMetricV40": [{"cvssData": {"baseScore": 9.3, "baseSeverity": "CRITICAL",
                                            "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}}]}


# ---------------------------------------------------------------------------
# nist_check: each way of coming back empty carries its own reason
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload,status,cvss_version,expected", [
    ({"totalResults": 0, "vulnerabilities": []}, 200, 3, helpers.UNSCORED_NOT_FOUND),
    (_nvd_record("Awaiting Analysis"), 200, 3, helpers.UNSCORED_AWAITING_ANALYSIS),
    (_nvd_record("Received", V40_ONLY), 200, 3, helpers.UNSCORED_NO_METRICS),
    ({}, 403, 3, helpers.UNSCORED_LOOKUP_ERROR),
])
def test_nist_check_tags_empty_results(monkeypatch, payload, status, cvss_version, expected):
    monkeypatch.setattr(helpers.requests, "get", lambda *a, **k: _Response(payload, status))
    result = helpers.nist_check("CVE-2000-0001", None, cvss_version)
    assert result["cvss_baseScore"] == ""
    assert result["unscored_reason"] == expected


def test_nist_check_v4_only_scores_when_v4_requested(monkeypatch):
    monkeypatch.setattr(helpers.requests, "get", lambda *a, **k: _Response(_nvd_record("Received", V40_ONLY)))
    result = helpers.nist_check("CVE-2000-0001", None, 4)
    assert result["cvss_baseScore"] == 9.3
    assert "unscored_reason" not in result


def test_nist_check_connection_error_is_lookup_error(monkeypatch):
    def boom(*a, **k):
        raise requests.exceptions.ConnectionError()
    monkeypatch.setattr(helpers.requests, "get", boom)
    assert helpers.nist_check("CVE-2000-0001", None, 3)["unscored_reason"] == helpers.UNSCORED_LOOKUP_ERROR


# ---------------------------------------------------------------------------
# vulncheck_check: same reasons through NVD++
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload,status,expected", [
    ({"_meta": {"total_documents": 0}, "data": []}, 200, helpers.UNSCORED_NOT_FOUND),
    ({"_meta": {"total_documents": 1}, "data": [{"vulnStatus": "Awaiting Analysis", "metrics": {}}]}, 200,
     helpers.UNSCORED_AWAITING_ANALYSIS),
    ({"_meta": {"total_documents": 1}, "data": [{"vulnStatus": "Received", "metrics": V40_ONLY}]}, 200,
     helpers.UNSCORED_NO_METRICS),
    ({}, 500, helpers.UNSCORED_LOOKUP_ERROR),
])
def test_vulncheck_check_tags_empty_results(monkeypatch, payload, status, expected):
    monkeypatch.setattr(helpers, "_get_kev_catalog", lambda: {})
    monkeypatch.setattr(helpers.requests, "get", lambda *a, **k: _Response(payload, status))
    result = helpers.vulncheck_check("CVE-2000-0001", "vulncheck_fake", False, 3)
    assert result["unscored_reason"] == expected


def test_vulncheck_check_without_key_is_lookup_error(monkeypatch):
    monkeypatch.delenv("VULNCHECK_API", raising=False)
    assert helpers.vulncheck_check("CVE-2000-0001", None, False, 3)["unscored_reason"] == helpers.UNSCORED_LOOKUP_ERROR


# ---------------------------------------------------------------------------
# worker: still no CSV row, but the CVE is reported with its reason
# ---------------------------------------------------------------------------

def _run_worker(monkeypatch, nist_result, epss_result, unscored=None):
    monkeypatch.setattr(helpers, "nist_check", lambda *a, **k: nist_result)
    monkeypatch.setattr(helpers, "epss_check", lambda *a, **k: epss_result)
    results = []
    worker("CVE-2000-0001", 6.0, 0.2, False, Semaphore(1), False, 3, results=results, unscored=unscored)
    return results


def test_worker_reports_unscored_cve_with_fetcher_reason(monkeypatch):
    unscored = []
    results = _run_worker(monkeypatch, helpers._empty_result(helpers.UNSCORED_NOT_FOUND),
                          {"epss": 0.01, "percentile": 0.1}, unscored)
    assert results == []
    assert unscored == [{"cve_id": "CVE-2000-0001", "reason": "not_found", "source": "CISA"}]


def test_worker_reports_missing_epss(monkeypatch):
    unscored = []
    scored = {"cvss_version": "CVSS 3.1", "cvss_baseScore": 9.8, "cvss_severity": "CRITICAL",
              "cisa_kev": False, "exploit_maturity_attacked": False, "ransomware": "", "cpe": "", "vector": ""}
    results = _run_worker(monkeypatch, scored, {"epss": None, "percentile": None}, unscored)
    assert results == []
    assert unscored[0]["reason"] == helpers.UNSCORED_EPSS_UNAVAILABLE


def test_worker_kev_cve_without_score_is_still_priority_1_plus(monkeypatch):
    # KEV membership decides on its own; a missing CVSS score must not demote it.
    unscored = []
    result = helpers._empty_result(helpers.UNSCORED_AWAITING_ANALYSIS)
    result["cisa_kev"] = "2026-10-01"
    results = _run_worker(monkeypatch, result, {"epss": 0.5, "percentile": 0.9}, unscored)
    assert results[0]["priority"] == "P1+"
    assert unscored == []


def test_worker_without_unscored_list_behaves_as_before(monkeypatch):
    # Callers that don't pass `unscored` see the old behaviour: nothing, no crash.
    results = _run_worker(monkeypatch, helpers._empty_result(helpers.UNSCORED_NOT_FOUND),
                          {"epss": 0.01, "percentile": 0.1})
    assert results == []


# ---------------------------------------------------------------------------
# CLI: --unscored-file, and the main CSV is unchanged
# ---------------------------------------------------------------------------

def test_cli_writes_unscored_file_and_leaves_output_csv_alone(monkeypatch, tmp_path):
    from cve_prioritizer import cve_prioritizer as cli

    def fake_nist(cve_id, api, cvss_v):
        if cve_id == "CVE-2026-0002":
            return helpers._empty_result(helpers.UNSCORED_NOT_FOUND)
        return {"cvss_version": "CVSS 3.1", "cvss_baseScore": 9.8, "cvss_severity": "CRITICAL",
                "cisa_kev": False, "exploit_maturity_attacked": False, "ransomware": "",
                "cpe": "cpe:2.3:a:v:p:1:*:*:*:*:*:*:*", "vector": "CVSS:3.1/AV:N"}

    monkeypatch.setattr(helpers, "nist_check", fake_nist)
    monkeypatch.setattr(helpers, "epss_check", lambda *a, **k: {"epss": 0.9, "percentile": 0.99})
    monkeypatch.setattr(cli, "epss_batch_prefetch", lambda ids: None)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    monkeypatch.setenv("NIST_API", "fake")

    out_csv = tmp_path / "out.csv"
    unscored_csv = tmp_path / "unscored.csv"
    result = CliRunner().invoke(cli.main, [
        "--list", "CVE-2026-0001,CVE-2026-0002", "--no-color",
        "--output", str(out_csv), "--unscored-file", str(unscored_csv),
    ])
    assert result.exit_code == 0, result.output

    rows = out_csv.read_text().strip().splitlines()
    assert rows[0].startswith("cve_id,priority,epss,epss_percentile,cvss,")  # header unchanged
    assert [r.split(",")[0] for r in rows[1:]] == ["CVE-2026-0001"]

    assert unscored_csv.read_text().splitlines() == ["cve_id,reason,source", "CVE-2026-0002,not_found,CISA"]
