import io
from threading import Semaphore

import pytest

from scripts import helpers

EMPTY_NVD = {
    "cvss_version": "", "cvss_baseScore": "", "cvss_severity": "", "cisa_kev": "",
    "exploit_maturity_attacked": "", "ransomware": "", "cpe": "", "vector": "",
}


def run_worker(monkeypatch, nvd_result, epss_result, verbose=True, public_exploit=False):
    monkeypatch.setattr(helpers, "nist_check", lambda *args: nvd_result)
    monkeypatch.setattr(helpers, "epss_check", lambda *args: epss_result)
    monkeypatch.setattr(helpers, "has_public_exploit", lambda cve_id: public_exploit)
    csv = io.StringIO()
    results = []
    helpers.worker("CVE-2025-0001", 6.0, 0.2, verbose, Semaphore(), False, 3,
                   save_output=csv, results=results)
    return results, csv.getvalue()


def test_awaiting_analysis_cve_is_reported_as_unscored(monkeypatch, capsys):
    # NVD has not scored it yet and EPSS doesn't know it: this used to vanish from every output
    results, csv = run_worker(monkeypatch, EMPTY_NVD, {"epss": None, "percentile": None})

    assert [r["priority"] for r in results] == ["UNSCORED"]
    assert csv.startswith("CVE-2025-0001,Unscored,")
    assert "Unscored" in capsys.readouterr().out


def test_kev_cve_without_scores_is_still_p1_plus(monkeypatch):
    nvd = dict(EMPTY_NVD, cisa_kev="2025-01-01", ransomware="KNOWN")
    results, csv = run_worker(monkeypatch, nvd, {"epss": None, "percentile": None})

    assert results[0]["priority"] == "P1+"
    assert results[0]["kev"] == "TRUE"
    assert results[0]["ransomware"] == "KNOWN"
    assert csv.startswith("CVE-2025-0001,Priority 1+,")


@pytest.mark.parametrize("verbose", [True, False])
def test_scored_cve_matches_across_outputs(monkeypatch, verbose):
    nvd = dict(EMPTY_NVD, cvss_version="CVSS V31", cvss_baseScore=9.8, cvss_severity="CRITICAL",
               cpe="cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
    results, csv = run_worker(monkeypatch, nvd, {"epss": 0.01, "percentile": 0.5}, verbose=verbose)

    assert results[0]["priority"] == "P2"
    assert results[0]["exploited"] == "FALSE"
    assert csv.split(",")[:2] == ["CVE-2025-0001", "Priority 2"]
    assert ",apache,log4j," in csv
