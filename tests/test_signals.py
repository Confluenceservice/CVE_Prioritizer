import shutil
from pathlib import Path

import pytest
import requests

from scripts import helpers
from scripts.helpers import (build_reason, classify, cvelist_check, get_nuclei_cves, has_public_exploit,
                             parse_ssvc, signal_notes, ssvc_check)

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def cvelist_mirror(tmp_path):
    """A local cvelistV5 mirror containing the trimmed real records in tests/fixtures."""
    for name, block in (("CVE-2021-44228", "44xxx"), ("CVE-2024-3400", "3xxx")):
        year = name.split("-")[1]
        target = tmp_path / "cves" / year / block
        target.mkdir(parents=True)
        shutil.copy(FIXTURES / f"{name}.json", target / f"{name}.json")
    return str(tmp_path)


# ---------- reason ----------

@pytest.mark.parametrize("priority, cvss, epss, expected", [
    ("P1", 9.8, 0.54, "CVSS 9.8 >= 6 and EPSS 0.54 >= 0.2"),
    ("P2", 9.8, 0.01, "CVSS 9.8 >= 6 but EPSS 0.01 < 0.2"),
    ("P3", 5.0, 0.4, "CVSS 5 < 6 but EPSS 0.4 >= 0.2"),
    ("P4", 3.1, 0.01, "CVSS 3.1 < 6 and EPSS 0.01 < 0.2"),
    ("UNSCORED", "", 0.4, "No CVSS score yet, review manually"),
    ("UNSCORED", "", None, "No CVSS or EPSS score yet, review manually"),
])
def test_reason_explains_the_bucket(priority, cvss, epss, expected):
    assert classify(cvss, epss, False, False, 6.0, 0.2) == priority
    assert build_reason(priority, cvss, epss, 6.0, 0.2) == expected


def test_reason_lists_exploitation_evidence_and_signals():
    reason = build_reason("P1+", 2.0, 0.01, 6.0, 0.2,
                          ["listed in KEV (CISA)", "CISA SSVC: active exploitation"],
                          ["public exploit template (Nuclei)"])

    assert reason == ("Exploited: listed in KEV (CISA), CISA SSVC: active exploitation; "
                      "public exploit template (Nuclei)")


def test_signal_notes():
    assert signal_notes(True, 0.35, {"exploitation": "poc", "automatable": "yes", "technical_impact": "total"}) == [
        "public exploit template (Nuclei)",
        "EPSS up +0.35 in 7 days",
        "CISA SSVC: poc exploitation, automatable, total impact",
    ]
    # Small EPSS moves, unknown exploit data and empty SSVC add nothing
    assert signal_notes(None, 0.02, {"exploitation": "", "automatable": "", "technical_impact": ""}) == []
    # "active" is already stated as exploitation evidence, so it isn't repeated as a signal
    assert signal_notes(False, None, {"exploitation": "active"}) == []


# ---------- CISA SSVC (Vulnrichment) ----------

def test_parse_ssvc_from_real_record():
    import json
    record = json.loads((FIXTURES / "CVE-2021-44228.json").read_text())

    assert parse_ssvc(record) == {"exploitation": "active", "automatable": "yes", "technical_impact": "total"}
    assert parse_ssvc({"containers": {"cna": {}}}) == {"exploitation": "", "automatable": "", "technical_impact": ""}
    assert parse_ssvc(None)["exploitation"] == ""


def test_cvelist_uses_cisa_cvss_when_vendor_has_none(cvelist_mirror):
    # Apache's CNA record for Log4Shell has no CVSS; CISA's ADP container adds one
    result = cvelist_check("CVE-2021-44228", cvelist_mirror)

    assert result["cvss_baseScore"] == 10.0
    assert result["cisa_kev"] is True
    assert result["ssvc"]["exploitation"] == "active"


def test_cvelist_prefers_vendor_cvss(cvelist_mirror):
    result = cvelist_check("CVE-2024-3400", cvelist_mirror)

    assert result["cvss_baseScore"] == 10.0
    assert result["cvss_severity"] == "CRITICAL"


def test_ssvc_check_for_other_sources(cvelist_mirror):
    assert ssvc_check("CVE-2024-3400", cvelist_mirror)["automatable"] == "yes"
    assert ssvc_check("CVE-2019-0001", cvelist_mirror)["exploitation"] == ""  # not in the mirror


# ---------- Public exploits (Nuclei) ----------

class TextResponse:
    status_code = 200

    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        pass


NUCLEI_INDEX = ('{"ID":"CVE-2021-44228","Info":{"Name":"Log4j RCE"},"file_path":"http/cves/2021/CVE-2021-44228.yaml"}\n'
                'not json\n'
                '\n'
                '{"ID":"cve-2024-3400","Info":{}}\n')


def test_nuclei_index_is_parsed_and_cached_on_disk(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return TextResponse(NUCLEI_INDEX)

    monkeypatch.setattr(helpers, "http_get", fake_get)

    assert get_nuclei_cves() == {"CVE-2021-44228", "CVE-2024-3400"}
    assert has_public_exploit("CVE-2024-3400") is True
    assert has_public_exploit("CVE-2023-4863") is False

    # A new run (fresh in-memory state) reads the index from the disk cache
    helpers._nuclei_ids, helpers._nuclei_loaded = None, False
    assert has_public_exploit("CVE-2021-44228") is True
    assert len(calls) == 1


def test_nuclei_unavailable_means_unknown_not_no(monkeypatch):
    def fake_get(url, **kwargs):
        raise requests.exceptions.ConnectionError("offline")

    monkeypatch.setattr(helpers, "http_get", fake_get)

    assert has_public_exploit("CVE-2021-44228") is None


# ---------- Worker integration ----------

def test_ssvc_active_exploitation_makes_p1_plus(monkeypatch, cvelist_mirror):
    import io
    from threading import Semaphore

    low_scores = {"cvss_version": "CVSS V31", "cvss_baseScore": 3.0, "cvss_severity": "LOW", "cisa_kev": False,
                  "exploit_maturity_attacked": False, "ransomware": "", "cpe": "", "vector": ""}
    monkeypatch.setattr(helpers, "nist_check", lambda *args: low_scores)
    monkeypatch.setattr(helpers, "epss_check",
                        lambda *args: {"epss": 0.01, "percentile": 0.1, "epss_change_7d": None})
    monkeypatch.setattr(helpers, "has_public_exploit", lambda cve_id: None)
    results = []

    helpers.worker("CVE-2024-3400", 6.0, 0.2, True, Semaphore(), False, 3, save_output=io.StringIO(),
                   results=results, cvelist_path=cvelist_mirror, ssvc=True)

    row = results[0]
    assert row["priority"] == "P1+"
    assert row["exploited"] == "TRUE"
    assert row["public_exploit"] == ""  # unknown, not FALSE
    assert row["reason"] == "Exploited: CISA SSVC: active exploitation"
