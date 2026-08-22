import io
from threading import Semaphore

import pytest

from scripts import helpers
from scripts.helpers import (
    is_valid_cve,
    parse_cpe,
    parse_report,
    truncate_string,
    worker,
)


# ---------------------------------------------------------------------------
# parse_cpe
# ---------------------------------------------------------------------------

def test_parse_cpe_extracts_vendor_and_product():
    vendor, product = parse_cpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
    assert vendor == "apache"
    assert product == "log4j"


def test_parse_cpe_empty_placeholder():
    vendor, product = parse_cpe("cpe:2.3:::::::::::")
    assert vendor == ""
    assert product == ""


# ---------------------------------------------------------------------------
# truncate_string
# ---------------------------------------------------------------------------

def test_truncate_string_short_input_unchanged():
    assert truncate_string("short", 10) == "short"


def test_truncate_string_long_input_ellipsized():
    result = truncate_string("a" * 20, 10)
    assert result == "a" * 7 + "..."
    assert len(result) == 10


# ---------------------------------------------------------------------------
# is_valid_cve
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cve_id", ["CVE-2021-44228", "CVE-1999-0001", "CVE-2024-123456"])
def test_is_valid_cve_accepts_standard_ids(cve_id):
    assert is_valid_cve(cve_id)


@pytest.mark.parametrize("cve_id", ["CVE-21-44228", "cve-2021-44228", "CVE-2021-1", "not-a-cve", ""])
def test_is_valid_cve_rejects_malformed_ids(cve_id):
    assert not is_valid_cve(cve_id)


# ---------------------------------------------------------------------------
# parse_report
# ---------------------------------------------------------------------------

NESSUS_XML = """<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="test">
    <ReportHost name="host1">
      <ReportItem port="443" pluginID="1">
        <cve>CVE-2021-44228</cve>
        <cve>CVE-2019-0708</cve>
        <cve>not-a-cve</cve>
      </ReportItem>
      <ReportItem port="80" pluginID="2">
        <cve>CVE-2021-44228</cve>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""

OPENVAS_XML = """<?xml version="1.0"?>
<report>
  <results>
    <result>
      <nvt oid="1.3.6.1.4.1.25623.1.0.1">
        <refs>
          <ref type="cve" id="CVE-2019-0708"/>
          <ref type="url" id="https://example.com/advisory"/>
        </refs>
      </nvt>
    </result>
    <result>
      <nvt oid="1.3.6.1.4.1.25623.1.0.2">
        <refs>
          <ref type="cve" id="CVE-2021-44228"/>
        </refs>
      </nvt>
    </result>
  </results>
</report>
"""


def test_parse_report_nessus_dedupes_and_filters(tmp_path):
    report = tmp_path / "scan.nessus"
    report.write_text(NESSUS_XML)
    result = parse_report(str(report), "nessus")
    assert sorted(result) == ["CVE-2019-0708", "CVE-2021-44228"]


def test_parse_report_openvas_reads_cve_refs_only(tmp_path):
    report = tmp_path / "scan.xml"
    report.write_text(OPENVAS_XML)
    result = parse_report(str(report), "openvas")
    assert sorted(result) == ["CVE-2019-0708", "CVE-2021-44228"]


def test_parse_report_invalid_xml_returns_empty(tmp_path):
    report = tmp_path / "broken.nessus"
    report.write_text("<not-closed>")
    assert parse_report(str(report), "nessus") == []


# ---------------------------------------------------------------------------
# worker priority logic
# ---------------------------------------------------------------------------

def _nist_result(**overrides):
    result = {
        "cvss_version": "CVSS 3.1",
        "cvss_baseScore": 5.0,
        "cvss_severity": "MEDIUM",
        "cisa_kev": False,
        "exploit_maturity_attacked": False,
        "ransomware": "",
        "cpe": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    }
    result.update(overrides)
    return result


def _run_worker(monkeypatch, nist_result, epss_result, save_output=None):
    """Run worker with mocked fetchers, default thresholds (CVSS 6.0 / EPSS 0.2)."""
    monkeypatch.setattr(helpers, "nist_check", lambda *a, **k: nist_result)
    monkeypatch.setattr(helpers, "epss_check", lambda *a, **k: epss_result)
    results = []
    worker(
        "CVE-2000-0001", 6.0, 0.2, False, Semaphore(1), False, 3,
        save_output=save_output, results=results,
    )
    return results


def test_worker_kev_is_priority_1_plus(monkeypatch):
    results = _run_worker(
        monkeypatch,
        _nist_result(cisa_kev="2021-12-10", ransomware="TRUE"),
        {"epss": 0.9, "percentile": 0.99},
    )
    assert results[0]["priority"] == "P1+"
    assert results[0]["kev"] == "TRUE"


def test_worker_exploit_maturity_is_priority_1_plus(monkeypatch):
    results = _run_worker(
        monkeypatch,
        _nist_result(exploit_maturity_attacked=True),
        {"epss": 0.01, "percentile": 0.1},
    )
    assert results[0]["priority"] == "P1+"
    assert results[0]["kev"] == "FALSE"


@pytest.mark.parametrize(
    "cvss,epss,expected",
    [
        (9.8, 0.9, "P1"),   # high CVSS, high EPSS
        (9.8, 0.01, "P2"),  # high CVSS, low EPSS
        (4.0, 0.9, "P3"),   # low CVSS, high EPSS
        (4.0, 0.01, "P4"),  # low CVSS, low EPSS
    ],
)
def test_worker_quadrant_priorities(monkeypatch, cvss, epss, expected):
    results = _run_worker(
        monkeypatch,
        _nist_result(cvss_baseScore=cvss),
        {"epss": epss, "percentile": 0.5},
    )
    assert results[0]["priority"] == expected


def test_worker_fetch_failure_produces_no_result(monkeypatch):
    # Fetchers signal failure with empty-string fields; worker must swallow
    # the comparison TypeError and skip the CVE instead of crashing.
    results = _run_worker(
        monkeypatch,
        _nist_result(cvss_baseScore="", cvss_severity="", cisa_kev="",
                     exploit_maturity_attacked="", cpe="", vector=""),
        {"epss": None, "percentile": None},
    )
    assert results == []


def test_worker_writes_csv_row(monkeypatch):
    output = io.StringIO()
    _run_worker(
        monkeypatch,
        _nist_result(cvss_baseScore=9.8),
        {"epss": 0.9, "percentile": 0.97},
        save_output=output,
    )
    row = output.getvalue().strip().split(",")
    assert row[0] == "CVE-2000-0001"
    assert row[1] == "Priority 1"
    assert row[2] == "0.9"
    assert row[3] == "0.97"
