from scripts.report_generator import generate_report


SAMPLE_DATA = {
    "metadata": {
        "generator": "CVE Prioritizer",
        "generation_date": "2026-08-19T00:00:00+00:00",
        "total_cves": 2,
        "cvss_threshold": 6.0,
        "epss_threshold": 0.2,
    },
    "cves": [
        {
            "cve_id": "CVE-2021-44228",
            "priority": "P1+",
            "epss": 0.97,
            "epss_percentile": 0.999,
            "cvss_base_score": 10.0,
            "cvss_version": "CVSS 3.1",
            "cvss_severity": "CRITICAL",
            "kev": "TRUE",
            "kev_source": "CISA",
            "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        },
        {
            "cve_id": "CVE-2020-29127",
            "priority": "P4",
            "epss": 0.01,
            "epss_percentile": None,
            "cvss_base_score": 4.0,
            "cvss_version": "CVSS 3.1",
            "cvss_severity": "MEDIUM",
            "kev": "FALSE",
            "kev_source": "CISA",
            "cpe": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
            "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        },
    ],
}


def test_generate_report_html(tmp_path):
    output = tmp_path / "report.html"
    generate_report(SAMPLE_DATA, output_path=str(output), format="html")

    assert output.exists()
    html = output.read_text()
    assert "CVE-2021-44228" in html
    assert "CVE-2020-29127" in html
    assert SAMPLE_DATA["metadata"]["generation_date"] in html


def test_generate_report_handles_none_percentile(tmp_path):
    # A CVE missing from EPSS carries percentile None; the template must
    # render it as N/A instead of raising.
    output = tmp_path / "report.html"
    generate_report(SAMPLE_DATA, output_path=str(output), format="html")
    assert "N/A" in output.read_text()
