from scripts.report_generator import generate_report


def row(cve_id, priority, kev="FALSE", public_exploit="FALSE", reason="", vendor="acme"):
    return {"cve_id": cve_id, "priority": priority, "epss": 0.5, "epss_percentile": 0.9, "cvss_base_score": 9.8,
            "kev": kev, "kev_source": "CISA", "public_exploit": public_exploit, "vendor": vendor,
            "product": "widget", "cpe": "", "reason": reason}


def render(tmp_path, cves):
    out = tmp_path / "report.html"
    generate_report({"metadata": {"generation_date": "2026-09-27", "total_cves": len(cves)}, "cves": cves},
                    output_path=str(out), format="html")
    return out.read_text()


def card(html, label):
    """The number shown on the summary card with this label."""
    before = html[:html.index(f"<p>{label}</p>")]
    return before[before.rindex("<h2>") + 4:before.rindex("</h2>")].strip()


def test_summary_cards_count_kev_and_public_exploits(tmp_path):
    html = render(tmp_path, [
        row("CVE-2021-44228", "P1+", kev="TRUE", public_exploit="TRUE"),
        row("CVE-2024-3400", "P1+", kev="TRUE"),
        row("CVE-2023-0001", "P4", public_exploit=""),
    ])

    assert card(html, "Listed in KEV") == "2"  # was always 0: Jinja loop-scoping bug
    assert card(html, "Public Exploit") == "1"
    assert "Unknown" in html  # public_exploit "" is shown as unknown, not "No"


def test_reason_and_third_party_text_are_escaped(tmp_path):
    html = render(tmp_path, [row("CVE-2024-0001", "P2", reason="CVSS 9.8 >= 6 but EPSS 0.01 < 0.2",
                                 vendor="<script>alert(1)</script>")])

    assert "CVSS 9.8 &gt;= 6 but EPSS 0.01 &lt; 0.2" in html
    assert "<script>alert(1)</script>" not in html
