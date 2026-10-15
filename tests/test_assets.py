import io
from pathlib import Path

import pytest

from scripts.assets import (AssetInventory, build_fix_order, load_assets, parse_csv_findings, parse_nessus_findings,
                            parse_openvas_findings)
from scripts.helpers import parse_report

FIXTURES = Path(__file__).parent / "fixtures"


def pairs(findings):
    return sorted((f["host"], f["ip"], f["port"], f["cve_id"]) for f in findings)


# ---------- scanner parsers keep the host ----------

def test_nessus_findings_keep_host_ip_and_port():
    with open(FIXTURES / "sample.nessus") as f:
        findings = parse_nessus_findings(f)

    assert pairs(findings) == [
        ("10.0.5.23", "10.0.5.23", "", "CVE-2019-0708"),          # port 0 -> no port
        ("10.0.5.23", "10.0.5.23", "3389/tcp", "CVE-2019-0708"),  # no DNS name -> IP is the host
        ("web01.corp.example", "203.0.113.10", "443/tcp", "CVE-2021-44228"),
        ("web01.corp.example", "203.0.113.10", "443/tcp", "CVE-2021-45046"),
    ]


def test_openvas_findings_support_refs_and_legacy_cve_text():
    with open(FIXTURES / "sample_openvas.xml") as f:
        findings = parse_openvas_findings(f)

    assert pairs(findings) == [
        ("10.0.9.4", "10.0.9.4", "general/tcp", "CVE-2023-4863"),
        ("10.0.9.4", "10.0.9.4", "general/tcp", "CVE-2023-5129"),
        ("vpn.corp.example", "198.51.100.7", "443/tcp", "CVE-2024-3400"),  # NOCVE result skipped
    ]


def test_parse_report_still_returns_cve_ids():
    with open(FIXTURES / "sample.nessus") as f:
        assert parse_report(f, "nessus") == ["CVE-2019-0708", "CVE-2021-44228", "CVE-2021-45046"]
    with open(FIXTURES / "sample_openvas.xml") as f:
        assert parse_report(f, "openvas") == ["CVE-2023-4863", "CVE-2023-5129", "CVE-2024-3400"]


def test_csv_findings_with_renamed_columns():
    data = io.StringIO("Host,CVE_ID,IP,Port\napp01,CVE-2024-3400 CVE-2021-44228,10.1.1.1,443\n,cve-2019-0708,,\n")

    assert pairs(parse_csv_findings(data)) == [
        ("", "", "", "CVE-2019-0708"),
        ("app01", "10.1.1.1", "443", "CVE-2021-44228"),
        ("app01", "10.1.1.1", "443", "CVE-2024-3400"),
    ]
    with pytest.raises(ValueError):
        parse_csv_findings(io.StringIO("name,vuln\nx,CVE-2024-3400\n"))


# ---------- asset inventory ----------

@pytest.fixture
def inventory(capsys):
    with open(FIXTURES / "assets.csv") as f:
        inv = load_assets(f)
    inv.warnings = capsys.readouterr().out
    return inv


def test_asset_file_warns_about_bad_values_but_keeps_the_row(inventory):
    assert "line 5" in inventory.warnings and "internet_facing" in inventory.warnings
    entry = inventory.lookup("10.0.9.4")
    assert entry["criticality"] == "medium"
    assert entry["internet_facing"] is None


@pytest.mark.parametrize("host, ip, expected_owner", [
    ("web01.corp.example", "203.0.113.10", "web-team@corp.example"),  # short name in inventory
    ("vpn", "", "netops@corp.example"),                                # FQDN in inventory, short from scanner
    ("VPN.CORP.EXAMPLE", "", "netops@corp.example"),                   # case-insensitive
    ("10.0.5.23", "10.0.5.23", "it-lab"),                              # inside a CIDR range
    ("unknown.corp.example", "192.0.2.1", None),
])
def test_inventory_lookup(inventory, host, ip, expected_owner):
    entry = inventory.lookup(host, ip)
    assert (entry or {}).get("owner") == expected_owner


def test_most_specific_range_wins():
    inv = AssetInventory([
        {"host": "10.0.0.0/8", "criticality": "low", "internet_facing": False, "owner": "wide"},
        {"host": "10.0.5.0/24", "criticality": "high", "internet_facing": False, "owner": "narrow"},
    ])
    assert inv.lookup(ip="10.0.5.9")["owner"] == "narrow"
    assert inv.lookup(ip="10.9.9.9")["owner"] == "wide"


# ---------- fix order ----------

def result(cve_id, priority, cvss=9.8, epss=0.5):
    return {"cve_id": cve_id, "priority": priority, "cvss_base_score": cvss, "epss": epss, "reason": "r"}


def finding(host, cve_id, ip="", port=""):
    return {"host": host, "ip": ip, "cve_id": cve_id, "port": port}


def test_fix_order_priority_then_exposure_then_criticality():
    inv = AssetInventory([
        {"host": "edge", "criticality": "low", "internet_facing": True, "owner": ""},
        {"host": "core-db", "criticality": "critical", "internet_facing": False, "owner": ""},
        {"host": "portal", "criticality": "critical", "internet_facing": True, "owner": ""},
    ])
    results = {"CVE-2024-0001": result("CVE-2024-0001", "P1"), "CVE-2024-0002": result("CVE-2024-0002", "P2"),
               "CVE-2024-0003": result("CVE-2024-0003", "P1+")}
    rows = build_fix_order([
        finding("core-db", "CVE-2024-0001"),
        finding("edge", "CVE-2024-0001"),
        finding("portal", "CVE-2024-0001"),
        finding("portal", "CVE-2024-0002"),
        finding("unlisted", "CVE-2024-0001"),
        finding("core-db", "CVE-2024-0003"),
        finding("core-db", "CVE-2024-0003"),  # duplicate report of the same finding
        finding("core-db", "CVE-2099-9999"),  # CVE with no result is left to the CVE output
    ], results, inv)

    assert [(r["rank"], r["host"], r["cve_id"]) for r in rows] == [
        (1, "core-db", "CVE-2024-0003"),  # P1+ beats everything, even on an internal host
        (2, "portal", "CVE-2024-0001"),   # P1, internet-facing, critical
        (3, "edge", "CVE-2024-0001"),     # P1, internet-facing, low
        (4, "unlisted", "CVE-2024-0001"),  # P1, exposure unknown
        (5, "core-db", "CVE-2024-0001"),  # P1, internal
        (6, "portal", "CVE-2024-0002"),   # P2
    ]
    assert rows[1]["reason"] == "P1 on internet-facing host (criticality: critical); r"
    assert rows[3]["in_inventory"] == "FALSE"
    assert rows[3]["reason"] == "P1 on exposure unknown host; r"


def test_unscored_sits_between_p3_and_p4():
    results = {c: result(c, p) for c, p in
               (("CVE-2024-0001", "P4"), ("CVE-2024-0002", "UNSCORED"), ("CVE-2024-0003", "P3"))}
    rows = build_fix_order([finding("h", c) for c in results], results)

    assert [r["priority"] for r in rows] == ["P3", "UNSCORED", "P4"]
