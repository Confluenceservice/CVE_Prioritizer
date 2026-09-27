import json
import sys
import types

import pytest
from click.testing import CliRunner

from scripts.diff import compare, compare_cves, compare_findings, load_baseline

sys.modules.setdefault("fade", types.SimpleNamespace(greenblue=lambda text: text))

from cve_prioritizer import cve_prioritizer as cli  # noqa: E402
from scripts import helpers  # noqa: E402
from scripts.constants import CISA_KEV_URL, EPSS_URL, NIST_BASE_URL, NUCLEI_BASE_URL  # noqa: E402


def cve(cve_id, priority, kev="FALSE", epss=0.1, public_exploit="FALSE", **extra):
    return dict(cve_id=cve_id, priority=priority, kev=kev, epss=epss, public_exploit=public_exploit,
                kev_source="CISA", **extra)


def kinds(changes):
    return [(c["change"], c["cve_id"]) for c in changes]


# ---------- CVE-level changes ----------

def test_detects_each_kind_of_change():
    before = [
        cve("CVE-2024-0001", "P2", epss=0.05),
        cve("CVE-2024-0002", "P1"),
        cve("CVE-2024-0003", "UNSCORED", epss=None),
        cve("CVE-2024-0004", "P3", public_exploit="FALSE"),
        cve("CVE-2024-0005", "P4"),
        cve("CVE-2024-0006", "P2", epss=0.05),
    ]
    after = [
        cve("CVE-2024-0001", "P1+", kev="TRUE", epss=0.6),  # KEV + priority up + EPSS spike
        cve("CVE-2024-0002", "P2"),                           # priority down
        cve("CVE-2024-0003", "P1", epss=0.3),                 # got scored
        cve("CVE-2024-0004", "P3", public_exploit="TRUE"),    # exploit published
        cve("CVE-2024-0006", "P2", epss=0.1),                 # +0.05: below the spike threshold
        cve("CVE-2024-0007", "P1"),                           # new
    ]

    assert kinds(compare_cves(before, after)) == [
        ("NEWLY_KEV", "CVE-2024-0001"),
        ("PRIORITY_UP", "CVE-2024-0001"),
        ("NEW", "CVE-2024-0007"),
        ("NEW_PUBLIC_EXPLOIT", "CVE-2024-0004"),
        ("EPSS_SPIKE", "CVE-2024-0001"),
        ("NEWLY_SCORED", "CVE-2024-0003"),
        ("PRIORITY_DOWN", "CVE-2024-0002"),
        ("RESOLVED", "CVE-2024-0005"),
    ]


def test_change_details_are_readable():
    changes = {c["change"]: c for c in compare_cves([cve("CVE-2024-0001", "P2", epss=0.05)],
                                                    [cve("CVE-2024-0001", "P1+", kev="TRUE", epss=0.6)])}

    assert changes["PRIORITY_UP"]["detail"] == "P2 -> P1+"
    assert changes["EPSS_SPIKE"]["detail"] == "EPSS 0.05 -> 0.6 (+0.55)"
    assert changes["NEWLY_KEV"]["detail"] == "added to KEV (CISA)"


def test_unknown_baseline_values_are_not_reported_as_changes():
    # Baselines from older versions have no public_exploit field; an unknown can't prove "new"
    before = [{"cve_id": "CVE-2024-0001", "priority": "P2", "kev": "FALSE", "epss": None}]
    after = [cve("CVE-2024-0001", "P2", public_exploit="TRUE", epss=0.9)]

    assert compare_cves(before, after) == []


def test_identical_runs_have_no_changes():
    run = [cve("CVE-2024-0001", "P1"), cve("CVE-2024-0002", "P4")]
    assert compare({"cves": run}, run)["cves"] == []


# ---------- host-level changes ----------

def test_new_and_fixed_findings():
    before = [{"host": "web01", "cve_id": "CVE-2024-0001", "port": "443/tcp", "rank": 1},
              {"host": "web01", "cve_id": "CVE-2024-0002", "port": "443/tcp", "rank": 2}]
    after = [{"host": "WEB01", "cve_id": "CVE-2024-0001", "port": "443/tcp", "rank": 1},  # same, case aside
             {"host": "db01", "cve_id": "CVE-2024-0001", "port": "5432/tcp", "rank": 2}]

    result = compare_findings(before, after)

    assert [(f["host"], f["cve_id"]) for f in result["new"]] == [("db01", "CVE-2024-0001")]
    assert [(f["host"], f["cve_id"]) for f in result["fixed"]] == [("web01", "CVE-2024-0002")]


def test_findings_are_only_compared_when_both_runs_have_them():
    assert "findings" not in compare({"cves": []}, [], current_findings=[{"host": "a", "cve_id": "CVE-2024-0001"}])
    assert "findings" not in compare({"cves": [], "findings": []}, [], current_findings=None)


# ---------- baseline file handling ----------

@pytest.mark.parametrize("content, message", [
    (None, "not found"),
    ("{not json", "Unable to read baseline"),
    ('{"some": "other json"}', "not a CVE Prioritizer JSON output"),
])
def test_unusable_baseline_is_explained_not_fatal(tmp_path, capsys, content, message):
    path = tmp_path / "baseline.json"
    if content is not None:
        path.write_text(content)

    assert load_baseline(str(path)) is None
    assert message in capsys.readouterr().out


# ---------- end to end: a rolling baseline ----------

class FakeResponse:
    def __init__(self, payload=None, text=""):
        self._payload = payload
        self.text = text
        self.status_code = 200

    def json(self):
        return self._payload

    def raise_for_status(self):
        pass


@pytest.fixture
def world(monkeypatch):
    """Threat data the fake APIs serve; tests change it between runs."""
    state = {"epss": {"CVE-2021-44228": 0.05, "CVE-2019-0708": 0.05, "CVE-2023-4863": 0.05},
             "kev": set()}

    def fake_get(url, **kwargs):
        if url.startswith(NIST_BASE_URL):
            cve_id = url.split("cveId=")[1]
            record = {"id": cve_id, "vulnStatus": "Analyzed",
                      "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL",
                                                                  "vectorString": "CVSS:3.1/AV:N"}}]}}
            if cve_id in state["kev"]:
                record["cisaExploitAdd"] = "2026-09-20"
            return FakeResponse({"totalResults": 1, "vulnerabilities": [{"cve": record}]})
        if url.startswith(EPSS_URL):
            requested = url.split("cve=")[1].split("&")[0].split(",")
            return FakeResponse({"total": 1, "data": [
                {"cve": c, "epss": str(state["epss"][c]), "percentile": "0.5"}
                for c in requested if c in state["epss"]]})
        if url == NUCLEI_BASE_URL:
            return FakeResponse(text="")
        if url == CISA_KEV_URL:
            return FakeResponse({"vulnerabilities": [{"cveID": c, "knownRansomwareCampaignUse": "Unknown"}
                                                     for c in state["kev"]]})
        raise AssertionError(f"unexpected URL {url}")

    monkeypatch.setattr(helpers, "http_get", fake_get)
    monkeypatch.setattr(cli.time, "sleep", lambda seconds: None)
    monkeypatch.delenv("NIST_API", raising=False)
    return state


def run_cli(tmp_path, cves, *extra):
    helpers._epss_cache.clear()
    helpers._kev_cache = None
    helpers._nuclei_ids, helpers._nuclei_loaded = None, False
    return CliRunner().invoke(cli.main, ["-l", ",".join(cves), "--no-cache", *extra],
                              env={"XDG_CACHE_HOME": str(tmp_path / "cache")})


def test_rolling_baseline_reports_what_changed_since_last_run(tmp_path, world, monkeypatch):
    monkeypatch.chdir(tmp_path)  # --report writes report.html to the working directory
    last = str(tmp_path / "last.json")

    first = run_cli(tmp_path, ["CVE-2021-44228", "CVE-2019-0708"], "-j", last, "--baseline", last)
    assert first.exit_code == 0, first.output
    assert "Baseline" in first.output and "not found" in first.output  # first run: nothing to compare yet

    # A week later: Log4Shell is added to KEV, BlueKeep's EPSS jumps, a new CVE appears, one is gone
    world["kev"].add("CVE-2021-44228")
    world["epss"]["CVE-2019-0708"] = 0.65
    second = run_cli(tmp_path, ["CVE-2021-44228", "CVE-2023-4863", "CVE-2019-0708"], "-j", last,
                     "--baseline", last, "--report", "html")
    assert second.exit_code == 0, second.output

    assert "added to CISA KEV" in second.output
    # Every label fits its column, so the CVE ID is never glued to it
    assert all("CVE-" not in line.split()[0] for line in second.output.splitlines()
               if line.startswith(("added", "priority", "new", "EPSS")))
    report = (tmp_path / "report.html").read_text()
    assert "Changes since" in report and "added to CISA KEV" in report
    changes = json.loads(open(last).read())["changes"]
    assert kinds(changes["cves"]) == [
        ("NEWLY_KEV", "CVE-2021-44228"),
        ("PRIORITY_UP", "CVE-2021-44228"),
        ("PRIORITY_UP", "CVE-2019-0708"),
        ("NEW", "CVE-2023-4863"),
        ("EPSS_SPIKE", "CVE-2019-0708"),
    ]

    # The saved file is now the baseline for the next run: running again reports no changes
    third = run_cli(tmp_path, ["CVE-2021-44228", "CVE-2023-4863", "CVE-2019-0708"], "-j", last, "--baseline", last)
    assert "No changes." in third.output
