import io
import json
import sys
import types
from datetime import date
from pathlib import Path
from threading import Semaphore

import pytest

from scripts import helpers, policy
from scripts.assets import AssetInventory, build_fix_order
from scripts.policy import PolicyError, apply_minimums, due_date, host_escalation, raise_priority, validate

ROOT = Path(__file__).parent.parent


# ---------- validation ----------

def test_no_policy_means_standard_behaviour():
    rules = validate(None)
    assert rules["thresholds"] == {"cvss": 6.0, "epss": 0.2}
    assert all(rules["exploitation"].values())
    assert not any(rules["minimum_priority"].values())
    assert rules["sla_days"] == {}


def test_example_policy_file_is_valid():
    rules = policy.load(str(ROOT / "policy.example.yaml"))
    assert rules["minimum_priority"]["public_exploit"] == "P1"
    assert rules["sla_days"]["P1+"] == 7


@pytest.mark.parametrize("data, message", [
    ({"thresold": {"cvss": 7}}, "unknown key(s) in 'policy': thresold"),         # typo is an error
    ({"thresholds": {"cvss": 11}}, "'thresholds.cvss' must be a number from 0 to 10"),
    ({"thresholds": {"epss": "high"}}, "'thresholds.epss' must be a number"),
    ({"exploitation": {"kev": "yes"}}, "'exploitation.kev' must be true or false"),
    ({"minimum_priority": {"public_exploit": "P1+"}}, "must be one of P1, P2, P3"),
    ({"host_escalation": {"internet_facing": 5}}, "from 0 to 3"),
    ({"host_escalation": {"internet_facing": True}}, "whole number of levels"),
    ({"host_escalation": {"criticality": {"extreme": 1}}}, "unknown key(s) in 'host_escalation.criticality'"),
    ({"sla_days": {"P1": -1}}, "'sla_days.P1' must be a whole number of days"),
    ({"sla_days": {"P0": 1}}, "unknown key(s) in 'sla_days'"),
    (["not", "a", "mapping"], "'policy' must be a mapping"),
])
def test_invalid_policies_name_the_problem(data, message):
    with pytest.raises(PolicyError) as err:
        validate(data)
    assert message in str(err.value)


def test_invalid_yaml(tmp_path):
    path = tmp_path / "p.yaml"
    path.write_text("thresholds: [unclosed")
    with pytest.raises(PolicyError, match="invalid YAML"):
        policy.load(str(path))


# ---------- rules ----------

@pytest.mark.parametrize("priority, levels, expected", [
    ("P4", 1, "P3"), ("P3", 1, "P2"), ("P2", 1, "P1"), ("P2", 5, "P1"),  # stops at P1
    ("P1", 1, "P1"), ("P1+", 1, "P1+"), ("UNSCORED", 2, "UNSCORED"), ("P3", 0, "P3"),
])
def test_raise_priority(priority, levels, expected):
    assert raise_priority(priority, levels) == expected


def test_minimum_priority_rules():
    rules = validate({"minimum_priority": {"public_exploit": "P1", "ssvc_poc": "P2"}})

    assert apply_minimums("P4", {"public_exploit": True}, rules) == \
        ("P1", ["raised to P1 by policy (public exploit)"])
    assert apply_minimums("P3", {"ssvc_poc": True}, rules) == \
        ("P2", ["raised to P2 by policy (CISA SSVC proof-of-concept)"])
    assert apply_minimums("P1", {"public_exploit": True}, rules) == ("P1", [])       # already there
    assert apply_minimums("P1+", {"public_exploit": True}, rules) == ("P1+", [])
    assert apply_minimums("UNSCORED", {"public_exploit": True}, rules)[0] == "P1"    # act before scores exist
    assert apply_minimums("P4", {"public_exploit": False}, rules) == ("P4", [])
    assert apply_minimums("P4", {"public_exploit": True}, validate(None)) == ("P4", [])  # off by default


def test_host_escalation_adds_levels():
    rules = validate({"host_escalation": {"internet_facing": 1, "criticality": {"critical": 1}}})

    assert host_escalation("P3", True, "critical", rules) == \
        ("P1", "raised P3 -> P1 by policy (internet-facing, critical criticality)")
    assert host_escalation("P3", False, "critical", rules) == \
        ("P2", "raised P3 -> P2 by policy (critical criticality)")
    assert host_escalation("P3", None, None, rules) == ("P3", "")
    assert host_escalation("P3", True, "critical", validate(None)) == ("P3", "")


def test_due_date_from_sla():
    rules = validate({"sla_days": {"P1+": 7, "P4": 180}})
    assert due_date("P1+", date(2026, 9, 27), rules) == "2026-10-04"
    assert due_date("P2", date(2026, 9, 27), rules) == ""  # no SLA for this priority


# ---------- applied in the worker ----------

def run_worker(monkeypatch, rules, kev=False, cvss=9.8, epss=0.01, public_exploit=False):
    policy.configure(rules)
    nvd = {"cvss_version": "CVSS V31", "cvss_baseScore": cvss, "cvss_severity": "CRITICAL", "cisa_kev": kev,
           "exploit_maturity_attacked": False, "ransomware": "", "cpe": "", "vector": ""}
    monkeypatch.setattr(helpers, "nist_check", lambda *args: nvd)
    monkeypatch.setattr(helpers, "epss_check",
                        lambda *args: {"epss": epss, "percentile": 0.5, "epss_change_7d": None})
    monkeypatch.setattr(helpers, "has_public_exploit", lambda cve_id: public_exploit)
    results = []
    helpers.worker("CVE-2024-0001", 6.0, 0.2, False, Semaphore(), False, 3, save_output=io.StringIO(),
                   results=results)
    return results[0]


def test_policy_can_stop_kev_alone_making_p1_plus(monkeypatch):
    row = run_worker(monkeypatch, validate({"exploitation": {"kev": False}}), kev=True)

    assert row["priority"] == "P2"   # judged on CVSS/EPSS instead
    assert row["kev"] == "TRUE"      # the fact is still reported


def test_public_exploit_minimum_raises_and_explains(monkeypatch):
    rules = validate({"minimum_priority": {"public_exploit": "P1"}, "sla_days": {"P1": 14}})
    row = run_worker(monkeypatch, rules, public_exploit=True)

    assert row["priority"] == "P1"
    assert row["reason"] == ("CVSS 9.8 >= 6 but EPSS 0.01 < 0.2; raised to P1 by policy (public exploit); "
                             "public exploit template (Nuclei)")
    assert row["due_date"] == due_date("P1", policy=rules)


def test_default_policy_changes_nothing(monkeypatch):
    row = run_worker(monkeypatch, None, public_exploit=True)
    assert row["priority"] == "P2"
    assert row["due_date"] == ""


# ---------- applied to the fix order ----------

def test_exposed_p2_outranks_internal_p1_when_policy_says_so():
    policy.configure(validate({"host_escalation": {"internet_facing": 1}, "sla_days": {"P1": 14}}))
    inventory = AssetInventory([
        {"host": "lab", "criticality": "low", "internet_facing": False, "owner": ""},
        {"host": "portal", "criticality": "high", "internet_facing": True, "owner": ""},
    ])
    results = {"CVE-2024-0001": {"cve_id": "CVE-2024-0001", "priority": "P1", "reason": "r"},
               "CVE-2024-0002": {"cve_id": "CVE-2024-0002", "priority": "P2", "reason": "r"}}
    rows = build_fix_order([{"host": "lab", "ip": "", "cve_id": "CVE-2024-0001", "port": ""},
                            {"host": "portal", "ip": "", "cve_id": "CVE-2024-0002", "port": ""}],
                           results, inventory)

    assert [(r["host"], r["priority"], r["finding_priority"]) for r in rows] == [
        ("portal", "P2", "P1"),  # raised for its host: now P1 and internet-facing, so first
        ("lab", "P1", "P1"),
    ]
    assert "raised P2 -> P1 by policy (internet-facing)" in rows[0]["reason"]
    assert rows[0]["due_date"] != ""


# ---------- command line ----------

sys.modules.setdefault("fade", types.SimpleNamespace(greenblue=lambda text: text))


def test_cli_flags_override_policy_thresholds(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from cve_prioritizer import cve_prioritizer as cli

    policy_file = tmp_path / "p.yaml"
    policy_file.write_text("thresholds:\n  cvss: 8.0\n  epss: 0.5\n")
    out = tmp_path / "out.json"

    def meta(*extra):
        result = CliRunner().invoke(cli.main, ["-c", "CVE-2024-0001", "--policy", str(policy_file), "-j", str(out),
                                               *extra], env={"XDG_CACHE_HOME": str(tmp_path / "c")})
        assert result.exit_code == 0, result.output
        return json.loads(out.read_text())["metadata"]

    # Only the metadata matters here: skip the lookups (the worker must still release the semaphore)
    monkeypatch.setattr(cli, "worker", lambda *args: args[4].release())
    monkeypatch.setattr(cli, "prefetch_epss", lambda ids: None)
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)

    from_file = meta()
    assert (from_file["cvss_threshold"], from_file["epss_threshold"]) == (8.0, 0.5)
    assert from_file["policy"]["thresholds"]["cvss"] == 8.0
    overridden = meta("--cvss", "7.5")
    assert (overridden["cvss_threshold"], overridden["epss_threshold"]) == (7.5, 0.5)


def test_cli_rejects_invalid_policy(tmp_path):
    from click.testing import CliRunner

    from cve_prioritizer import cve_prioritizer as cli

    bad = tmp_path / "bad.yaml"
    bad.write_text("thresold:\n  cvss: 7\n")
    result = CliRunner().invoke(cli.main, ["-c", "CVE-2024-0001", "--policy", str(bad)])

    assert result.exit_code == 1
    assert "unknown key(s) in 'policy': thresold" in result.output
