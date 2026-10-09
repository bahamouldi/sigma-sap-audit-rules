"""Test suite for the SAP Security Audit Log Sigma ruleset.

Three things are checked:

1. Schema validity  - every rule carries the fields Sigma expects, has a valid UUID,
   and its `condition` only references selections that actually exist in the rule.
2. True positives    - every planted attack scenario is detected by the rule that is
   supposed to detect it.
3. False positives   - the high severity rules produce zero matches against a benign
   baseline. The medium correlation rules are expected to match benign traffic, which
   is by design: they exist to isolate events for a correlation layer, not to alert
   on their own. This is asserted explicitly so the intent cannot silently regress.

Run with:  python3 -m pytest -q
"""

from __future__ import annotations

import re
import sys
import uuid
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "sigma" / "rules" / "sap"
sys.path.insert(0, str(ROOT / "tools"))

from run_detections import evaluate_condition, load_rules  # noqa: E402
from sap_log_simulator import generate  # noqa: E402

SEED = 42
BENIGN_EVENTS = 400
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}


@pytest.fixture(scope="module")
def rules():
    return load_rules(RULES_DIR)


@pytest.fixture(scope="module")
def events():
    return generate(SEED, BENIGN_EVENTS)


@pytest.fixture(scope="module")
def benign_only(events):
    """Events whose client_host stays inside the corporate subnet."""
    return [e for e in events if e["client_host"].startswith("10.20.30.")]


# ------------------------------------------------------------------------- 1. schema


def test_rules_are_discovered(rules):
    assert len(rules) == 6, f"expected 6 rules, found {len(rules)}"


@pytest.mark.parametrize("path", sorted(RULES_DIR.glob("*.yml")), ids=lambda p: p.stem)
def test_rule_schema(path):
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))

    for field in ("title", "id", "status", "description", "references", "author",
                  "date", "tags", "logsource", "detection"):
        assert field in doc, f"{path.name}: missing '{field}'"

    uuid.UUID(str(doc["id"]))  # raises if malformed
    assert re.match(r"^\d{4}-\d{2}-\d{2}$", str(doc["date"])), f"{path.name}: bad date"
    assert all(str(t).startswith("attack.") for t in doc["tags"]), \
        f"{path.name}: every tag must be an ATT&CK technique id"

    detection = doc["detection"]
    # Per the Sigma specification level and falsepositives belong to the detection block.
    assert "level" in detection, f"{path.name}: missing detection.level"
    assert detection["level"] in VALID_LEVELS, \
        f"{path.name}: bad level {detection['level']!r}"
    assert "condition" in detection
    condition = str(detection["condition"])

    # Every selection name referenced by the condition must be defined in the rule.
    # Strip any aggregation clause first: "selection | count() by user > 5" references
    # one selection ('selection') and one event field ('user'), and only the former
    # has to be defined in the detection block.
    condition_wo_aggregation = re.sub(r"count\(\)\s*by\s+[\w.]+\s*>\s*\d+", "", condition)
    for name in set(re.findall(r"[a-z_]+", condition_wo_aggregation)):
        if name in {"and", "or", "not", "count", "by"}:
            continue
        assert name in detection, \
            f"{path.name}: condition references undefined selection '{name}'"

    assert detection.get("falsepositives"), f"{path.name}: no falsepositives documented"
    assert doc["description"].strip(), f"{path.name}: empty description"
    assert doc["references"], f"{path.name}: no references"
    assert doc["status"] in {"stable","tested","experimental","deprecated","unsupported"}


def test_no_duplicate_rule_ids(rules):
    ids = [r.uid for r in rules]
    assert len(ids) == len(set(ids)), "duplicate rule UUIDs"


# ---------------------------------------------------------------- 2. true positives


def _hits(rule, events):
    return evaluate_condition(rule, events)


def test_se16n_rule_detects_direct_table_access(rules, events):
    rule = next(r for r in rules if "SE16N" in r.title)
    hits = _hits(rule, events)
    assert len(hits) == 2, f"expected 2 SE16N events, got {len(hits)}"
    assert all(h["tcode"] == "SE16N" for h in hits)


def test_audit_config_rule_detects_monitor_tampering(rules, events):
    rule = next(r for r in rules if "Audit Log Configuration" in r.title)
    hits = _hits(rule, events)
    # One audit_config_change (SM19) plus one transaction_start on SM18.
    assert len(hits) == 2, f"expected 2 audit tampering events, got {len(hits)}"
    assert {h["event_type"] for h in hits} == {"audit_config_change", "transaction_start"}
    assert any(h.get("tcode") == "SM18" for h in hits)


def test_user_master_rule_detects_privilege_escalation(rules, events):
    rule = next(r for r in rules if "User Master" in r.title)
    hits = _hits(rule, events)
    assert any(h["user"] == "SEC_ADMIN" and h["client_host"] == "203.0.113.77" for h in hits), \
        "the external-host user master change should be detected"


def test_role_rule_detects_role_assignment(rules, events):
    rule = next(r for r in rules if "Authorization Role" in r.title)
    hits = _hits(rule, events)
    assert any(h["event_type"] == "role_assignment"
               and h["client_host"] == "203.0.113.77" for h in hits), \
        "the external-host role assignment should be detected"


def test_logon_burst_rule_uses_threshold(rules, events):
    rule = next(r for r in rules if "Unsuccessful Dialog Logon" in r.title)
    hits = _hits(rule, events)
    # 7 planted failures on A.MARTIN from 203.0.113.77 must exceed the threshold of 5.
    assert len([h for h in hits if h["client_host"] == "203.0.113.77"]) == 7, \
        "all 7 planted logon failures should be returned once the threshold trips"
    # Users below the threshold must not appear.
    per_user: dict[str, int] = {}
    for event in events:
        if event["event_type"] == "logon_failure" and event["status"] == "FAIL":
            per_user[event["user"]] = per_user.get(event["user"], 0) + 1
    for hit in hits:
        if hit["user"] in per_user and per_user[hit["user"]] <= 5:
            pytest.fail(f"{hit['user']} has {per_user[hit['user']]} failures, under the threshold")


def test_rfc_rule_detects_remote_privesc(rules, events):
    rule = next(r for r in rules if "Remote Function Module" in r.title)
    hits = _hits(rule, events)
    assert any(h.get("rfc_function") == "SU01_USER_CREATE"
               and h["client_host"] == "203.0.113.77" for h in hits), \
        "RFC call to SU01_USER_CREATE from the external host should be detected"


# --------------------------------------------------------------- 3. false positives


@pytest.mark.parametrize(
    "title_fragment",
    ["SE16N", "Audit Log Configuration"],
    ids=["se16n", "audit_config_change"],
)
def test_high_severity_rules_are_silent_on_benign_traffic(rules, benign_only, title_fragment):
    rule = next(r for r in rules if title_fragment in r.title)
    hits = _hits(rule, benign_only)
    assert hits == [], \
        f"{rule.title} matched {len(hits)} benign events; these rules must be specific"


def test_audit_config_rule_ignores_legitimate_admin_transactions(rules, benign_only):
    """SM51/SM21/SM04 are normal BASIS work and must not trip the audit-tamper rule."""
    rule = next(r for r in rules if "Audit Log Configuration" in r.title)
    hits = _hits(rule, benign_only)
    assert not any(h.get("tcode") in {"SM51", "SM21", "SM04", "ST03N"} for h in hits)


def test_medium_correlation_rules_are_expected_to_match_benign_traffic(rules, benign_only):
    """Documents intent: these rules isolate events, they do not alert on their own."""
    rule = next(r for r in rules if "Remote Function Module" in r.title)
    assert _hits(rule, benign_only), (
        "the RFC rule is a correlation rule and is expected to see legitimate traffic; "
        "if this assertion ever fails the rule has silently become an alerting rule"
    )


def test_simulator_is_deterministic():
    a = generate(SEED, 50)
    b = generate(SEED, 50)
    assert a == b, "simulator must be reproducible for a fixed seed"


def test_simulator_emits_only_documented_event_types(events):
    documented = {
        "logon_success", "logon_failure", "rfc_logon_success", "rfc_logon_failure",
        "rfc_function_module_call", "transaction_start", "transaction_end",
        "report_start", "user_master_change", "role_change", "role_assignment",
        "audit_config_change", "http_session_mgmt_change", "file_download",
    }
    unexpected = {e["event_type"] for e in events} - documented
    assert not unexpected, f"undocumented event types emitted: {unexpected}"