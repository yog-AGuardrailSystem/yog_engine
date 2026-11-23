"""The command line, the policy test runner, the policy diff and the trace converter."""
import json
from pathlib import Path

import pytest

from yog_platform import cli, testing, trace
from yog_platform.pdp import ReferencePDP

ROOT = Path(__file__).resolve().parents[2]
GATEWAY_POLICY = ROOT / "examples" / "ai_guardrails" / "v2_gateway.yog"
GATEWAY_TESTS = ROOT / "examples" / "ai_guardrails" / "v2_gateway.yogtest"


def run(argv, capsys):
    code = cli.main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


# ------------------------------------------------------------------ policy tests

def test_the_shipped_gateway_tests_pass_and_report_uncovered_clauses():
    report = testing.run_tests(str(GATEWAY_TESTS), ReferencePDP)
    failures = [r for r in report.results if not r.passed]
    assert not failures, failures
    assert len(report.results) == 10
    assert report.uncovered                                   # not every clause is tested: coverage says which
    assert all(isinstance(line, int) for line, _ in report.uncovered)


def test_a_failing_expectation_is_reported(tmp_path):
    policy = tmp_path / "p.yog"
    policy.write_text("input a(text)\nallow act(U, R):\n    a(U)\n", encoding="utf-8")
    spec = tmp_path / "t.yogtest"
    spec.write_text(json.dumps({"policy": "p.yog", "tests": [
        {"name": "wrong", "request": {"actor": "x", "action": "act", "resource": "r",
                                      "facts": [{"predicate": "a", "args": ["x"]}]},
         "expect": {"decision": "DENY"}},
        {"name": "right", "request": {"actor": "x", "action": "act", "resource": "r",
                                      "facts": [{"predicate": "a", "args": ["x"]}]},
         "expect": {"decision": "ALLOW", "reason_contains": "allow clause", "obligations": []}},
        {"name": "bad request is an error", "request": {"actor": 1},
         "expect": {"decision": "DENY"}},
    ]}), encoding="utf-8")
    report = testing.run_tests(str(spec), ReferencePDP)
    assert [r.passed for r in report.results] == [False, True, False]
    assert "expected DENY, got ALLOW" in report.results[0].message
    assert "ERROR" in report.results[2].message


def test_cli_test_command_exit_codes(capsys):
    code, out, _ = run(["test", str(GATEWAY_TESTS)], capsys)
    assert code == 0 and "10/10 passed" in out and "uncovered" in out


# --------------------------------------------------------------------------- diff

def test_diff_shows_only_the_changed_decisions(tmp_path, capsys):
    old = "input a(text)\nallow act(U, R):\n    a(U)\n"
    new = "input a(text)\nallow act(U, R):\n    a(U)\n    obligation audit(1)\nrequire_approval act(U, R):\n    a(\"vip\")\n"
    (tmp_path / "old.yog").write_text(old, encoding="utf-8")
    (tmp_path / "new.yog").write_text(new, encoding="utf-8")
    requests = [
        {"actor": "x", "action": "act", "resource": "r", "facts": [{"predicate": "a", "args": ["x"]}]},       # gains an obligation
        {"actor": "y", "action": "act", "resource": "r", "facts": [{"predicate": "a", "args": ["vip"]}]},     # becomes an approval
        {"actor": "z", "action": "act", "resource": "r"},                                                       # unchanged
    ]
    (tmp_path / "req.json").write_text(json.dumps(requests), encoding="utf-8")
    code, out, err = run(["diff", str(tmp_path / "old.yog"), str(tmp_path / "new.yog"), "--requests",
                          str(tmp_path / "req.json"), "--fail-on-change"], capsys)
    changes = json.loads(out)
    assert code == 1 and "2 of 3" in err
    assert changes[0]["new"]["obligations"] == ["audit"] and changes[0]["old"]["obligations"] == []
    assert changes[1]["old"]["decision"] == "DENY" and changes[1]["new"]["decision"] == "REQUIRE_APPROVAL"


# ---------------------------------------------------------------------------- fmt / analyze

def test_cli_fmt_check_and_write(tmp_path, capsys):
    f = tmp_path / "p.yog"
    f.write_text("fact  a( b )   \n", encoding="utf-8")
    assert run(["fmt", "--check", str(f)], capsys)[0] == 1
    assert f.read_text() == "fact  a( b )   \n"                  # --check never writes
    assert run(["fmt", str(f)], capsys)[0] == 0
    assert f.read_text() == "fact a(b)\n"
    assert run(["fmt", "--check", str(f)], capsys)[0] == 0


def test_cli_analyze_exit_codes(tmp_path, capsys):
    f = tmp_path / "p.yog"
    f.write_text("fact orphan(a)\nfact t(x)\ndeny act(U, R):\n    t(R)\n", encoding="utf-8")
    code, out, _ = run(["analyze", str(f)], capsys)
    assert code == 0 and "A002" in out and "A007" in out
    assert run(["analyze", str(f), "--strict"], capsys)[0] == 1
    f.write_text("input a(text)\nallow act(U, R):\n    a(U)\n    obligation nope(1)\n", encoding="utf-8")
    assert run(["analyze", str(f), "--known-obligations", "audit"], capsys)[0] == 1
    code, out, _ = run(["analyze", str(f), "--json"], capsys)
    assert json.loads(out) == []


# ---------------------------------------------------------------------------- bundles

def test_bundle_keygen_build_verify_round_trip(tmp_path, capsys):
    keys = tmp_path / "keys"
    assert run(["bundle", "keygen", "--out", str(keys), "--key-id", "k1"], capsys)[0] == 0
    policy_dir = tmp_path / "policy"
    (policy_dir / "rules").mkdir(parents=True)
    (policy_dir / "main.yog").write_text('version 2\nimport "rules/a.yog"\nfact x(a)\n', encoding="utf-8")
    (policy_dir / "rules" / "a.yog").write_text("fact y(b)\n", encoding="utf-8")
    out = tmp_path / "bundle.json"
    assert run(["bundle", "build", "--dir", str(policy_dir), "--version", "7", "--key", str(keys / "k1.secret"),
                "--key-id", "k1", "--out", str(out)], capsys)[0] == 0
    code, text, _ = run(["bundle", "verify", str(out), "--pub", f"k1:{keys / 'k1.public'}"], capsys)
    assert code == 0 and "policy_version 7" in text
    # a different key does not verify, and the failure is an exit code, not a traceback
    run(["bundle", "keygen", "--out", str(keys), "--key-id", "k2"], capsys)
    code, _, err = run(["bundle", "verify", str(out), "--pub", f"k1:{keys / 'k2.public'}"], capsys)
    assert code == 2 and "does not verify" in err
    doc = json.loads(out.read_text())
    doc["files"]["main.yog"] += "fact evil(1)\n"
    out.write_text(json.dumps(doc))
    assert run(["bundle", "verify", str(out), "--pub", f"k1:{keys / 'k1.public'}"], capsys)[0] == 2


# ------------------------------------------------------------------------------ trace

def test_trace_to_events():
    text = "?- can_x(a, b)\ntry decision can_x/2 (line 12)\n> ?- role(a, admin)\ntry fact role/2 (line 3)\n-> ALLOW (allow clause at line 12 matched)\n"
    out = trace.to_events(text)
    assert [e["kind"] for e in out["events"]] == ["goal", "try_clause", "goal", "try_clause", "decision"]
    assert out["events"][1] == {"id": 1, "kind": "try_clause", "clause_kind": "decision", "predicate": "can_x/2", "line": 12}
    assert out["events"][4]["decision"] == "ALLOW" and not out["truncated"]
    assert trace.to_events("")["events"] == []


def test_trace_is_capped():
    out = trace.to_events("?- g\n" * (trace.MAX_EVENTS + 5))
    assert len(out["events"]) == trace.MAX_EVENTS and out["truncated"] is True
