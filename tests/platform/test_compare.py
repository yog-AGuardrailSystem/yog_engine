"""Bounded policy comparison."""
from yog_platform.compare import compare_policies, permits_subset

OLD = """version 2
input arg(text, any)
input env(text, any)
fact role(alice, admin)
fact role(bob, reader)
deny act(U, R):
    arg("sql", Q)
    contains(Q, "drop")
allow act(U, R):
    role(U, admin)
allow act(U, R):
    role(U, reader)
    arg("n", N)
    N < 5
"""


def test_identical_policies_are_equivalent_and_exhaustive():
    report = compare_policies(OLD, OLD)
    assert report["verdict"] == "equivalent" and report["exhaustive"] is True and report["checked"] > 50
    assert permits_subset(OLD, OLD) == "yes"


def test_a_planted_allow_clause_is_found_with_a_counterexample():
    new = OLD + "allow act(U, R):\n    role(U, reader)\n    arg(\"n\", N)\n    N < 9\n"
    report = compare_policies(OLD, new)
    assert report["verdict"] == "different"
    hit = report["new_permits_more"][0]
    assert hit["old"] == "DENY" and hit["new"] == "ALLOW"
    assert hit["request"]["actor"] == "bob" and 5 <= hit["request"]["args"]["n"] < 9
    assert permits_subset(OLD, new) == "no"


def test_the_reverse_direction_is_a_narrowing_not_a_widening():
    new = OLD + "deny act(U, R):\n    role(U, reader)\n"
    report = compare_policies(OLD, new)
    assert report["new_permits_more_count"] == 0 and report["new_denies_more_count"] > 0
    assert permits_subset(OLD, new) == "yes"


def test_a_changed_obligation_and_an_approval_change_are_reported():
    base = "version 2\ninput arg(text, any)\nallow act(U, R):\n    arg(\"x\", 1)\n"
    with_obligation = base.replace("arg(\"x\", 1)\n", "arg(\"x\", 1)\n    obligation audit(R)\n")
    assert compare_policies(base, with_obligation)["obligation_changes_count"] > 0
    approval = base.replace("allow", "require_approval")
    report = compare_policies(base, approval)
    assert report["approval_changes_count"] > 0 and report["new_permits_more_count"] == 0


def test_capped_runs_never_claim_equivalence():
    new = OLD
    report = compare_policies(OLD, new, limit=10)
    assert report["exhaustive"] is False and report["verdict"] == "inconclusive"
    assert permits_subset(OLD, new, limit=10) == "inconclusive"


def test_custom_inputs_make_the_answer_inconclusive():
    custom = "version 2\ninput has_scope(text, text)\nallow act(U, R):\n    has_scope(U, \"a\")\n"
    assert compare_policies(custom, custom)["verdict"] == "inconclusive"
    extra = [{"actor": "u", "action": "act", "resource": "r", "facts": [{"predicate": "has_scope", "args": ["u", "a"]}]}]
    assert compare_policies(custom, "version 2\ninput has_scope(text, text)\n", extra_requests=extra)["new_denies_more_count"] == 1


def test_the_real_example_policies_compare_cleanly():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2] / "examples"
    text = (root / "claude_code" / "guard.yog").read_text(encoding="utf-8")
    report = compare_policies(text, text, limit=2000)
    assert report["verdict"] in ("equivalent", "inconclusive")


def test_cli_compare_exit_codes(tmp_path, capsys):
    from yog_platform import cli
    old, wider = tmp_path / "old.yog", tmp_path / "new.yog"
    old.write_text(OLD, encoding="utf-8")
    wider.write_text(OLD + "allow act(U, R):\n    role(U, reader)\n    arg(\"n\", N)\n    N < 9\n", encoding="utf-8")
    assert cli.main(["compare", str(old), str(old), "--fail-on-broader"]) == 0
    assert cli.main(["compare", str(old), str(wider), "--fail-on-broader"]) == 1
    assert cli.main(["compare", str(old), str(old), "--limit", "5", "--require-proof"]) == 2
    capsys.readouterr()
    assert cli.main(["compare", str(old), str(wider), "--json"]) == 0
    import json
    assert json.loads(capsys.readouterr().out)["verdict"] == "different"
