"""Formatter and static analysis."""
from pathlib import Path

import pytest

from yog_platform import analysis
from yog_platform.format import format_source, same_meaning

ROOT = Path(__file__).resolve().parents[2]
POLICIES = [ROOT / "examples" / "v2_demo.yog", ROOT / "examples" / "v2_json_demo.yog",
            ROOT / "examples" / "ai_guardrails" / "v2_gateway.yog", ROOT / "all_examples.yog",
            *sorted((ROOT / "examples" / "ai_guardrails").glob("*.yog"))]

MESSY = '''\r
\r
version 2   \r
input arg( text,any )\r
\r
\r
\r
fact  allowed_tool( read_file )   # keep me\r
rule dangerous( Q ) :\r
      arg("q" ,Q)\r
   matches(Q,"a , b ( c )")\r
  Q<=5\r
\r
# a comment between clauses\r
allow run_tool( A,T ):\r
        allowed_tool(T)\r
    obligation audit( "x" ,T )   # trailing\r
'''


def test_formats_messy_source_canonically():
    out = format_source(MESSY)
    assert out == (
        'version 2\n'
        'input arg(text, any)\n'
        '\n'
        'fact allowed_tool(read_file)  # keep me\n'
        'rule dangerous(Q):\n'
        '    arg("q", Q)\n'
        '    matches(Q, "a , b ( c )")\n'
        '    Q <= 5\n'
        '\n'
        '# a comment between clauses\n'
        'allow run_tool(A, T):\n'
        '    allowed_tool(T)\n'
        '    obligation audit("x", T)  # trailing\n')


def test_formatting_is_idempotent_and_keeps_strings_comments_and_meaning():
    once = format_source(MESSY)
    assert format_source(once) == once
    assert "a , b ( c )" in once and "# keep me" in once and "# a comment between clauses" in once


@pytest.mark.parametrize("path", POLICIES, ids=lambda p: p.name)
def test_real_policies_survive_formatting(path):
    source = path.read_text(encoding="utf-8")
    formatted = format_source(source)
    assert format_source(formatted) == formatted                  # idempotent
    assert same_meaning(source, formatted)                        # same program
    assert formatted.count("#") == source.count("#")              # no comment lost


def test_formatter_handles_degenerate_input():
    assert format_source("") == ""
    assert format_source("\n\n  \n") == ""
    assert format_source("fact a(b)") == "fact a(b)\n"


# ------------------------------------------------------------------------- analysis

SOURCE = '''version 2
input arg(text, any)
input unused_input(text)
fact used(a)
fact orphan(b)
rule helper(X):
    used(X)
rule dead(X):
    used(X)

deny act(U, R):
    arg("k", V)
    V == "bad"
allow act(U, R):
    arg("k", V)
    V == "bad"
    used(R)
allow act(U, R):
    used(R)
allow act(U, R):
    used(R)
require_approval act(U, R):
    arg("k", V)
    V == "maybe"
allow act(U, R):
    arg("k", V)
    V == "maybe"
    used(U)

deny only_deny(U, R):
    used(R)
'''


def codes(findings):
    return [(f["code"], f["line"]) for f in findings]


def test_analysis_reports_the_expected_findings():
    found = codes(analysis.analyze(SOURCE))
    assert ("A001", 6) in found and ("A001", 8) in found       # helper and dead are never used
    assert ("A002", 5) in found                                # orphan fact
    assert ("A003", 3) in found                                # unused input
    assert ("A004", 14) in found                               # allow shadowed by the deny
    assert ("A006", 20) in found                               # duplicate allow
    assert ("A005", 25) in found                               # allow shadowed by require_approval
    assert ("A007", 30) in found                               # only_deny can never be allowed


def test_analysis_is_quiet_about_healthy_policies():
    healthy = '''input arg(text, any)
fact tool(a)
deny act(U, R):
    arg("k", "bad")
allow act(U, R):
    tool(R)
'''
    assert analysis.analyze(healthy) == []


def test_unknown_obligations_are_errors_when_requested():
    source = 'input a(text)\nallow act(U, R):\n    a(U)\n    obligation launch_rocket(1)\n    obligation audit(2)\n'
    findings = analysis.analyze(source, known_obligations=["audit"])
    assert [(f["code"], f["severity"]) for f in findings] == [("A008", "error")]


def test_shipped_policies_have_no_unexpected_findings():
    for path in (ROOT / "examples" / "ai_guardrails" / "v2_gateway.yog", ROOT / "examples" / "v2_demo.yog"):
        for finding in analysis.analyze(path.read_text(encoding="utf-8"),
                                        known_obligations=["audit", "rate_limit", "max_output_bytes", "seen_at"]):
            assert finding["severity"] != "error", (path.name, finding)
