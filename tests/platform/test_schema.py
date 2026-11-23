"""Tool schema: gateway validation and static checks A009-A013."""
import json
from pathlib import Path

import pytest

from yog_platform import analysis
from yog_platform.gateway import Gateway
from yog_platform.pdp import ReferencePDP
from yog_platform.schema import Schema, SchemaError

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = Schema({
    "tools": {"read_file": {"args": {"path": "text", "limit": "int"}, "required": ["path"]},
              "flag": {"args": {"on": "bool"}}},
    "obligations": {"audit": 1},
})


def codes(source, schema=SCHEMA):
    return sorted(f["code"] for f in analysis.analyze(source, schema=schema) if f["code"] >= "A009")


HEAD = "version 2\ninput arg(text, any)\nfact t(read_file)\n"


def test_the_shipped_claude_code_policy_matches_the_shipped_schema():
    schema = Schema.load(str(ROOT / "examples" / "claude_code" / "schema.json"))
    findings = analysis.analyze((ROOT / "examples" / "claude_code" / "guard.yog").read_text(encoding="utf-8"), schema=schema)
    assert [f for f in findings if f["code"] >= "A009"] == []


def test_a_clean_policy_has_no_schema_findings():
    src = HEAD + 'allow run(A, "read_file"):\n    arg("input.path", P)\n    arg("input.limit", L)\n    L < 10\n    obligation audit(P)\n'
    assert codes(src) == []


@pytest.mark.parametrize("body,expected", [
    ('allow run(A, T):\n    T == "nope"\n', ["A009"]),
    ('allow run(A, T):\n    in(T, "read_file", "nope")\n', ["A009"]),
    ('allow run(A, "read_file"):\n    arg("input.bogus", V)\n', ["A010"]),
    ('allow run(A, "flag"):\n    arg("input.path", V)\n', ["A010"]),
    ('allow run(A, "read_file"):\n    arg("input.limit", "ten")\n', ["A011"]),
    ('allow run(A, "read_file"):\n    arg("input.limit", L)\n    L == "x"\n', ["A011"]),
    ('allow run(A, "read_file"):\n    arg("input.limit", L)\n    contains(L, "1")\n', ["A011"]),
    ('allow run(A, "read_file"):\n    obligation nope(1)\n', ["A012"]),
    ('allow run(A, "read_file"):\n    obligation audit(1, 2)\n', ["A012"]),
    ('allow run(A, "ghost"):\n    arg("input.path", P)\n', ["A013"]),
])
def test_each_schema_code_fires(body, expected):
    assert codes(HEAD + body) == expected


def test_gateway_refuses_calls_that_do_not_match_the_schema():
    pdp = ReferencePDP(HEAD + 'allow run_tool(A, T):\n    t(T)\n')
    gw = Gateway(pdp, schema=SCHEMA)
    assert gw.authorize("a", "read_file", {"path": "x"}).status == "allowed"
    for tool, args, why in [("nope", {}, "unknown tool"), ("read_file", {}, "missing required"),
                            ("read_file", {"path": "x", "evil": 1}, "unknown argument"),
                            ("read_file", {"path": 5}, "must be text"), ("read_file", {"path": "x", "limit": True}, "must be int")]:
        auth = gw.authorize("a", tool, args)
        assert auth.status == "denied" and why in auth.reason, (tool, args, auth.reason)


def test_bad_schemas_are_rejected():
    for doc in ([], {"tools": {"t": {"args": {"a": "float"}}}}, {"tools": {"t": {"args": {}, "required": ["x"]}}},
                {"obligations": {"audit": -1}}, {"surprise": 1}):
        with pytest.raises(SchemaError):
            Schema(doc)


def test_cli_analyze_with_schema(tmp_path, capsys):
    from yog_platform import cli
    schema = tmp_path / "s.json"
    schema.write_text(json.dumps({"tools": {"t": {"args": {}}}}), encoding="utf-8")
    policy = tmp_path / "p.yog"
    policy.write_text('version 2\nallow run(A, "ghost"):\n    true == true\n', encoding="utf-8")
    assert cli.main(["analyze", str(policy), "--schema", str(schema)]) == 1
    assert "A013" in capsys.readouterr().out
