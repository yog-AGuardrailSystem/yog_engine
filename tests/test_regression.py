
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from yog import Engine, Parser, tokenize


def make_engine(policy):
    program = Parser(tokenize(policy)).parse()
    return Engine(program)


def test_allow_rule_allows_request():
    engine = make_engine("""
allow can_read(User, Resource):
    role(User, reader)
fact role(alice, reader)
""")
    result = engine.check("alice", "can_read", "report")
    assert result["decision"] == "ALLOW"


def test_deny_rule_overrides_allow_rule():
    engine = make_engine("""
allow can_read(User, Resource):
    role(User, reader)
deny can_read(User, Resource):
    role(User, reader)
fact role(alice, reader)
""")
    result = engine.check("alice", "can_read", "report")
    assert result["decision"] == "DENY"


def test_default_deny_when_no_allow_rule_matches():
    engine = make_engine("""
allow can_read(User, Resource):
    role(User, reader)
fact role(alice, reader)
""")
    result = engine.check("bob", "can_read", "report")
    assert result["decision"] == "DENY"
    assert result["reason"] == "default deny: no allow clause was satisfied"


def test_unknown_action_is_denied():
    engine = make_engine("""
allow can_read(User, Resource):
    role(User, reader)
fact role(alice, reader)
""")
    result = engine.check("alice", "can_delete", "report")
    assert result["decision"] == "DENY"
    assert "no allow/deny clause defines action" in result["reason"]
