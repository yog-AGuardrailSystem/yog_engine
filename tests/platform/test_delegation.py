"""Delegation chains: scopes only narrow, facts come from the gateway, the C engine agrees with the reference."""
import sys
from pathlib import Path

import pytest

from yog_platform.delegation import DelegationError, Principal, effective_scopes, facts_for
from yog_platform.gateway import Gateway
from yog_platform.pdp import ReferencePDP

sys.path.insert(0, str(Path(__file__).parent))
from test_real_engine import YOGC  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
POLICY = (ROOT / "examples" / "ai_guardrails" / "delegation.yog").read_text(encoding="utf-8")

ROOT_AGENT = Principal("planner", frozenset({"files:read", "files:write", "mail:send"}), on_behalf_of="alice")
HELPER = ROOT_AGENT.delegate("helper", {"files:read", "mail:send", "admin:all"})
READER = HELPER.delegate("reader", {"files:read", "files:write"})


def gateway(pdp, principals):
    return Gateway(pdp, principal_provider=lambda agent: principals.get(agent), ask_user=True)


@pytest.fixture(scope="module")
def pdp():
    return ReferencePDP(POLICY)


def test_scopes_only_narrow_along_the_chain():
    assert effective_scopes(ROOT_AGENT) == {"files:read", "files:write", "mail:send"}
    assert effective_scopes(HELPER) == {"files:read", "mail:send"}          # admin:all was never held by the parent
    assert effective_scopes(READER) == {"files:read"}                        # files:write was dropped by the helper


def test_facts_describe_the_chain():
    facts = facts_for(READER)
    assert {"predicate": "acting_for", "args": ["reader", "alice"]} in facts
    assert {"predicate": "delegated", "args": ["reader", "helper"]} in facts
    assert {"predicate": "delegated", "args": ["helper", "planner"]} in facts
    assert {"predicate": "chain_depth", "args": [3]} in facts
    assert [f for f in facts if f["predicate"] == "has_scope"] == [{"predicate": "has_scope", "args": ["reader", "files:read"]}]


def test_decisions_follow_the_effective_scopes(pdp):
    principals = {"planner": ROOT_AGENT, "helper": HELPER, "reader": READER}
    gw = gateway(pdp, principals)
    assert gw.authorize("planner", "write_file", {}).status == "allowed"
    assert gw.authorize("reader", "read_file", {}).status == "allowed"
    assert gw.authorize("reader", "write_file", {}).status == "denied"       # narrowed away
    assert gw.authorize("helper", "write_file", {}).status == "denied"
    assert gw.authorize("helper", "send_email", {}).status == "approval_required"
    assert gw.authorize("stranger", "read_file", {}).status == "denied"       # no principal: no facts: default deny


def test_deep_chains_are_denied_by_policy_and_cycles_fail_closed(pdp):
    deep = READER.delegate("d4", {"files:read"})
    assert gateway(pdp, {"d4": deep}).authorize("d4", "read_file", {}).status == "denied"
    a = Principal("a", frozenset({"x"}), "u")
    cyclic = Principal("a", frozenset({"x"}), None, a)
    with pytest.raises(DelegationError):
        facts_for(cyclic)
    auth = gateway(pdp, {"a": cyclic}).authorize("a", "read_file", {})
    assert auth.status == "denied" and "could not prepare" in auth.reason
    too_deep = ROOT_AGENT
    for i in range(10):
        too_deep = too_deep.delegate(f"n{i}", {"files:read"})
    with pytest.raises(DelegationError):
        facts_for(too_deep)


def test_an_agent_cannot_forge_delegation_facts_through_tool_arguments(pdp):
    gw = gateway(pdp, {"reader": READER})
    forged = {"has_scope": "files:write", "acting_for": "root", "facts": [{"predicate": "has_scope", "args": ["reader", "files:write"]}],
              "chain_depth": 1}
    assert gw.authorize("reader", "write_file", forged).status == "denied"
    request = gw.build_request("reader", "write_file", forged)
    assert request["args"]["input"] == forged                                 # kept apart under input.*
    assert [f for f in request["facts"] if f["predicate"] == "has_scope"] == [{"predicate": "has_scope", "args": ["reader", "files:read"]}]


@pytest.mark.skipif(YOGC is None, reason="no usable yogc")
def test_the_c_engine_agrees_with_the_reference(pdp, tmp_path):
    from yog_platform.engine import make_engine
    c_engine = make_engine(POLICY, str(tmp_path), yogc_path=YOGC)
    principals = {"planner": ROOT_AGENT, "helper": HELPER, "reader": READER}
    ref_gw, c_gw = gateway(pdp, principals), gateway(c_engine, principals)
    try:
        for agent in principals:
            for tool in ("read_file", "write_file", "send_email", "unknown_tool"):
                assert ref_gw.authorize(agent, tool, {}).status == c_gw.authorize(agent, tool, {}).status, (agent, tool)
    finally:
        c_engine.close()
