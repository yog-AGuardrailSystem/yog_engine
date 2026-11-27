"""Tests for benchmarks/agent_security/ (stand-ins; optional suites skip if absent)."""
from __future__ import annotations

import importlib.util
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from benchmarks.agent_security.agentdojo_adapter import facts_for_environment  # noqa: E402
from benchmarks.agent_security.evaluate_owasp import evaluate_owasp  # noqa: E402
from benchmarks.agent_security.guard import (  # noqa: E402
    ToolGuard,
    facts_array,
    load_policy,
    sanitize_arguments,
    summarize,
)
from benchmarks.agent_security.injecagent import (  # noqa: E402
    classify_tool,
    default_data_dir,
    facts_for_tool,
    load_tools,
)


def test_sanitize_arguments_handles_floats_nulls_and_nested_lists():
    cleaned = sanitize_arguments({
        "amount": 12.5,
        "note": None,
        "tags": ["a", None, "b"],
        "attachments": [{"file_id": "f1"}, {"file_id": None, "name": "ok"}],
    })
    assert cleaned["amount"] == "12.5"
    assert "note" not in cleaned
    assert cleaned["tags"] == ["a", "b"]
    assert cleaned["attachments"] == {"0": {"file_id": "f1"}, "1": {"name": "ok"}}


def test_facts_array_validates_predicate_and_args():
    assert facts_array([("known_email", ("a@b.com",))]) == [
        {"predicate": "known_email", "args": ["a@b.com"]}
    ]
    with pytest.raises(ValueError):
        facts_array([("BadPred", ("x",))])
    with pytest.raises(ValueError):
        facts_array([("known_email", ())])


def test_facts_for_environment_banking_and_workspace():
    bank_env = {
        "bank_account": {
            "iban": "DE001",
            "transactions": [{"sender": "me", "recipient": "DE002"}],
            "scheduled_transactions": [{"sender": "DE003", "recipient": "me"}],
        }
    }
    bank_facts = facts_for_environment("banking", bank_env)
    assert ("trusted_recipient", ("DE001",)) in bank_facts
    assert ("trusted_recipient", ("DE002",)) in bank_facts
    assert ("trusted_recipient", ("DE003",)) in bank_facts

    ws_env = {
        "inbox": {
            "account_email": "me@corp.test",
            "contact_list": [{"email": "alice@corp.test"}],
            "initial_emails": [{"sender": "bob@corp.test", "recipients": ["me@corp.test"]}],
        },
        "calendar": {"initial_events": [{"participants": ["carol@corp.test"]}]},
        "cloud_drive": {"initial_files": [{"owner": "dave@corp.test", "shared_with": ["erin@corp.test"]}]},
    }
    ws_facts = dict((args[0], pred) for pred, args in facts_for_environment("workspace", ws_env))
    for expected in ("me@corp.test", "alice@corp.test", "bob@corp.test", "carol@corp.test", "dave@corp.test", "erin@corp.test"):
        assert ws_facts.get(expected) == "known_email"


def test_all_benchmark_policies_compile_and_decide():
    for name in (
        "agentdojo_banking",
        "agentdojo_workspace",
        "agentdojo_slack",
        "agentdojo_travel",
        "injecagent_least_privilege",
        "owasp_agentic",
    ):
        guard = ToolGuard(load_policy(name))
        dec = guard.check("unknown_tool", {})
        assert dec.decision in ("ALLOW", "DENY", "REQUIRE_APPROVAL")


def test_owasp_agentic_coverage_suite():
    report = evaluate_owasp()
    assert report["scenarios_passed"] == report["scenarios_total"]
    assert report["attack_interception_rate"] == 1.0
    assert report["benign_utility_rate"] == 1.0


def test_banking_and_injecagent_guard_decisions():
    banking = ToolGuard(load_policy("agentdojo_banking"))
    allow_dec = banking.check(
        "send_money",
        {"recipient": "DE002"},
        facts=[("trusted_recipient", ("DE002",))],
    )
    assert allow_dec.allowed
    blocked_dec = banking.check(
        "send_money",
        {"recipient": "ATTACKER_IBAN"},
        facts=[("trusted_recipient", ("DE002",))],
    )
    assert blocked_dec.blocked

    inj = ToolGuard(load_policy("injecagent_least_privilege"))
    assert inj.check("AmazonGetProductDetails", {}, facts=facts_for_tool("AmazonGetProductDetails")).decision == "ALLOW"
    assert inj.check("AmazonViewSavedAddresses", {}, facts=facts_for_tool("AmazonViewSavedAddresses")).decision == "REQUIRE_APPROVAL"
    assert inj.check("GmailSendEmail", {}, facts=facts_for_tool("GmailSendEmail")).decision == "REQUIRE_APPROVAL"
    assert inj.check("AugustSmartLockGrantGuestAccess", {}, facts=facts_for_tool("AugustSmartLockGrantGuestAccess")).decision == "DENY"
    assert inj.check("TerminalExecute", {}, facts=facts_for_tool("TerminalExecute")).decision == "DENY"

    summary = summarize([allow_dec, blocked_dec])
    assert summary["total"] == 2
    assert summary["allow"] == 1


def test_injecagent_precedence():
    assert classify_tool("TerminalExecute", toolkit="Terminal") == "destructive"
    assert classify_tool("TwitterManagerDeleteTweets", toolkit="TwitterManager") == "destructive"
    assert classify_tool("GmailSendEmail", toolkit="Gmail") == "write"
    assert classify_tool("NortonIdentitySafeSearchPasswords", toolkit="NortonIdentitySafe") == "sensitive_read"
    assert classify_tool("GoogleSearchWebSearch", toolkit="GoogleSearch") == "read"


def test_optional_agentdojo_offline_smoke():
    if importlib.util.find_spec("agentdojo") is None:
        pytest.skip("agentdojo not installed")
    from agentdojo.task_suite.load_suites import get_suite
    from benchmarks.agent_security.evaluate_agentdojo import evaluate_suite

    suite = get_suite("v1", "banking")
    result = evaluate_suite(suite, ToolGuard(load_policy("agentdojo_banking")))
    assert result["interception_rate"] == 1.0


def test_optional_injecagent_offline_smoke():
    tools_path = os.path.join(default_data_dir(), "tools.json")
    if not os.path.exists(tools_path):
        pytest.skip("InjecAgent data not present in %TEMP%\\injecagent")
    catalog = load_tools(tools_path)
    assert len(catalog) > 0
    assert "AugustSmartLockGrantGuestAccess" in catalog
    with open(os.path.join(default_data_dir(), "test_cases_dh_base.json"), encoding="utf-8") as handle:
        cases = json.load(handle)
    assert len(cases) > 0
