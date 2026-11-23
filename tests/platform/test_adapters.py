"""Framework adapters, tested with stand-in tools (no framework needs to be installed)."""
import asyncio
import inspect

import pytest

from yog_platform.adapters import ApprovalRequired, PolicyDenied, guard_function, guarded_call
from yog_platform.adapters.claude_sdk import default_gateway, make_pre_tool_use_hook
from yog_platform.adapters.langchain import GuardedTool, guard_tool, guard_tools
from yog_platform.adapters.openai_agents import guard
from yog_platform.approvals import ApprovalManager
from yog_platform.gateway import Gateway
from yog_platform.pdp import ReferencePDP

POLICY = """version 2
input arg(text, any)
input env(text, any)
allow run_tool(A, "read_file"):
    arg("input.path", P)
    under(P, "/work")
    obligation max_output_bytes(10)
allow run_tool(A, "add"):
    arg("input.a", X)
    X < 100
require_approval run_tool(A, "deploy"):
    true == true
"""


@pytest.fixture()
def gateway():
    return Gateway(ReferencePDP(POLICY), ask_user=True)


def test_guard_function_runs_allowed_calls_and_keeps_the_signature(gateway):
    @guard_function(gateway, "agent")
    def add(a: int, b: int = 1) -> int:
        """Adds."""
        return a + b

    assert add(2) == 3 and add(2, b=5) == 7
    assert add.__name__ == "add" and add.__doc__ == "Adds." and list(inspect.signature(add).parameters) == ["a", "b"]
    with pytest.raises(PolicyDenied):
        add(500)                                                   # the policy only allows a < 100


def test_a_denied_function_is_never_called(gateway):
    calls = []

    @guard_function(gateway, "agent")
    def delete_everything():
        calls.append(1)

    with pytest.raises(PolicyDenied) as info:
        delete_everything()
    assert calls == [] and "default deny" in info.value.reason


def test_a_bad_call_signature_is_refused_not_guessed(gateway):
    @guard_function(gateway, "agent")
    def add(a: int, b: int = 1):
        return a + b

    with pytest.raises(PolicyDenied):
        add()                                                      # missing argument: refused before anything runs


def test_obligations_are_applied_to_the_output(gateway):
    @guard_function(gateway, "agent")
    def read_file(path: str) -> str:
        return "x" * 100

    assert read_file("/work/a").endswith("[truncated by policy]") and len(read_file("/work/a")) < 60
    with pytest.raises(PolicyDenied):
        read_file("/etc/passwd")


def test_approval_required_raises_a_distinct_error(gateway):
    @guard_function(gateway, "agent")
    def deploy():
        raise AssertionError("must not run")

    with pytest.raises(ApprovalRequired):
        deploy()


def test_an_unavailable_decision_point_fails_closed():
    class Down:
        def check(self, request):
            raise RuntimeError("down")
    ran = []
    with pytest.raises(PolicyDenied):
        guarded_call(Gateway(Down()), "a", "t", {}, lambda: ran.append(1))
    assert ran == []


def test_async_functions_are_guarded(gateway):
    @guard_function(gateway, "agent")
    async def add(a: int) -> int:
        return a + 1

    assert asyncio.run(add(1)) == 2
    with pytest.raises(PolicyDenied):
        asyncio.run(add(1000))


# ----------------------------------------------------------------------------------------- LangChain

class FakeTool:
    name, description, args_schema = "read_file", "reads a file", None

    def __init__(self):
        self.calls = []

    def invoke(self, tool_input, config=None, **kwargs):
        self.calls.append(tool_input)
        return "y" * 50


def test_langchain_style_tools_return_the_refusal_as_text_by_default(gateway):
    tool = FakeTool()
    guarded = GuardedTool(tool, gateway, "agent")
    assert guarded.name == "read_file" and guarded.description == "reads a file"
    assert guarded.invoke({"path": "/work/x"}).endswith("[truncated by policy]")
    assert guarded.invoke({"path": "/etc/shadow"}).startswith("Blocked by policy")
    assert tool.calls == [{"path": "/work/x"}]                     # the denied call never reached the tool


def test_langchain_tools_can_raise_instead(gateway):
    guarded = GuardedTool(FakeTool(), gateway, "agent", on_denied="raise")
    with pytest.raises(PolicyDenied):
        guarded.invoke({"path": "/etc/shadow"})
    with pytest.raises(ValueError):
        GuardedTool(FakeTool(), gateway, "agent", on_denied="ignore")


def test_langchain_approval_message_carries_the_approval_id():
    manager = ApprovalManager(b"k" * 32)
    gw = Gateway(ReferencePDP(POLICY), approvals=manager)

    class Deploy(FakeTool):
        name = "deploy"
    out = GuardedTool(Deploy(), gw, "agent").invoke({})
    assert out.startswith("Approval required") and "approval id" in out


def test_guard_tools_wraps_a_list(gateway):
    wrapped = guard_tools([FakeTool()], gateway, "agent")
    assert len(wrapped) == 1 and wrapped[0].name == "read_file"
    assert guard_tool(FakeTool(), gateway, "agent").invoke({"path": "/work/a"})


# ------------------------------------------------------------------------------------ OpenAI Agents

def test_openai_style_decorator_keeps_the_schema_source_and_can_return_text(gateway):
    @guard(gateway, "agent", as_text=True)
    def add(a: int, b: int = 1) -> int:
        """Adds two numbers."""
        return a + b

    assert add(1, 2) == 3
    assert add(1000).startswith("Blocked by policy")
    assert inspect.signature(add).parameters["b"].default == 1 and add.__doc__ == "Adds two numbers."

    @guard(gateway, "agent")
    def other(a: int):
        return a
    with pytest.raises(PolicyDenied):
        other(1000)

    @guard(gateway, "agent", as_text=True, name="add")
    async def aadd(a: int):
        return a + 1
    assert asyncio.run(aadd(1)) == 2 and asyncio.run(aadd(1000)).startswith("Blocked")


# -------------------------------------------------------------------------------------- Claude SDK

def test_claude_sdk_hook_matches_the_command_line_hook():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    pdp = ReferencePDP((root / "examples" / "claude_code" / "guard.yog").read_text(encoding="utf-8"))
    gw = default_gateway(pdp, env={"stage": "dev", "cwd": "/home/dev/project"})
    hook = make_pre_tool_use_hook(gw)

    def run(tool, **tool_input):
        event = {"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": tool, "tool_input": tool_input}
        return asyncio.run(hook(event, "id-1", None))

    assert run("Read", file_path="/home/dev/project/a.py") == {}
    assert run("Bash", command="rm -rf /")["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert run("Bash", command="git push origin main")["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert asyncio.run(hook("not a dict", None, None))["hookSpecificOutput"]["permissionDecision"] == "deny"
