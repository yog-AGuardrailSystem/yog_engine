"""Partial evaluation: which tools could ever be allowed (sound over-approximation) and tool-list filtering."""
import random
import sys
import threading
from pathlib import Path

import pytest

from yog_platform.gateway import Gateway
from yog_platform.mcp_proxy import McpProxy
from yog_platform.partial_eval import possible_tools, visible_tools
from yog_platform.pdp import ReferencePDP, check_batch

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
from test_gateway import Pipes, rpc  # noqa: E402

POLICY = """version 2
input arg(text, any)
input env(text, any)
fact open_tool("read_file")
fact open_tool("search")
fact banned("rm")
fact banned("search")
fact admin_tool("deploy")
fact role(root, admin)
deny run_tool(A, T):
    banned(T)
deny run_tool(A, "wipe"):
    true == true
allow run_tool(A, T):
    open_tool(T)
allow run_tool(A, T):
    admin_tool(T)
    role(A, admin)
require_approval run_tool(A, "payments"):
    arg("input.amount", N)
    N > 100
allow run_tool(A, "payments"):
    arg("input.amount", N)
    N <= 100
"""


def test_tools_no_clause_can_match_are_hidden():
    verdict = possible_tools(POLICY, ["read_file", "rm", "wipe", "deploy", "payments", "mystery"], actor="root")
    assert verdict["read_file"]["possible"] is True
    assert verdict["payments"]["possible"] is True                   # depends on the request: kept
    assert verdict["deploy"]["possible"] is True                     # root has the role
    assert verdict["mystery"]["possible"] is False                   # no clause names it
    assert verdict["wipe"]["possible"] is False                      # an unconditional deny
    assert verdict["search"]["possible"] is False if "search" in verdict else True


def test_the_actor_changes_the_answer():
    assert possible_tools(POLICY, ["deploy"], actor="root")["deploy"]["possible"] is True
    assert possible_tools(POLICY, ["deploy"], actor="intern")["deploy"]["possible"] is False
    assert possible_tools(POLICY, ["deploy"])["deploy"]["possible"] is True      # unknown actor: keep


def test_banned_tools_are_never_possible_even_if_an_allow_clause_matches():
    assert possible_tools(POLICY, ["search"])["search"] == {"possible": False,
                                                           "reason": "a deny clause holds for this tool whatever the request says"}


def test_visible_tools_keeps_order():
    assert visible_tools(POLICY, ["mystery", "read_file", "payments", "wipe"]) == ["read_file", "payments"]


def test_gateway_visible_tools_needs_the_policy_text_and_never_blocks_calls():
    gw = Gateway(ReferencePDP(POLICY), policy_source=POLICY)
    assert gw.visible_tools("root", ["read_file", "mystery"]) == ["read_file"]
    assert Gateway(ReferencePDP(POLICY)).visible_tools("root", ["read_file", "mystery"]) == ["read_file", "mystery"]
    assert gw.authorize("root", "mystery", {}).status == "denied"             # hidden or not, still enforced


def test_proxy_filters_the_tool_list_but_a_failing_filter_shows_everything():
    pdp = ReferencePDP(POLICY)
    gateway = Gateway(pdp)
    for visible, expect_all in ((lambda names: [n for n in names if n != "shell"], False), (lambda names: 1 / 0, True)):
        pipes = Pipes()
        proxy = McpProxy(gateway, [sys.executable, str(HERE / "mock_mcp_server.py")], "agent-1",
                         read_agent=pipes.read, write_agent=pipes.write, visible=visible)
        threading.Thread(target=proxy.run, daemon=True).start()
        names = [t["name"] for t in rpc(pipes, 1, "tools/list")["result"]["tools"]]
        assert ("shell" in names) == expect_all and len(names) > 1


def test_check_batch_runs_in_order_and_isolates_failures():
    class Flaky:
        def check(self, request):
            if request.get("boom"):
                raise RuntimeError("down")
            return {"decision": "ALLOW", "reason": "", "obligations": []}
    out = check_batch(Flaky(), [{}, {"boom": 1}, {}])
    assert [o["decision"] for o in out] == ["ALLOW", "DENY", "ALLOW"] and "error" in out[1]
    pdp = ReferencePDP(POLICY)
    reqs = [{"actor": "root", "action": "run_tool", "resource": "read_file"}, {"actor": "x", "action": "run_tool", "resource": "nope"}]
    assert [o["decision"] for o in check_batch(pdp, reqs)] == ["ALLOW", "DENY"]


# ------------------------------------------------------------- soundness property

TOOLS = ["t1", "t2", "t3", "t4"]


def random_policy(rng: random.Random) -> str:
    lines = ["version 2", "input arg(text, any)", "input env(text, any)"]
    for fact in ["open", "beta", "gamma", "delta"]:
        for t in rng.sample(TOOLS, rng.randint(1, 3)):
            lines.append(f'fact {fact}("{t}")')
    lines.append('fact role(alice, admin)')
    conditions = ['open(T)', 'beta(T)', 'not gamma(T)', 'delta(T)', 'role(A, admin)', 'not role(A, admin)',
                  'arg("n", N)\n    N > 3', 'arg("n", N)\n    N < 2', 'env("stage", "prod")', 'true == true', 'false == true']
    for _ in range(rng.randint(2, 6)):
        kind = rng.choice(["allow", "allow", "deny", "require_approval"])
        head = rng.choice(["T", '"t1"', '"t2"'])
        body = "\n    ".join(rng.sample(conditions, rng.randint(1, 3))).replace("(T)", f"({head})")
        lines.append(f"{kind} run_tool(A, {head}):\n    {body}")
    return "\n".join(lines) + "\n"


def sample_requests(rng, tool):
    for actor in ("alice", "bob"):
        for n in (None, 0, 3, 4, 9):
            for stage in (None, "prod", "dev"):
                request = {"actor": actor, "action": "run_tool", "resource": tool}
                if n is not None:
                    request["args"] = {"n": n}
                if stage:
                    request["env"] = {"stage": stage}
                yield request


@pytest.mark.parametrize("seed", range(200))
def test_a_hidden_tool_is_never_allowed_for_any_sampled_request(seed):
    rng = random.Random(seed)
    source = random_policy(rng)
    pdp = ReferencePDP(source)
    for actor in ("alice", "bob", None):
        verdict = possible_tools(source, TOOLS, actor=actor)
        for tool in TOOLS:
            if verdict[tool]["possible"]:
                continue
            for request in sample_requests(rng, tool):
                if actor is not None and request["actor"] != actor:
                    continue
                decision = pdp.check(request).get("decision")
                assert decision not in ("ALLOW", "REQUIRE_APPROVAL"), (source, actor, tool, request, decision)
