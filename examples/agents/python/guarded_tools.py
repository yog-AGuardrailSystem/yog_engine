"""A guarded tool call in an agent written in Python.

Run it:   python examples/agents/python/guarded_tools.py

The policy below is evaluated by the reference interpreter so the example needs nothing to be built.  With a built
`yogc` swap `ReferencePDP(...)` for `yog_platform.engine.make_engine(...)`.  The three styles show the same gateway
behind a plain function, a LangChain-style tool and the OpenAI Agents SDK; none of them needs the framework installed
to run this file.

Remember: an in-process guard like this can be bypassed by the agent's own code.  For enforcement, give the agent no
credentials for the tools and put the gateway or sidecar between them (docs/OPERATIONS.md).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))

from yog_platform.adapters import ApprovalRequired, PolicyDenied, guard_function  # noqa: E402
from yog_platform.adapters.langchain import GuardedTool  # noqa: E402
from yog_platform.adapters.openai_agents import guard  # noqa: E402
from yog_platform.gateway import Gateway  # noqa: E402
from yog_platform.pdp import ReferencePDP  # noqa: E402

POLICY = """version 2
input arg(text, any)

# reading is allowed inside /work only, and long output is cut
allow run_tool(Agent, "read_file"):
    arg("input.path", P)
    under(P, "/work")
    obligation max_output_bytes(40)

# deleting needs a human
require_approval run_tool(Agent, "delete_file"):
    arg("input.path", P)
    under(P, "/work")

# a table that must never be dropped, whatever the agent says
deny run_tool(Agent, "run_sql"):
    arg("input.query", Q)
    matches(Q, "(?i)drop +table")
allow run_tool(Agent, "run_sql"):
    arg("input.query", Q)
    starts_with(Q, "SELECT")
"""

gateway = Gateway(ReferencePDP(POLICY), ask_user=True)


@guard_function(gateway, "demo-agent")
def read_file(path: str) -> str:
    return "contents of " + path + " " + "." * 60


@guard_function(gateway, "demo-agent")
def delete_file(path: str) -> str:
    return "deleted " + path


@guard(gateway, "demo-agent", as_text=True)
def run_sql(query: str) -> str:
    return "ok: " + query


class FakeLangChainTool:                      # any object with name/description/invoke works
    name, description, args_schema = "read_file", "Reads a file", None

    def invoke(self, tool_input, config=None, **kwargs):
        return "contents of " + tool_input["path"]


def attempt(label, fn):
    try:
        print(f"{label:<34} -> {fn()}")
    except ApprovalRequired as exc:
        print(f"{label:<34} -> NEEDS APPROVAL ({exc.approval and exc.approval.get('approval_id', '')}) {exc.reason}")
    except PolicyDenied as exc:
        print(f"{label:<34} -> DENIED: {exc.reason}")


if __name__ == "__main__":
    attempt("read /work/report.txt", lambda: read_file("/work/report.txt"))
    attempt("read /etc/passwd", lambda: read_file("/etc/passwd"))
    attempt("read /work/../etc/passwd", lambda: read_file("/work/../etc/passwd"))
    attempt("delete /work/old.txt", lambda: delete_file("/work/old.txt"))
    attempt("sql select", lambda: run_sql("SELECT 1"))
    attempt("sql drop table", lambda: run_sql("DROP   TABLE users"))
    tool = GuardedTool(FakeLangChainTool(), gateway, "demo-agent")
    attempt("langchain-style read (allowed)", lambda: tool.invoke({"path": "/work/a"}))
    attempt("langchain-style read (denied)", lambda: tool.invoke({"path": "/root/.ssh/id_rsa"}))
