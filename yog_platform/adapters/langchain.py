"""LangChain tools behind a gateway.

``guard_tool(tool, gateway, agent)`` returns a tool with the same name, description and argument schema whose
execution is authorised first.  It works with any object that has ``name``, ``description`` and ``invoke(input)``
(every LangChain ``BaseTool``).  When ``langchain_core`` is installed the result is a real ``StructuredTool`` so it
can be passed to an agent unchanged; otherwise a small stand-in with the same interface is returned.

A denied call does not raise into the agent loop by default: the model receives the refusal as the tool's result
(``on_denied="message"``), which lets it explain or choose another action.  Use ``on_denied="raise"`` to stop the run.
"""
from __future__ import annotations

from typing import Any, Iterable, Optional

from .core import ApprovalRequired, PolicyDenied, guarded_call


def _arguments(tool_input: Any) -> dict:
    if isinstance(tool_input, dict):
        return dict(tool_input)
    return {"input": tool_input}                               # a single-string tool


class GuardedTool:
    """Duck-typed stand-in used when langchain_core is not installed."""

    def __init__(self, tool, gateway, agent: str, on_denied: str = "message"):
        if on_denied not in ("message", "raise"):
            raise ValueError("on_denied must be 'message' or 'raise'")
        self._tool, self._gateway, self._agent, self._on_denied = tool, gateway, agent, on_denied
        self.name = tool.name
        self.description = getattr(tool, "description", "")
        self.args_schema = getattr(tool, "args_schema", None)

    def invoke(self, tool_input: Any, config: Optional[dict] = None, **kwargs) -> Any:
        try:
            return guarded_call(self._gateway, self._agent, self.name, _arguments(tool_input),
                                lambda: self._tool.invoke(tool_input, config, **kwargs) if config is not None
                                else self._tool.invoke(tool_input, **kwargs))
        except ApprovalRequired as exc:
            if self._on_denied == "raise":
                raise
            return f"Approval required before this call can run (approval id {(exc.approval or {}).get('approval_id', 'n/a')})."
        except PolicyDenied as exc:
            if self._on_denied == "raise":
                raise
            return f"Blocked by policy: {exc.reason}"

    run = invoke


def guard_tool(tool, gateway, agent: str, *, on_denied: str = "message"):
    guarded = GuardedTool(tool, gateway, agent, on_denied)
    try:                                                       # pragma: no cover - needs langchain_core
        from langchain_core.tools import StructuredTool
    except ImportError:
        return guarded
    return StructuredTool(name=guarded.name, description=guarded.description or guarded.name,
                          args_schema=guarded.args_schema, func=lambda **kw: guarded.invoke(kw))


def guard_tools(tools: Iterable, gateway, agent: str, *, on_denied: str = "message") -> list:
    return [guard_tool(t, gateway, agent, on_denied=on_denied) for t in tools]
