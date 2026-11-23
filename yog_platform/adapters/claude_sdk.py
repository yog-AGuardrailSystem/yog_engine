"""Claude Agent SDK hooks backed by a gateway.

``make_pre_tool_use_hook`` returns an async hook for ``ClaudeAgentOptions(hooks={"PreToolUse": [HookMatcher(hooks=[...])]})``.
It gives the same answers as the command-line hook in :mod:`yog_platform.claude_hook`:

* ALLOW: ``{}``; the SDK's own permission rules still apply, so the policy never grants more than they do;
* DENY and any error: ``permissionDecision: "deny"`` with the reason;
* REQUIRE_APPROVAL: ``permissionDecision: "ask"``.

The hook needs no SDK import, only the dictionary shapes the SDK documents, so it is easy to test without the SDK.
"""
from __future__ import annotations

from typing import Callable

from .. import claude_hook
from ..gateway import Gateway


def make_pre_tool_use_hook(gateway: Gateway) -> Callable:
    """Build the hook.  Create the gateway with ``tools=claude_hook.TOOLS`` and ``ask_user=True`` to get shell, URL and
    taint handling for Claude Code's built-in tools."""
    async def hook(input_data: dict, tool_use_id=None, context=None) -> dict:
        try:
            output = claude_hook.handle_event(input_data if isinstance(input_data, dict) else {}, gateway)
        except Exception as exc:                              # a broken guard must block, not wave calls through
            return claude_hook._decision(f"YOG guard error: {type(exc).__name__}", "deny")
        return output or {}
    return hook


def default_gateway(pdp, **kwargs) -> Gateway:
    """A gateway set up for Claude Code's built-in tools (shell and URL analysis, context taint, ask-the-user approvals)."""
    kwargs.setdefault("tools", claude_hook.TOOLS)
    kwargs.setdefault("ask_user", True)
    return Gateway(pdp, **kwargs)
