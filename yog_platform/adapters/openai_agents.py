"""OpenAI Agents SDK function tools behind a gateway.

The SDK builds a tool's JSON schema from the Python function's signature and docstring, so guard the function
*before* wrapping it with ``function_tool``; ``guard_function`` keeps the signature intact::

    from agents import function_tool
    from yog_platform.adapters.openai_agents import guard

    @function_tool
    @guard(gateway, "support-agent")
    def read_file(path: str) -> str:
        ...

A refusal raises :class:`~yog_platform.adapters.PolicyDenied`; set ``as_text=True`` to return it to the model as the
tool's output instead (the SDK would otherwise report the exception as a tool error).
"""
from __future__ import annotations

import functools
import inspect
from typing import Callable, Optional

from .core import ApprovalRequired, PolicyDenied, guard_function


def guard(gateway, agent: str, *, name: Optional[str] = None, as_text: bool = False):
    """Decorator for a function tool.  See the module docstring."""
    def decorate(func: Callable):
        guarded = guard_function(gateway, agent, func, name=name)
        if not as_text:
            return guarded

        def message(exc: PolicyDenied) -> str:
            if isinstance(exc, ApprovalRequired):
                return f"Approval required before this call can run (approval id {(exc.approval or {}).get('approval_id', 'n/a')})."
            return f"Blocked by policy: {exc.reason}"

        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def awrapper(*args, **kwargs):
                try:
                    return await guarded(*args, **kwargs)
                except PolicyDenied as exc:
                    return message(exc)
            return awrapper

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return guarded(*args, **kwargs)
            except PolicyDenied as exc:
                return message(exc)
        return wrapper
    return decorate
