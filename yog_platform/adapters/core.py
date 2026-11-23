"""Framework-independent building blocks: run a function only if the gateway allows the call."""
from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Optional

from ..gateway import Gateway, Refusal


class PolicyDenied(Exception):
    """The policy refused the call (or something needed to decide failed, which counts as a refusal)."""

    def __init__(self, reason: str, request_hash: str = ""):
        super().__init__(reason)
        self.reason, self.request_hash = reason, request_hash


class ApprovalRequired(PolicyDenied):
    """A human must approve this exact call first.  ``approval`` has the approval id to hand to an approver."""

    def __init__(self, reason: str, approval: Optional[dict], request_hash: str = ""):
        super().__init__(reason, request_hash)
        self.approval = approval


def _apply_after(auth, output: Any) -> Any:
    try:
        for after in auth.after:
            output = after(output)
    except Refusal as exc:
        raise PolicyDenied(str(exc), auth.request_hash) from exc
    except Exception as exc:                                  # an obligation that cannot be applied withholds the output
        raise PolicyDenied(f"output withheld by policy: {type(exc).__name__}", auth.request_hash) from exc
    return output


def guarded_call(gateway: Gateway, agent: str, tool: str, arguments: dict, call: Callable[[], Any],
                 approval_token: Optional[str] = None) -> Any:
    """Asks the gateway about ``tool(arguments)``; runs ``call()`` only when allowed and returns its (possibly
    obligation-processed) result.  Raises :class:`PolicyDenied` or :class:`ApprovalRequired` otherwise."""
    auth = gateway.authorize(agent, tool, arguments, approval_token)
    if auth.status == "approval_required":
        raise ApprovalRequired(auth.reason or "this call needs approval", auth.approval, auth.request_hash)
    if auth.status != "allowed":
        raise PolicyDenied(auth.reason or "denied by policy", auth.request_hash)
    return _apply_after(auth, call())


def guard_function(gateway: Gateway, agent: str, fn: Optional[Callable] = None, *, name: Optional[str] = None):
    """Decorator (or wrapper) for a plain function used as a tool.  The call's keyword and positional arguments are
    bound to the function's parameter names and sent to the policy as the tool arguments; the signature,
    docstring and annotations are kept, so frameworks that read them (function-calling schemas) still work.

        @guard_function(gateway, "agent-1")
        def read_file(path: str) -> str: ...
    """
    def decorate(func: Callable):
        tool = name or func.__name__
        signature = inspect.signature(func)

        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def awrapper(*args, **kwargs):
                arguments = _bind(signature, args, kwargs)
                auth = gateway.authorize(agent, tool, arguments)
                _raise_unless_allowed(auth)
                return _apply_after(auth, await func(*args, **kwargs))
            return awrapper

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            arguments = _bind(signature, args, kwargs)
            return guarded_call(gateway, agent, tool, arguments, lambda: func(*args, **kwargs))
        return wrapper

    return decorate(fn) if fn is not None else decorate


def _bind(signature: inspect.Signature, args: tuple, kwargs: dict) -> dict:
    try:
        bound = signature.bind(*args, **kwargs)
    except TypeError as exc:                                  # the call is malformed: refuse rather than guess
        raise PolicyDenied(f"the call does not match the tool's signature: {exc}") from exc
    bound.apply_defaults()
    return dict(bound.arguments)


def _raise_unless_allowed(auth) -> None:
    if auth.status == "approval_required":
        raise ApprovalRequired(auth.reason or "this call needs approval", auth.approval, auth.request_hash)
    if auth.status != "allowed":
        raise PolicyDenied(auth.reason or "denied by policy", auth.request_hash)
