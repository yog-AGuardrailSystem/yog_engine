"""Adapters that put a :class:`~yog_platform.gateway.Gateway` in front of tools used by agent frameworks.

Read this first: an adapter runs **inside the agent's own process**.  It stops honest mistakes and well-behaved
agents, but code in that process can call the tool directly and skip it.  For enforcement the agent must have no
credentials for the tool and reach it only through a gateway or sidecar that holds them (docs/OPERATIONS.md).
Use adapters for development, for shadow mode, and for the convenience of getting the decision and the reason
back to the model.

Every adapter fails closed: a policy error, an unreachable decision point, an approval that has not been granted,
or an obligation that cannot be performed all stop the call.
"""
from .core import ApprovalRequired, PolicyDenied, guard_function, guarded_call

__all__ = ["ApprovalRequired", "PolicyDenied", "guard_function", "guarded_call"]
