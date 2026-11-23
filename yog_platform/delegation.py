"""Delegation chains: who an agent acts for, and what it may do.

The gateway turns a trusted :class:`Principal` into request facts.  The facts come from the gateway, never
from the agent, and a sub-agent's scopes are the *intersection* of every scope along its chain, so delegating
can only narrow authority, never widen it.

Facts emitted (declare them with ``input`` in the policy)::

    acting_for(Agent, User)    the human the chain started from
    delegated(Child, Parent)   one fact per hop
    has_scope(Agent, Scope)    one fact per effective scope
    chain_depth(N)             number of agents in the chain (1 = no delegation)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

MAX_DEPTH = 8
MAX_SCOPES = 64


class DelegationError(Exception):
    pass


@dataclass(frozen=True)
class Principal:
    agent: str
    scopes: frozenset = frozenset()
    on_behalf_of: Optional[str] = None          # the originating user (set on the root of the chain)
    parent: Optional["Principal"] = None

    def delegate(self, agent: str, scopes=()) -> "Principal":
        """A sub-agent.  The scopes it asks for are cut down to what this principal holds."""
        return Principal(agent, frozenset(scopes), None, self)


def chain(principal: Principal) -> list:
    """The principals from the leaf up to the root.  Fails on a cycle or a chain that is too deep."""
    seen, out, node = set(), [], principal
    while node is not None:
        if node.agent in seen:
            raise DelegationError(f"delegation cycle at {node.agent!r}")
        if len(out) >= MAX_DEPTH:
            raise DelegationError(f"delegation chain is deeper than {MAX_DEPTH}")
        if not isinstance(node.agent, str) or not node.agent:
            raise DelegationError("every agent in a chain needs a name")
        seen.add(node.agent)
        out.append(node)
        node = node.parent
    return out


def effective_scopes(principal: Principal) -> frozenset:
    scopes = None
    for node in chain(principal):
        scopes = frozenset(node.scopes) if scopes is None else scopes & frozenset(node.scopes)
    return scopes or frozenset()


def originating_user(principal: Principal) -> Optional[str]:
    return chain(principal)[-1].on_behalf_of


def facts_for(principal: Principal) -> list:
    nodes = chain(principal)
    scopes = sorted(effective_scopes(principal))
    if len(scopes) > MAX_SCOPES:
        raise DelegationError("too many scopes")
    facts = []
    user = nodes[-1].on_behalf_of
    if user is not None:
        facts.append({"predicate": "acting_for", "args": [principal.agent, user]})
    for child, parent in zip(nodes, nodes[1:]):
        facts.append({"predicate": "delegated", "args": [child.agent, parent.agent]})
    facts += [{"predicate": "has_scope", "args": [principal.agent, s]} for s in scopes]
    facts.append({"predicate": "chain_depth", "args": [len(nodes)]})
    return facts
