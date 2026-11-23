"""Partial evaluation: which tools could ever be allowed?

``possible_tools`` answers, for each tool name, "is there any request for this tool the policy could allow or
send to approval?"  It is a *sound over-approximation*: a tool is reported ``possible: False`` only when that is
certain, so hiding it from an agent's tool list can never hide something the agent was entitled to use.  A tool
reported possible may still be denied for every real request; the gateway enforces on the call regardless.

How: for each ``allow`` / ``require_approval`` clause, the resource is bound to the tool and the clause body is
evaluated as far as the constants allow.  Facts are enumerated, comparisons of known values are decided, and
anything that depends on the request (``arg``, ``env``, ``state``, ``now``, custom inputs, rules, built-ins)
counts as "maybe".  A tool is *never* possible when no such clause survives, or when a ``deny`` clause for it
holds with no "maybe" left (it is denied whatever the request says).

Tool-list filtering is a convenience for the model (fewer irrelevant tools), not a security control.
"""
from __future__ import annotations

import os
import sys
from typing import Iterable, Optional

_REFERENCE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reference")
UNKNOWN = object()


def _ref():
    if _REFERENCE not in sys.path:
        sys.path.insert(0, _REFERENCE)
    import yog_ref
    return yog_ref


def _same(a, b) -> bool:
    return type(a) is type(b) and a == b


def possible_tools(source: str, tools: Iterable[str], *, action: str = "run_tool", actor: Optional[str] = None) -> dict:
    """``{tool: {"possible": bool, "reason": str}}`` for each tool name."""
    ref = _ref()
    program = ref.Parser(ref.tokenize(source)).parse()
    facts: dict = {}
    for fact in program.facts:
        facts.setdefault(fact.key, []).append([a.val for a in fact.args])
    inputs = set(program.inputs) | {("arg", 2), ("env", 2), ("state", 2), ("now", 1), ("state_version", 1)}
    clauses = [c for c in program.clauses if c.kind != "rule" and c.head.pred == action and len(c.head.args) == 2]

    def ground(term, env):
        if isinstance(term, ref.Const):
            return True, term.val
        value = env.get(term.name, UNKNOWN)
        return value is not UNKNOWN, value

    def run(clause, tool):
        """Surviving environments for this clause with the resource bound to ``tool``; each carries a
        ``certain`` flag (no 'maybe' goal was involved)."""
        env: dict = {}
        for term, value in zip(clause.head.args, (actor, tool)):
            if isinstance(term, ref.Const):
                if value is not None and not _same(term.val, value):
                    return []
            elif value is not None:
                env[term.name] = value
            else:
                env[term.name] = UNKNOWN
        states = [(env, True)]
        for goal in clause.body:
            if isinstance(goal, ref.Obl):
                continue
            negated = isinstance(goal, ref.Neg)
            target = goal.goal if negated else goal
            nxt = []
            for env, certain in states:
                nxt.extend(step(target, negated, env, certain))
            states = nxt
            if not states:
                return []
        return states

    def maybe(target, env):
        out = dict(env)
        for term in getattr(target, "args", []):
            if isinstance(term, ref.Var) and term.name not in out:
                out[term.name] = UNKNOWN
        return [(out, False)]

    def step(target, negated, env, certain):
        if isinstance(target, ref.Cmp):
            (lk, lv), (rk, rv) = ground(target.lhs, env), ground(target.rhs, env)
            if lk and rk and not negated:
                try:
                    return [(env, certain)] if ref.compare(target.op, lv, rv) else []
                except ref.YogError:
                    return [(env, False)]                     # an error is not a proof of anything
            return [(env, False)]
        key = target.key
        if key in inputs or ref.is_builtin(key) or key not in facts:
            return [(e, False) for e, _ in maybe(target, env)]
        rows = facts[key]
        if negated:
            values = [ground(t, env) for t in target.args]
            if all(k for k, _ in values):
                hit = any(all(_same(v, x) for (_, v), x in zip(values, row)) for row in rows)
                return [] if hit else [(env, certain)]
            return [(env, False)]
        out = []
        depends = any(isinstance(t, ref.Var) and env.get(t.name) is UNKNOWN for t in target.args)
        certain = certain and not depends             # matching on a value we do not know proves nothing
        for row in rows:
            new_env, keep = dict(env), True
            for term, value in zip(target.args, row):
                if isinstance(term, ref.Const):
                    keep = _same(term.val, value)
                else:
                    current = new_env.get(term.name, None)
                    if current is None:
                        new_env[term.name] = value
                    elif current is not UNKNOWN:
                        keep = _same(current, value)
                if not keep:
                    break
            if keep:
                out.append((new_env, certain))
        return out

    result = {}
    for tool in tools:
        allowing = [c for c in clauses if c.kind in ("allow", "require_approval")]
        if not any(run(c, tool) for c in allowing):
            result[tool] = {"possible": False, "reason": "no allow or require_approval clause can match this tool"}
            continue
        denied = False
        for c in clauses:
            if c.kind == "deny" and any(certain for _, certain in run(c, tool)):
                denied = True
                break
        result[tool] = ({"possible": False, "reason": "a deny clause holds for this tool whatever the request says"}
                        if denied else {"possible": True, "reason": "an allow clause may match"})
    return result


def visible_tools(source: str, tools: Iterable[str], **kwargs) -> list:
    """The subset of ``tools`` that could ever be allowed, in the original order."""
    tools = list(tools)
    verdict = possible_tools(source, tools, **kwargs)
    return [t for t in tools if verdict[t]["possible"]]
