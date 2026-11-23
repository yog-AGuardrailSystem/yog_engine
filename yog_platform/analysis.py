"""Static analysis of a policy: things that are almost certainly mistakes.

These are heuristics over the syntax tree, not proofs.  Each finding has a stable code so teams can track or
suppress them.

  A001 rule is never used          A002 fact predicate is never used     A003 input is never used
  A004 allow clause is shadowed by a deny clause (every condition of the deny also appears in it)
  A005 allow clause is shadowed by a require_approval clause (same reasoning)
  A006 duplicate clause            A007 action can never be allowed (no allow clause)
  A008 obligation the enforcement point does not implement (only with ``known_obligations``)

With a :class:`~yog_platform.schema.Schema` the analysis also reports (see ``analysis_schema.py``):

  A009 a tool name that is not in the schema is compared with, or tested against, the resource
  A010 ``arg("input.<field>", ...)`` names a field the schema does not declare
  A011 a literal or built-in does not fit the declared type of a field
  A012 an obligation the schema does not list, or with the wrong number of arguments
  A013 the clause is for a tool that is not in the schema, so the gateway never lets it match
"""
from __future__ import annotations

import os
import sys
from typing import Iterable, Optional

_REFERENCE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reference")


def _ref():
    if _REFERENCE not in sys.path:
        sys.path.insert(0, _REFERENCE)
    import yog_ref
    return yog_ref


def _normalise(clause):
    """Head variables become positional placeholders so two clauses for the same action compare equal."""
    ref = _ref()
    mapping = {}
    for i, arg in enumerate(clause.head.args):
        if isinstance(arg, ref.Var) and arg.name not in mapping:
            mapping[arg.name] = f"${i}"

    def term(t):
        if isinstance(t, ref.Var):
            return mapping.get(t.name, t.name)
        return repr(t.val) if not isinstance(t.val, str) else f'"{t.val}"'

    def goal(g):
        if isinstance(g, ref.Atom):
            return f"{g.pred}({','.join(term(a) for a in g.args)})"
        if isinstance(g, ref.Neg):
            return "not " + goal(g.goal)
        if isinstance(g, ref.Obl):
            return None                                   # annotations are not conditions
        return f"{term(g.lhs)} {g.op} {term(g.rhs)}"

    conditions = frozenset(x for x in (goal(g) for g in clause.body) if x is not None)
    obligations = tuple(sorted(f"{g.goal.pred}({','.join(term(a) for a in g.goal.args)})"
                               for g in clause.body if isinstance(g, ref.Obl)))
    head = tuple(term(a) if not isinstance(a, ref.Var) else f"${i}" for i, a in enumerate(clause.head.args))
    return clause.head.pred, head, conditions, obligations


def analyze(source: str, *, known_obligations: Optional[Iterable[str]] = None, schema=None) -> list[dict]:
    ref = _ref()
    program = ref.Parser(ref.tokenize(source)).parse()
    findings: list[dict] = []

    def add(code, line, message, severity="warning"):
        findings.append({"code": code, "severity": severity, "line": line, "message": message})

    used = set()
    for clause in program.clauses:
        for goal in clause.body:
            target = goal.goal if isinstance(goal, (ref.Neg, ref.Obl)) else goal
            if isinstance(target, ref.Atom) and not isinstance(goal, ref.Obl):
                used.add(target.key)
    for clause in program.clauses:
        if clause.kind == "rule" and clause.head.key not in used:
            add("A001", clause.line, f"rule {clause.head.pred}/{len(clause.head.args)} is never used")
    for fact in {f.key: f for f in program.facts}.values():
        if fact.key not in used:
            add("A002", fact.line, f"fact {fact.pred}/{len(fact.args)} is never used")
    for key, (_, line) in program.inputs.items():
        if key not in used:
            add("A003", line, f"input {key[0]}/{key[1]} is never used")

    by_action: dict = {}
    for clause in program.clauses:
        if clause.kind != "rule":
            by_action.setdefault(clause.head.key, []).append(clause)
    for key, clauses in by_action.items():
        normal = [(c, _normalise(c)) for c in clauses]
        seen = {}
        for clause, norm in normal:
            fingerprint = (clause.kind, norm[0], norm[1], norm[2], norm[3])
            if fingerprint in seen:
                add("A006", clause.line, f"{clause.kind} clause duplicates the one at line {seen[fingerprint]}")
            else:
                seen[fingerprint] = clause.line
        for clause, norm in normal:
            if clause.kind != "allow":
                continue
            for other, other_norm in normal:
                if other.kind in ("deny", "require_approval") and other_norm[1] == norm[1] and other_norm[2] <= norm[2]:
                    code = "A004" if other.kind == "deny" else "A005"
                    add(code, clause.line, f"allow clause can never win: the {other.kind} clause at line "
                                           f"{other.line} holds whenever it does")
                    break
        if not any(c.kind == "allow" for c in clauses):
            add("A007", clauses[0].line, f"action {key[0]}/{key[1]} has no allow clause, so it can never be allowed")

    if known_obligations is not None:
        known = set(known_obligations)
        for clause in program.clauses:
            for goal in clause.body:
                if isinstance(goal, ref.Obl) and goal.goal.pred not in known:
                    add("A008", goal.line, f"obligation {goal.goal.pred!r} is not implemented by the enforcement point",
                        "error")
    if schema is not None:
        from .analysis_schema import schema_checks
        schema_checks(ref, program, schema, add)
    return sorted(findings, key=lambda f: (f["line"], f["code"]))
