"""Symbolic policy comparison with Z3 (optional: needs the ``z3-solver`` package).

:func:`compare_smt` answers "can the new policy permit a request the old one did not?" for *all* requests, not
only a sampled universe.  It encodes the decision clauses of both policies as one formula over the request
(actor, resource, and the ``arg`` / ``env`` / ``state`` values) and asks the solver for a request where the new
decision is more permissive.

Scope, stated plainly:

* Supported: ``fact`` atoms, ``arg``/``env``/``state`` atoms with a constant key, ``==``, ``!=``, ``<``... on
  integers and strings, ``in``, ``contains``, ``starts_with``, ``ends_with``, ``not``.  Anything else (rules,
  ``matches``, ``glob``, ``under``, ``cidr``, ``now``, custom inputs) raises :class:`Unsupported`; use the
  bounded comparison in ``compare.py`` for those.
* "yes" holds for *well-typed* requests: a value the policy compares with an integer is assumed to be an
  integer, and so on.  An ill-typed request makes the real engine fail closed (DENY), so it is not a way to
  gain access, but it is outside this proof.
* A counterexample is replayed on the reference interpreter before it is reported; if the replay disagrees,
  the answer is "inconclusive", never a false claim.
"""
from __future__ import annotations

import itertools
import os
import sys
from typing import Optional

_REFERENCE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reference")


class Unsupported(Exception):
    """The policy uses something the symbolic encoding does not cover."""


def available() -> bool:
    try:
        import z3  # noqa: F401
        return True
    except ImportError:
        return False


def _ref():
    if _REFERENCE not in sys.path:
        sys.path.insert(0, _REFERENCE)
    import yog_ref
    return yog_ref


class _Symbols:
    """The request variables, shared by both policies so one model describes one request."""

    def __init__(self):
        import z3
        self.z3 = z3
        val = z3.Datatype("Val")
        val.declare("S", ("s", z3.StringSort()))
        val.declare("I", ("i", z3.IntSort()))
        val.declare("B", ("b", z3.BoolSort()))
        self.Val = val.create()
        self.actor = z3.String("actor")
        self.resource = z3.String("resource")
        self.keys: dict = {}                       # (section, key) -> (present, value)
        self.assumptions: list = []

    def key(self, section: str, name: str):
        if (section, name) not in self.keys:
            tag = f"{section}_{len(self.keys)}"
            self.keys[(section, name)] = (self.z3.Bool("p_" + tag), self.z3.Const("v_" + tag, self.Val))
        return self.keys[(section, name)]

    def literal(self, value):
        z3 = self.z3
        if isinstance(value, bool):
            return self.Val.B(z3.BoolVal(value))
        if isinstance(value, int):
            return self.Val.I(z3.IntVal(value))
        if isinstance(value, str):
            return self.Val.S(z3.StringVal(value))
        raise Unsupported(f"unsupported constant {value!r}")


class _Encoder:
    def __init__(self, program, symbols: _Symbols):
        self.ref = _ref()
        self.program = program
        self.sym = symbols
        self.facts: dict = {}
        for fact in program.facts:
            self.facts.setdefault(fact.key, []).append([a.val for a in fact.args])
        for key in program.inputs:
            if key[0] not in ("arg", "env", "state"):
                raise Unsupported(f"custom input {key[0]}/{key[1]}")
        for clause in program.clauses:
            if clause.kind == "rule":
                raise Unsupported(f"rule {clause.head.pred}/{len(clause.head.args)}")

    # a value is (z3 Val expression, presence condition or None)
    def _term(self, term, env):
        if isinstance(term, self.ref.Const):
            return self.sym.literal(term.val), None
        if term.name not in env:
            raise Unsupported(f"variable {term.name} is used before it is bound")
        return env[term.name]

    def _assume_type(self, value, kind: str) -> None:
        expr, present = value
        test = {"int": self.sym.Val.is_I, "text": self.sym.Val.is_S}[kind](expr)
        self.sym.assumptions.append(self.sym.z3.Implies(present, test) if present is not None else test)

    def clause(self, clause):
        z3, ref, sym = self.sym.z3, self.ref, self.sym
        if len(clause.head.args) != 2:
            raise Unsupported("decision heads must have two arguments (actor, resource)")
        env, constraints = {}, []
        for term, symbol in zip(clause.head.args, (sym.actor, sym.resource)):
            if isinstance(term, ref.Var):
                env[term.name] = (sym.Val.S(symbol), None)
            elif isinstance(term.val, str):
                constraints.append(symbol == z3.StringVal(term.val))
            else:
                raise Unsupported("a head constant must be text")
        branches = [(env, constraints)]
        for goal in clause.body:
            if isinstance(goal, ref.Obl):
                continue
            nxt = []
            for env, constraints in branches:
                nxt.extend(self._goal(goal, env, constraints))
            branches = nxt
        return z3.Or([z3.And(c) if c else z3.BoolVal(True) for _, c in branches]) if branches else z3.BoolVal(False)

    def _goal(self, goal, env, constraints):
        z3, ref, sym = self.sym.z3, self.ref, self.sym
        negated = isinstance(goal, ref.Neg)
        target = goal.goal if negated else goal
        if isinstance(target, ref.Cmp):
            if negated:
                raise Unsupported("not over a comparison")
            return [(env, constraints + [self._cmp(target, env)])]
        pred, args = target.pred, target.args
        if pred in ("arg", "env", "state"):
            if len(args) != 2 or not isinstance(args[0], ref.Const) or not isinstance(args[0].val, str):
                raise Unsupported(f"{pred} needs a constant key")
            present, value = sym.key(pred, args[0].val)
            if isinstance(args[1], ref.Var) and args[1].name not in env:
                if negated:
                    return [(env, constraints + [z3.Not(present)])]
                return [({**env, args[1].name: (value, present)}, constraints + [present])]
            other, _ = self._term(args[1], env)
            cond = z3.And(present, value == other)
            return [(env, constraints + [z3.Not(cond) if negated else cond])]
        if pred in ref.BUILTINS:
            if negated:
                raise Unsupported("not over a built-in")
            return [(env, constraints + [self._builtin(pred, args, env)])]
        rows = self.facts.get((pred, len(args)))
        if rows is None:
            raise Unsupported(f"predicate {pred}/{len(args)} is neither a fact nor an input")
        if negated:
            alternatives = []
            for row in rows:
                parts = []
                for term, value in zip(args, row):
                    expr, _ = self._term(term, env)
                    parts.append(expr == sym.literal(value))
                alternatives.append(z3.And(parts) if parts else z3.BoolVal(True))
            return [(env, constraints + [z3.Not(z3.Or(alternatives)) if alternatives else z3.BoolVal(True)])]
        out = []
        for row in rows:
            new_env, extra = dict(env), []
            for term, value in zip(args, row):
                if isinstance(term, ref.Const):
                    if term.val != value or type(term.val) is not type(value):
                        break
                elif term.name in new_env:
                    extra.append(new_env[term.name][0] == sym.literal(value))
                else:
                    new_env[term.name] = (sym.literal(value), None)
            else:
                out.append((new_env, constraints + extra))
        return out

    def _cmp(self, goal, env):
        z3, ref, sym = self.sym.z3, self.ref, self.sym
        left, right = self._term(goal.lhs, env), self._term(goal.rhs, env)
        lc, rc = isinstance(goal.lhs, ref.Const), isinstance(goal.rhs, ref.Const)
        if lc and rc:
            return z3.BoolVal(ref.compare(goal.op, goal.lhs.val, goal.rhs.val))
        if not (lc or rc):
            raise Unsupported("comparison of two variables")
        const = goal.lhs.val if lc else goal.rhs.val
        var = right if lc else left
        if isinstance(const, bool):
            if goal.op not in ("==", "!="):
                raise Unsupported("ordering booleans")
            eq = var[0] == sym.literal(const)
            return eq if goal.op == "==" else z3.Not(eq)
        kind = "int" if isinstance(const, int) else "text"
        self._assume_type(var, kind)
        accessor = sym.Val.i if kind == "int" else sym.Val.s
        a, b = accessor(left[0]) if not lc else (z3.IntVal(const) if kind == "int" else z3.StringVal(const)), \
            accessor(right[0]) if not rc else (z3.IntVal(const) if kind == "int" else z3.StringVal(const))
        return {"==": lambda: a == b, "!=": lambda: a != b, "<": lambda: a < b, "<=": lambda: a <= b,
                ">": lambda: a > b, ">=": lambda: a >= b}[goal.op]()

    def _builtin(self, name, args, env):
        z3, ref, sym = self.sym.z3, self.ref, self.sym
        subject = self._term(args[0], env)
        if name == "in":
            return z3.Or([subject[0] == self._term(a, env)[0] for a in args[1:]])
        if name in ("contains", "starts_with", "ends_with"):
            pattern = args[1]
            if not isinstance(pattern, ref.Const) or not isinstance(pattern.val, str) or isinstance(args[0], ref.Const):
                raise Unsupported(f"{name} needs a variable and a constant string")
            self._assume_type(subject, "text")
            text, lit = sym.Val.s(subject[0]), z3.StringVal(pattern.val)
            return {"contains": z3.Contains(text, lit), "starts_with": z3.PrefixOf(lit, text),
                    "ends_with": z3.SuffixOf(lit, text)}[name]
        raise Unsupported(f"built-in {name}")

    def perm(self, action: str):
        z3 = self.sym.z3
        by_kind = {"deny": [], "require_approval": [], "allow": []}
        for clause in self.program.clauses:
            if clause.head.pred == action:
                by_kind[clause.kind].append(self.clause(clause))
        d, ap, al = (z3.Or(by_kind[k]) if by_kind[k] else z3.BoolVal(False) for k in ("deny", "require_approval", "allow"))
        return z3.If(d, 0, z3.If(ap, 1, z3.If(al, 2, 0)))


def _decode(text: str) -> str:
    import re
    return re.sub(r"\\u\{([0-9a-fA-F]+)\}", lambda m: chr(int(m.group(1), 16)), text)


def _request(model, sym: _Symbols, action: str) -> dict:
    z3 = sym.z3
    request = {"actor": _decode(model.eval(sym.actor, model_completion=True).as_string()),
               "action": action,
               "resource": _decode(model.eval(sym.resource, model_completion=True).as_string())}
    args, env, state = {}, {}, {}
    for (section, name), (present, value) in sym.keys.items():
        if not z3.is_true(model.eval(present, model_completion=True)):
            continue
        v = model.eval(value, model_completion=True)
        kind = v.decl().name()
        child = v.arg(0)
        python = _decode(child.as_string()) if kind == "S" else (child.as_long() if kind == "I" else z3.is_true(child))
        {"arg": args, "env": env, "state": state}[section][name] = python
    if args:
        request["args"] = args
    if env:
        request["env"] = env
    if state:
        request["state"] = {"version": 1, "values": state}
    return request


def compare_smt(old_source: str, new_source: str, *, timeout_ms: int = 20000) -> dict:
    """``{"verdict": "yes"|"no"|"inconclusive", "counterexample": request|None, "reason": str}``.

    ``yes``: for every well-typed request the new policy is never more permissive than the old one.
    ``no``: ``counterexample`` is a request the new policy permits more (replayed on the reference interpreter)."""
    if not available():
        raise Unsupported("the z3-solver package is not installed")
    ref = _ref()
    sym = _Symbols()
    z3 = sym.z3
    old = ref.Parser(ref.tokenize(old_source)).parse()
    new = ref.Parser(ref.tokenize(new_source)).parse()
    old_enc, new_enc = _Encoder(old, sym), _Encoder(new, sym)
    actions = sorted({c.head.pred for p in (old, new) for c in p.clauses if c.kind != "rule"})
    old_engine, new_engine = ref.Engine(old), ref.Engine(new)
    rank = {"DENY": 0, "REQUIRE_APPROVAL": 1, "ALLOW": 2}
    for action in actions:
        solver = z3.Solver()
        solver.set("timeout", timeout_ms)
        before = len(sym.assumptions)
        a, b = old_enc.perm(action), new_enc.perm(action)
        solver.add(sym.assumptions)
        solver.add(b > a)
        outcome = solver.check()
        if outcome == z3.unsat:
            continue
        if outcome == z3.unknown:
            return {"verdict": "inconclusive", "counterexample": None, "reason": f"solver gave up on {action}"}
        request = _request(solver.model(), sym, action)
        ra, rb = ref.check_json(old_engine, request), ref.check_json(new_engine, request)
        if rank.get(rb.get("decision", "DENY"), 0) > rank.get(ra.get("decision", "DENY"), 0):
            return {"verdict": "no", "counterexample": request, "reason": f"{action}: {ra.get('decision')} -> {rb.get('decision')}"}
        return {"verdict": "inconclusive", "counterexample": None,
                "reason": "the solver's counterexample did not reproduce on the reference interpreter"}
    return {"verdict": "yes", "counterexample": None, "reason": "no well-typed request is permitted more by the new policy"}
