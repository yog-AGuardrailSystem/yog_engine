"""Comparing two policies: what does the new one allow that the old one did not?

This is a *bounded* analysis.  It builds a universe of requests from the constants the two policies mention
(plus an "other" value for each dimension and a boundary value for each integer), evaluates both policies on
every request, and reports the differences.  Two outcomes matter:

* a difference is a real, replayable counterexample request;
* "no differences" is a proof only when ``exhaustive`` is true, that is, the whole universe was enumerated and
  the policies use nothing the universe generator cannot see (custom ``input`` predicates, for which you must
  pass ``extra_requests``).  Otherwise the answer is "inconclusive", never "equivalent".

The universe covers: actor, action, resource, ``arg``/``env``/``state`` keys with candidate values (or absent),
``now`` and ``state_version``.  ``regex`` patterns contribute only their literal characters as candidates, so a
policy that depends on a clever regex may need ``extra_requests`` too.
"""
from __future__ import annotations

import itertools
import os
import random
import sys
from typing import Iterable, Optional

_REFERENCE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reference")
OTHER = "~other~"
ABSENT = object()
PERMISSIVENESS = {"DENY": 0, "REQUIRE_APPROVAL": 1, "ALLOW": 2}


def _ref():
    if _REFERENCE not in sys.path:
        sys.path.insert(0, _REFERENCE)
    import yog_ref
    return yog_ref


def _compile(source: str):
    ref = _ref()
    program = ref.Parser(ref.tokenize(source)).parse()
    return program, ref.Engine(program)


class _Universe:
    """Candidate values gathered from one or more programs."""

    def __init__(self):
        self.actions: list = []
        self.actors: list = []
        self.resources: list = []
        self.keys: dict = {}              # (section, key) -> list of candidate values
        self.now: list = []
        self.state_version: list = []
        self.custom_inputs = False
        self.truncated = False

    def _add(self, bucket: list, value) -> None:
        if value not in bucket and not any(value == v and type(value) is type(v) for v in bucket):
            bucket.append(value)

    def key(self, section: str, key: str, value=None) -> None:
        bucket = self.keys.setdefault((section, key), [])
        if value is not None:
            self._add(bucket, value)

    def scan(self, program) -> None:
        ref = _ref()
        for fact in program.facts:
            for arg in fact.args:
                if isinstance(arg, ref.Const) and isinstance(arg.val, str):
                    self._add(self.actors, arg.val)
                    self._add(self.resources, arg.val)
        builtin = set(ref.BUILTINS)
        for (pred, arity) in program.inputs:
            if pred not in ("arg", "env", "state", "state_version", "now"):
                self.custom_inputs = True
        for clause in program.clauses:
            if clause.kind != "rule":
                self._add(self.actions, clause.head.pred)
                for position, target in ((0, self.actors), (1, self.resources)):
                    if len(clause.head.args) > position and isinstance(clause.head.args[position], ref.Const):
                        self._add(target, clause.head.args[position].val)
            bound: dict = {}
            goals = [g.goal if isinstance(g, ref.Neg) else g for g in clause.body if not isinstance(g, ref.Obl)]
            for goal in goals:                                       # first the places that bind a variable
                if not isinstance(goal, ref.Atom):
                    continue
                if goal.pred in ("arg", "env", "state") and len(goal.args) == 2 and isinstance(goal.args[0], ref.Const):
                    key = (goal.pred, str(goal.args[0].val))
                    self.key(*key)
                    if isinstance(goal.args[1], ref.Const):
                        self.key(*key, goal.args[1].val)
                    else:
                        bound[goal.args[1].name] = key
                elif goal.pred in ("now", "state_version") and len(goal.args) == 1:
                    if isinstance(goal.args[0], ref.Const):
                        self._add(self.now if goal.pred == "now" else self.state_version, goal.args[0].val)
                    else:
                        bound[goal.args[0].name] = (goal.pred, "")
                elif goal.pred not in builtin:
                    for arg in goal.args:                            # constants in ordinary predicates: possible actors/resources
                        if isinstance(arg, ref.Const) and isinstance(arg.val, str):
                            self._add(self.actors, arg.val)
                            self._add(self.resources, arg.val)
            for goal in goals:
                if isinstance(goal, ref.Cmp):
                    for var, const in ((goal.lhs, goal.rhs), (goal.rhs, goal.lhs)):
                        if isinstance(var, ref.Var) and var.name in bound and isinstance(const, ref.Const):
                            self._candidates(bound[var.name], const.val)
                elif isinstance(goal, ref.Atom) and goal.pred in builtin and goal.args and isinstance(goal.args[0], ref.Var):
                    target = bound.get(goal.args[0].name)
                    if target is not None:
                        for arg in goal.args[1:]:
                            if isinstance(arg, ref.Const):
                                self._from_builtin(target, goal.pred, arg.val)

    def _candidates(self, target, value) -> None:
        section, key = target
        values = [value]
        if isinstance(value, int) and not isinstance(value, bool):
            values += [value - 1, value + 1]
        for v in values:
            if section in ("now", "state_version"):
                self._add(self.now if section == "now" else self.state_version, v)
            else:
                self.key(section, key, v)

    def _from_builtin(self, target, name: str, value) -> None:
        if not isinstance(value, str):
            self._candidates(target, value)
            return
        if name in ("in",):
            self._candidates(target, value)
        elif name == "contains":
            self._candidates(target, "x" + value + "x")
        elif name == "starts_with":
            self._candidates(target, value + "x")
        elif name == "ends_with":
            self._candidates(target, "x" + value)
        elif name == "glob":
            self._candidates(target, value.replace("*", "x").replace("?", "y"))
        elif name == "under":
            base = value.rstrip("/")
            for candidate in (value, base + "/a", base + "/../b", "/other"):
                self._candidates(target, candidate)
        elif name == "cidr":
            net = value.split("/")[0]
            self._candidates(target, net)
        elif name == "matches":
            literal = "".join(ch for ch in value.replace("(?i)", "") if ch.isalnum() or ch in " _-./:")
            self._candidates(target, literal)
            self._candidates(target, literal.upper())
        else:
            self._candidates(target, value)


def _bounded(values: list, cap: int, universe: _Universe) -> list:
    if len(values) > cap:
        universe.truncated = True
        values = values[:cap]
    return list(values) + [OTHER]


def _requests(universe: _Universe, limit: int, seed: int) -> tuple:
    """Returns (iterator of requests, total size, exhaustive)."""
    actions = universe.actions or ["act"]
    actors = _bounded(universe.actors, 12, universe)
    resources = _bounded(universe.resources, 12, universe)
    dims = []                                                                # (kind, key, [values])
    for (section, key), values in sorted(universe.keys.items()):
        extra = list(values)
        if not any(isinstance(v, str) for v in values):
            extra.append(OTHER)
        if not extra:
            extra = [OTHER, 0, True, False]
        dims.append((section, key, extra + [ABSENT]))
    if universe.now:
        dims.append(("now", "", list(universe.now) + [ABSENT]))
    if universe.state_version:
        dims.append(("state_version", "", list(universe.state_version) + [ABSENT]))
    sizes = [len(actors), len(actions), len(resources)] + [len(d[2]) for d in dims]
    total = 1
    for s in sizes:
        total *= s

    def make(actor, action, resource, picks):
        request = {"actor": actor, "action": action, "resource": resource}
        args, env, state = {}, {}, {}
        for (section, key, _), value in zip(dims, picks):
            if value is ABSENT:
                continue
            if section == "arg":
                args[key] = value
            elif section == "env":
                env[key] = value
            elif section == "state":
                state[key] = value
            elif section == "now":
                request["now"] = value
            else:
                request.setdefault("state", {})["version"] = value
        if args:
            request["args"] = args
        if env:
            request["env"] = env
        if state:
            st = request.setdefault("state", {"version": 1})
            st["values"] = state
        elif "state" in request and "values" not in request["state"]:
            request["state"]["values"] = {}
        if "state" in request and "version" not in request["state"]:
            request["state"]["version"] = 1
        return request

    value_lists = [d[2] for d in dims]
    if total <= limit:
        def gen():
            for actor, action, resource in itertools.product(actors, actions, resources):
                for picks in itertools.product(*value_lists):
                    yield make(actor, action, resource, picks)
        return gen(), total, not universe.truncated and not universe.custom_inputs
    rng = random.Random(seed)

    def sample():
        for _ in range(limit):
            yield make(rng.choice(actors), rng.choice(actions), rng.choice(resources), [rng.choice(v) for v in value_lists])
    return sample(), total, False


def _weight(request: dict) -> int:
    return sum(len(request.get(k, {})) for k in ("args", "env")) + len((request.get("state") or {}).get("values", {})) \
        + ("now" in request)


def compare_policies(old_source: str, new_source: str, *, limit: int = 5000, seed: int = 0,
                     extra_requests: Optional[Iterable[dict]] = None, max_report: int = 20) -> dict:
    """Evaluates both policies over a bounded universe of requests and reports where they differ.

    Returns a dict with ``exhaustive``, ``checked``, ``universe_size``, ``verdict`` (``"equivalent"``,
    ``"different"`` or ``"inconclusive"``) and the lists ``new_permits_more``, ``new_denies_more``,
    ``approval_changes`` and ``obligation_changes`` (each entry: request, old, new), simplest requests first."""
    ref = _ref()
    old_program, old_engine = _compile(old_source)
    new_program, new_engine = _compile(new_source)
    universe = _Universe()
    universe.scan(old_program)
    universe.scan(new_program)
    iterator, total, exhaustive = _requests(universe, limit, seed)
    if extra_requests is not None:
        iterator = itertools.chain(iterator, extra_requests)
    found = {"new_permits_more": [], "new_denies_more": [], "approval_changes": [], "obligation_changes": []}
    checked = 0
    for request in iterator:
        checked += 1
        a, b = ref.check_json(old_engine, request), ref.check_json(new_engine, request)
        # an evaluation error is a fail-closed DENY (a request that confuses the policy is refused)
        da, db = (a.get("decision") or "DENY"), (b.get("decision") or "DENY")
        if da != db:
            wa, wb = PERMISSIVENESS[da], PERMISSIVENESS[db]
            if "REQUIRE_APPROVAL" in (da, db) and "DENY" not in (da, db):
                found["approval_changes"].append((request, da, db))
            elif wb > wa:
                found["new_permits_more"].append((request, da, db))
            else:
                found["new_denies_more"].append((request, da, db))
        else:
            oa = sorted(map(repr, a.get("obligations", [])))
            ob = sorted(map(repr, b.get("obligations", [])))
            if oa != ob:
                found["obligation_changes"].append((request, da, db))
    report: dict = {"exhaustive": exhaustive, "checked": checked, "universe_size": total,
                    "custom_inputs": universe.custom_inputs}
    different = False
    for name, items in found.items():
        items.sort(key=lambda t: (_weight(t[0]), repr(t[0])))
        different = different or bool(items)
        report[name] = [{"request": r, "old": da, "new": db} for r, da, db in items[:max_report]]
        report[name + "_count"] = len(items)
    report["verdict"] = "different" if different else ("equivalent" if report["exhaustive"] else "inconclusive")
    return report


def permits_subset(old_source: str, new_source: str, **kwargs) -> str:
    """"The new policy permits nothing the old one denied."  Returns ``"yes"`` (proven over an exhaustive
    universe), ``"no"`` (a counterexample exists, see :func:`compare_policies`) or ``"inconclusive"``."""
    report = compare_policies(old_source, new_source, **kwargs)
    if report["new_permits_more_count"]:
        return "no"
    return "yes" if report["exhaustive"] else "inconclusive"
