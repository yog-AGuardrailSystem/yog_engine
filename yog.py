#!/usr/bin/env python3
"""
YOG v0 -- reference AST-walk interpreter for the YOG policy DSL.

Pipeline:  source -> tokenize -> parse -> check -> solve (backward chaining)

Four statement kinds, deliberately distinct:
    fact   <atom>            ground input data        (BASE predicate)
    rule   <head>: <body>    derived logic            (DERIVED predicate)
    allow  <head>: <body>    policy effect: permit    (DECISION predicate)
    deny   <head>: <body>    policy effect: forbid    (DECISION predicate)
    query  <atom>            ask the engine

Conflict resolution is fixed and deterministic: DENY > ALLOW > default DENY.
v1 is non-recursive by design, so evaluation always terminates.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional

# ============================================================ 1. LEXER

KEYWORDS = {"fact", "rule", "allow", "deny", "query", "not"}
OPS = ("<=", ">=", "==", "!=", "<", ">")          # longest-first: order matters


class YogError(Exception):
    pass


@dataclass
class Tok:
    kind: str          # IDENT VAR STR INT WILD KW OP ( ) , : NEWLINE INDENT DEDENT EOF
    val: Any
    line: int


def tokenize(src: str) -> list[Tok]:
    """Indentation-aware scanner. Only rule/decision bodies are indented,
    so a plain indent stack (no continuation handling) is sufficient."""
    toks: list[Tok] = []
    stack = [0]

    for lineno, raw in enumerate(src.splitlines(), 1):
        if not raw.strip() or raw.strip().startswith("#"):
            continue                                   # blank / comment-only line

        indent = len(raw) - len(raw.lstrip(" "))
        if indent > stack[-1]:
            stack.append(indent)
            toks.append(Tok("INDENT", None, lineno))
        while indent < stack[-1]:
            stack.pop()
            toks.append(Tok("DEDENT", None, lineno))
        if indent != stack[-1]:
            raise YogError(f"line {lineno}: inconsistent indentation")

        i = indent
        while i < len(raw):
            c = raw[i]
            if c == " ":
                i += 1
            elif c == "#":                             # trailing comment
                break
            elif c in "(),:":
                toks.append(Tok(c, c, lineno)); i += 1
            elif c == '"':                             # quoted atom
                j = raw.find('"', i + 1)
                if j < 0:
                    raise YogError(f"line {lineno}: unterminated string")
                toks.append(Tok("STR", raw[i + 1:j], lineno)); i = j + 1
            elif c.isdigit() or (c == "-" and raw[i + 1:i + 2].isdigit()):
                j = i + 1
                while j < len(raw) and raw[j].isdigit():
                    j += 1
                toks.append(Tok("INT", int(raw[i:j]), lineno)); i = j
            elif c.isalpha() or c == "_":
                j = i
                while j < len(raw) and (raw[j].isalnum() or raw[j] in "_."):
                    j += 1
                w = raw[i:j]
                if w == "_":
                    toks.append(Tok("WILD", None, lineno))
                elif w in KEYWORDS:
                    toks.append(Tok("KW", w, lineno))
                elif w[0].isupper():                   # Uppercase => variable
                    toks.append(Tok("VAR", w, lineno))
                else:
                    toks.append(Tok("IDENT", w, lineno))
                i = j
            else:
                op = next((o for o in OPS if raw.startswith(o, i)), None)
                if not op:
                    raise YogError(f"line {lineno}: unexpected character {c!r}")
                toks.append(Tok("OP", op, lineno)); i += len(op)

        toks.append(Tok("NEWLINE", None, lineno))

    while len(stack) > 1:
        stack.pop(); toks.append(Tok("DEDENT", None, lineno))
    toks.append(Tok("EOF", None, lineno + 1 if toks else 1))
    return toks


# ============================================================ 2. AST

@dataclass(frozen=True)
class Var:
    name: str
    def __repr__(self): return self.name


@dataclass(frozen=True)
class Const:
    val: Any
    def __repr__(self): return str(self.val)


@dataclass
class Atom:
    pred: str
    args: list
    line: int = 0
    @property
    def key(self): return (self.pred, len(self.args))
    def __repr__(self): return f"{self.pred}({', '.join(map(repr, self.args))})"


@dataclass
class Neg:
    goal: Atom
    def __repr__(self): return f"not {self.goal!r}"


@dataclass
class Cmp:
    op: str
    lhs: Any
    rhs: Any
    line: int = 0
    def __repr__(self): return f"{self.lhs!r} {self.op} {self.rhs!r}"


@dataclass
class Clause:
    kind: str                 # "rule" | "allow" | "deny"
    head: Atom
    body: list
    line: int = 0


@dataclass
class Program:
    facts: list[Atom] = field(default_factory=list)
    clauses: list[Clause] = field(default_factory=list)
    queries: list[Atom] = field(default_factory=list)


# ============================================================ 3. PARSER (recursive descent)

class Parser:
    def __init__(self, toks): self.t, self.i = toks, 0

    def peek(self, k=0): return self.t[self.i + k]
    def next(self): self.i += 1; return self.t[self.i - 1]

    def eat(self, kind, val=None):
        tok = self.peek()
        if tok.kind != kind or (val is not None and tok.val != val):
            raise YogError(f"line {tok.line}: expected {val or kind}, got {tok.val or tok.kind!r}")
        return self.next()

    def parse(self) -> Program:
        p = Program()
        while self.peek().kind != "EOF":
            kw = self.eat("KW").val
            if kw == "fact":
                a = self.atom(); self.eat("NEWLINE")
                if any(isinstance(x, Var) for x in a.args):
                    raise YogError(f"line {a.line}: facts must be ground (no variables)")
                p.facts.append(a)
            elif kw == "query":
                p.queries.append(self.atom()); self.eat("NEWLINE")
            elif kw in ("rule", "allow", "deny"):
                head = self.atom(); self.eat(":"); self.eat("NEWLINE")
                p.clauses.append(Clause(kw, head, self.body(), head.line))
            else:
                raise YogError(f"line {self.peek().line}: unexpected keyword {kw!r}")
        return p

    def body(self) -> list:
        """INDENT goal+ DEDENT -- every line is a conjunct (implicit AND)."""
        self.eat("INDENT")
        goals = []
        while self.peek().kind != "DEDENT":
            goals.append(self.goal()); self.eat("NEWLINE")
        self.eat("DEDENT")
        if not goals:
            raise YogError("empty rule body")
        return goals

    def goal(self):
        if self.peek().kind == "KW" and self.peek().val == "not":
            self.next(); return Neg(self.atom())
        # lookahead: `Term OP Term` is a comparison, otherwise an atom
        if self.peek().kind in ("VAR", "INT", "STR") and self.peek(1).kind == "OP":
            lhs = self.term(); op = self.eat("OP").val
            return Cmp(op, lhs, self.term(), self.peek(-1).line)
        return self.atom()

    def atom(self) -> Atom:
        tok = self.eat("IDENT"); self.eat("(")
        args = [self.term()]
        while self.peek().kind == ",":
            self.next(); args.append(self.term())
        self.eat(")")
        return Atom(tok.val, args, tok.line)

    _wild = 0
    def term(self):
        tok = self.next()
        if tok.kind == "VAR":  return Var(tok.val)
        if tok.kind == "WILD": Parser._wild += 1; return Var(f"_G{Parser._wild}")
        if tok.kind in ("IDENT", "STR", "INT"): return Const(tok.val)
        raise YogError(f"line {tok.line}: expected a term, got {tok.kind}")


# ============================================================ 4. SEMANTIC CHECKER
# This is what keeps facts / rules / decisions from blurring into each other.

def check_program(p: Program) -> None:
    base = {f.key for f in p.facts}
    derived = {c.head.key for c in p.clauses if c.kind == "rule"}
    decision = {c.head.key for c in p.clauses if c.kind in ("allow", "deny")}

    # C1: a predicate has exactly one role in the program.
    for bad, msg in ((base & derived, "is both a fact and a rule head"),
                     (base & decision, "is both a fact and a decision head"),
                     (derived & decision, "is both a rule and a decision head")):
        if bad:
            k = sorted(bad)[0]
            raise YogError(f"predicate {k[0]}/{k[1]} {msg}; pick one role for it")

    known = base | derived
    for c in p.clauses:
        head_vars = {a.name for a in c.head.args if isinstance(a, Var)}
        # C2: range restriction -- every head variable of a *rule* must be bound
        # by its body. Decision heads are exempt: their args are always supplied
        # ground by yog.check(), so they act as inputs, not outputs.
        if c.kind == "rule":
            bound = set()
            for g in c.body:
                if isinstance(g, Atom):
                    bound |= {a.name for a in g.args if isinstance(a, Var)}
            for a in c.head.args:
                if isinstance(a, Var) and a.name not in bound:
                    raise YogError(f"line {c.line}: variable {a.name} in head of "
                                   f"{c.head.pred} is never bound by the body")
        # C3: safe negation / comparison -- operands must be bound *earlier*.
        seen = set() if c.kind == "rule" else set(head_vars)
        for g in c.body:
            if isinstance(g, Atom):
                seen |= {a.name for a in g.args if isinstance(a, Var)}
            elif isinstance(g, Neg):
                free = {a.name for a in g.goal.args if isinstance(a, Var)} - seen
                if free:
                    raise YogError(f"line {c.line}: unbound variable(s) "
                                   f"{sorted(free)} inside `not`")
            elif isinstance(g, Cmp):
                free = {t.name for t in (g.lhs, g.rhs) if isinstance(t, Var)} - seen
                if free:
                    raise YogError(f"line {c.line}: unbound variable(s) "
                                   f"{sorted(free)} in comparison")
            # C4: no calls to undefined predicates
            tgt = g.goal if isinstance(g, Neg) else g
            if isinstance(tgt, Atom) and tgt.key not in known:
                raise YogError(f"line {c.line}: {tgt.pred}/{len(tgt.args)} is not "
                               f"defined by any fact or rule")

    # C5: rule-dependency graph must be acyclic (v1 forbids recursion => terminates).
    edges = {k: set() for k in derived | decision}
    for c in p.clauses:
        for g in c.body:
            tgt = g.goal if isinstance(g, Neg) else g
            if isinstance(tgt, Atom) and tgt.key in derived:
                edges[c.head.key].add(tgt.key)
    WHITE, GREY, BLACK = 0, 1, 2
    color = {k: WHITE for k in edges}

    def visit(n, path):
        if color[n] == GREY:
            raise YogError("rule cycle: " + " -> ".join(f"{a}/{b}" for a, b in path + [n]))
        if color[n] == BLACK:
            return
        color[n] = GREY
        for m in edges[n]:
            visit(m, path + [n])
        color[n] = BLACK

    for n in list(edges):
        visit(n, [])


# ============================================================ 5. ENGINE (backward chaining)

def walk(t, s):
    """Dereference a term through the substitution chain."""
    while isinstance(t, Var) and t.name in s:
        t = s[t.name]
    return t


def unify(a, b, s: dict) -> Optional[dict]:
    a, b = walk(a, s), walk(b, s)
    if isinstance(a, Var) and isinstance(b, Var) and a.name == b.name:
        return s
    if isinstance(a, Var):
        return {**s, a.name: b}
    if isinstance(b, Var):
        return {**s, b.name: a}
    return s if a.val == b.val else None


def fmt(a: Atom, s: dict) -> str:
    """Render a goal with current bindings applied -- readable explanations."""
    def one(t):
        t = walk(t, s)
        return repr(t) if not isinstance(t, Var) else "?"
    return f"{a.pred}({', '.join(one(x) for x in a.args)})"


class Engine:
    def __init__(self, prog: Program):
        check_program(prog)
        self.facts: dict = {}
        for f in prog.facts:
            self.facts.setdefault(f.key, []).append(f)
        self.rules: dict = {}
        self.decisions: dict = {}
        for c in prog.clauses:
            (self.rules if c.kind == "rule" else self.decisions) \
                .setdefault(c.head.key, []).append(c)
        self.queries = prog.queries
        self._n = 0

    # -- fresh variable names so two uses of a rule don't collide -------------
    def rename(self, clause: Clause) -> Clause:
        self._n += 1
        suf = f"#{self._n}"
        def rt(t): return Var(t.name + suf) if isinstance(t, Var) else t
        def rg(g):
            if isinstance(g, Atom): return Atom(g.pred, [rt(a) for a in g.args], g.line)
            if isinstance(g, Neg):  return Neg(rg(g.goal))
            return Cmp(g.op, rt(g.lhs), rt(g.rhs), g.line)
        return Clause(clause.kind, rg(clause.head), [rg(g) for g in clause.body], clause.line)

    # -- the AST walk --------------------------------------------------------
    def solve(self, goal, s: dict, trace: list, depth: int = 0) -> Iterator[dict]:
        """Yields one substitution per proof of `goal`. Appends to `trace`."""
        pad = "  " * depth

        if isinstance(goal, Cmp):
            l, r = walk(goal.lhs, s), walk(goal.rhs, s)
            ok = {"==": l.val == r.val, "!=": l.val != r.val,
                  "<": l.val < r.val, "<=": l.val <= r.val,
                  ">": l.val > r.val, ">=": l.val >= r.val}[goal.op]
            trace.append(f"{pad}{l!r} {goal.op} {r!r} -> {ok}")
            if ok:
                yield s
            return

        if isinstance(goal, Neg):
            trace.append(f"{pad}not {fmt(goal.goal, s)}")
            inner: list = []
            found = any(True for _ in self.solve(goal.goal, s, inner, depth + 1))
            trace.extend(inner)
            trace.append(f"{pad}-> {not found}")
            if not found:
                yield s
            return

        trace.append(f"{pad}?- {fmt(goal, s)}")

        for f in self.facts.get(goal.key, []):                 # base predicate
            s2 = self.unify_atom(goal, f, s)
            if s2 is not None:
                trace.append(f"{pad}  matched fact {f!r}")
                yield s2

        for clause in self.rules.get(goal.key, []) + self.decisions.get(goal.key, []):
            c = self.rename(clause)
            s2 = self.unify_atom(goal, c.head, s)
            if s2 is None:
                continue
            trace.append(f"{pad}  try {clause.kind} {clause.head!r} (line {clause.line})")
            yield from self.conj(c.body, s2, trace, depth + 1)

    def unify_atom(self, a: Atom, b: Atom, s) -> Optional[dict]:
        if a.key != b.key:
            return None
        for x, y in zip(a.args, b.args):
            s = unify(x, y, s)
            if s is None:
                return None
        return s

    def conj(self, goals: list, s: dict, trace: list, depth: int) -> Iterator[dict]:
        """Conjunction: solve goals left-to-right, backtracking on failure."""
        if not goals:
            yield s
            return
        for s2 in self.solve(goals[0], s, trace, depth):
            yield from self.conj(goals[1:], s2, trace, depth)

    # -- public API ----------------------------------------------------------
    def ask(self, goal: Atom) -> tuple[bool, list, list]:
        trace: list = []
        sols = [{k: walk(Var(k), s) for k in s} for s in self.solve(goal, {}, trace)]
        return bool(sols), sols, trace

    def check(self, actor: str, action: str, resource: str,
              context: Optional[list[Atom]] = None) -> dict:
        """The runtime wrapper. DENY wins; absence of ALLOW is DENY."""
        added = []
        for f in (context or []):                     # per-request facts
            self.facts.setdefault(f.key, []).append(f); added.append(f)
        try:
            goal = Atom(action, [Const(actor), Const(resource)])
            if goal.key not in self.decisions:
                return {"decision": "DENY", "reason":
                        f"no allow/deny clause defines action {action}/2", "trace": []}

            for kind in ("deny", "allow"):
                for clause in [c for c in self.decisions[goal.key] if c.kind == kind]:
                    c = self.rename(clause)
                    s = self.unify_atom(goal, c.head, {})
                    if s is None:
                        continue
                    trace: list = []
                    if any(True for _ in self.conj(c.body, s, trace, 0)):
                        return {"decision": kind.upper(),
                                "reason": f"{kind} clause at line {clause.line} matched",
                                "trace": trace}
            return {"decision": "DENY",
                    "reason": "default deny: no allow clause was satisfied", "trace": []}
        finally:
            for f in added:
                self.facts[f.key].remove(f)


def load_policy(path: str) -> Engine:
    with open(path) as fh:
        return Engine(Parser(tokenize(fh.read())).parse())


# ============================================================ 6. CLI

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: yog.py <policy.yog> [--trace]")
    show_trace = "--trace" in sys.argv
    try:
        eng = load_policy(sys.argv[1])
    except YogError as e:
        sys.exit(f"YOG error: {e}")

    for q in eng.queries:
        ok, sols, trace = eng.ask(q)
        print(f"query {q!r}\n  -> {str(ok).upper()}")
        for s in sols:
            binds = {k: v for k, v in s.items() if "#" not in k and not k.startswith("_G")}
            if binds:
                print("     " + ", ".join(f"{k}={v!r}" for k, v in binds.items()))
        if show_trace:
            print("\n".join("     " + t for t in trace))
        print()

    print("--- yog.check() demo " + "-" * 40)
    for actor, action, res, ctx in [
        ("agent",      "delete",   "database_1", []),
        ("admin_user", "delete",   "database_1", []),
        ("agent",      "deploy",   "database_2", []),
        ("finance_bot", "transfer", "acct_123",  [Atom("amount", [Const("acct_123"), Const(50000)])]),
        ("finance_bot", "transfer", "acct_123",  [Atom("amount", [Const("acct_123"), Const(5000)])]),
    ]:
        r = eng.check(actor, action, res, ctx)
        print(f"{actor} -> {action}({res}): {r['decision']:5}  # {r['reason']}")
        if show_trace and r["trace"]:
            print("\n".join("     " + t for t in r["trace"]))
