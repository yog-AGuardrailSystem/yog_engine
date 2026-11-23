#!/usr/bin/env python3
"""
YOG reference AST-walk interpreter for the YOG policy DSL (language versions 1 and 2).

Pipeline:  source -> tokenize -> parse -> check -> solve (backward chaining)

Statement kinds, deliberately distinct:
    version N                language version the policy was written for (first statement)
    input  <name>(types)     data supplied with each request, typed text/int/bool/any
    fact   <atom>            ground data in the policy        (BASE predicate)
    rule   <head>: <body>    derived logic                    (DERIVED predicate)
    allow  <head>: <body>    policy effect: permit            (DECISION predicate)
    deny   <head>: <body>    policy effect: forbid            (DECISION predicate)
    require_approval <head>: <body>   permit only after approval (DECISION predicate)
    query  <atom>            ask the engine

A body line `obligation name(args)` inside an allow or require_approval clause is
not a condition: it is returned with the decision when that clause wins.

Conflict resolution is fixed and deterministic:
    DENY > REQUIRE_APPROVAL > ALLOW > default DENY.
The language is non-recursive by design, so evaluation always terminates.

This file is the behavioural reference for the C engine in ``yog/``.  It
implements the built-in predicates independently (a set-based NFA for regular
expressions, its own glob, path and CIDR logic) so that the differential tests
compare two separate implementations.  It works on UTF-8 bytes for the
built-ins, like the C engine.
"""
from __future__ import annotations

import json
import re
import re as _re
import sys
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional

# ============================================================ 1. LEXER

KEYWORDS = {"fact", "rule", "allow", "deny", "query", "not",
            "require_approval", "obligation", "input", "version"}
OPS = ("<=", ">=", "==", "!=", "<", ">")          # longest-first: order matters
SUPPORTED_LANGUAGE_VERSION = 2


class YogError(Exception):
    pass


@dataclass
class Tok:
    kind: str          # IDENT VAR STR INT BOOL WILD KW OP ( ) , : NEWLINE INDENT DEDENT EOF
    val: Any
    line: int


def tokenize(src: str) -> list[Tok]:
    """Indentation-aware scanner. Only rule/decision bodies are indented,
    so a plain indent stack (no continuation handling) is sufficient."""
    toks: list[Tok] = []
    stack = [0]
    lineno = 0

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
                elif w in ("true", "false"):
                    toks.append(Tok("BOOL", w == "true", lineno))
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
    val: Any          # str, int or bool -- compared by type AND value
    def __repr__(self):
        if isinstance(self.val, bool):
            return "true" if self.val else "false"
        return str(self.val)


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
class Obl:
    """`obligation name(args)`: an annotation, never a condition."""
    goal: Atom
    line: int = 0
    def __repr__(self): return f"obligation {self.goal!r}"


@dataclass
class Clause:
    kind: str                 # "rule" | "allow" | "deny" | "require_approval"
    head: Atom
    body: list
    line: int = 0


@dataclass
class Program:
    facts: list[Atom] = field(default_factory=list)
    clauses: list[Clause] = field(default_factory=list)
    queries: list[Atom] = field(default_factory=list)
    inputs: dict = field(default_factory=dict)       # key -> (types tuple, line)
    version: int = 1


def same_value(a: Any, b: Any) -> bool:
    """Equality that never lets True == 1 or 1 == "1"."""
    return type(a) is type(b) and a == b


# ============================================================ 3. PARSER (recursive descent)

INPUT_TYPES = ("text", "int", "bool", "any")


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
        count = 0
        while self.peek().kind != "EOF":
            kw_tok = self.eat("KW")
            kw = kw_tok.val
            if kw == "version":
                num = self.eat("INT"); self.eat("NEWLINE")
                if count != 0:
                    raise YogError(f"line {kw_tok.line}: version must be the first statement of the policy")
                if num.val < 1 or num.val > SUPPORTED_LANGUAGE_VERSION:
                    raise YogError(f"line {kw_tok.line}: policy requires language version {num.val}; "
                                   f"this engine supports 1 to {SUPPORTED_LANGUAGE_VERSION}")
                p.version = num.val
            elif kw == "fact":
                a = self.atom(); self.eat("NEWLINE")
                if any(isinstance(x, Var) for x in a.args):
                    raise YogError(f"line {a.line}: facts must be ground (no variables)")
                p.facts.append(a)
            elif kw == "input":
                a = self.atom(); self.eat("NEWLINE")
                types = []
                for x in a.args:
                    if not (isinstance(x, Const) and isinstance(x.val, str) and x.val in INPUT_TYPES):
                        raise YogError(f"line {a.line}: unknown input type in {a.pred}/{len(a.args)} "
                                       f"(use text, int, bool or any)")
                    types.append(x.val)
                if a.key in p.inputs:
                    raise YogError(f"line {a.line}: input {a.pred}/{len(a.args)} is declared twice")
                p.inputs[a.key] = (tuple(types), a.line)
            elif kw == "query":
                p.queries.append(self.atom()); self.eat("NEWLINE")
            elif kw in ("rule", "allow", "deny", "require_approval"):
                head = self.atom(); self.eat(":"); self.eat("NEWLINE")
                p.clauses.append(Clause(kw, head, self.body(), head.line))
            else:
                raise YogError(f"line {kw_tok.line}: unexpected keyword {kw!r}")
            count += 1
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
        tok = self.peek()
        if tok.kind == "KW" and tok.val == "not":
            self.next(); return Neg(self.atom())
        if tok.kind == "KW" and tok.val == "obligation":
            self.next(); return Obl(self.atom(), tok.line)
        # lookahead: `Term OP Term` is a comparison, otherwise an atom
        if tok.kind in ("VAR", "INT", "STR", "BOOL") and self.peek(1).kind == "OP":
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
        if tok.kind in ("IDENT", "STR", "INT", "BOOL"): return Const(tok.val)
        raise YogError(f"line {tok.line}: expected a term, got {tok.kind}")


# ============================================================ 4. BUILT-IN PREDICATES
# Independent implementations (see the module docstring).  Every error here is an
# evaluation error: the C engine reports it and the caller must treat it as DENY.

BUILTINS = {                       # name -> (min arity, max arity or None for variadic)
    "in": (2, None), "matches": (2, 2), "glob": (2, 2), "under": (2, 2),
    "starts_with": (2, 2), "ends_with": (2, 2), "contains": (2, 2), "cidr": (2, 2),
}
MAX_PATTERN = 256
MAX_TEXT = 4096
MAX_PATH_SEGMENTS = 128


def is_builtin(key) -> bool:
    name, n = key
    if name not in BUILTINS:
        return False
    lo, hi = BUILTINS[name]
    return n >= lo and (hi is None or n <= hi)


def _bytes(value: str) -> bytes:
    return value.encode("utf-8")


# ---- regular expressions: parse to a small AST, match with sets of positions

class _ReError(YogError):
    pass


class _RegexParser:
    def __init__(self, pattern: bytes):
        self.p = pattern
        self.pos = 0
        self.icase = False
        self.depth = 0
        if pattern.startswith(b"(?i)"):
            self.icase = True
            self.pos = 4

    def fail(self, message):
        raise _ReError(f"matches: invalid pattern ({message})")

    def parse(self):
        node = self.alt()
        if self.pos < len(self.p):
            self.fail("unmatched ')'")
        return node

    def alt(self):
        left = self.cat()
        while self.pos < len(self.p) and self.p[self.pos:self.pos + 1] == b"|":
            self.pos += 1
            left = ("alt", left, self.cat())
        return left

    def cat(self):
        left = None
        while self.pos < len(self.p) and self.p[self.pos:self.pos + 1] not in (b"|", b")"):
            nxt = self.repeat()
            left = nxt if left is None else ("cat", left, nxt)
        return ("empty",) if left is None else left

    def repeat(self):
        atom = self.atom()
        if self.pos < len(self.p) and self.p[self.pos:self.pos + 1] in (b"*", b"+", b"?"):
            q = self.p[self.pos:self.pos + 1]
            self.pos += 1
            atom = ({b"*": "star", b"+": "plus", b"?": "quest"}[q], atom)
            if self.pos < len(self.p) and self.p[self.pos:self.pos + 1] in (b"*", b"+", b"?"):
                self.fail("nested quantifiers are not supported")
        return atom

    def lit(self, ch: int):
        if self.icase and (65 <= ch <= 90 or 97 <= ch <= 122):
            return ("class", frozenset({ch, ch ^ 0x20}))
        return ("char", ch)

    def atom(self):
        c = self.p[self.pos]
        self.pos += 1
        if c == 0x28:                                   # (
            self.depth += 1
            if self.depth > 32:
                self.fail("groups are nested too deeply")
            inner = self.alt()
            if self.pos >= len(self.p) or self.p[self.pos] != 0x29:
                self.fail("missing ')'")
            self.pos += 1
            self.depth -= 1
            return inner
        if c == 0x5B:                                   # [
            return self.char_class()
        if c == 0x2E: return ("any",)
        if c == 0x5E: return ("bol",)
        if c == 0x24: return ("eol",)
        if c == 0x5C: return self.escape()
        if c in (0x2A, 0x2B, 0x3F):
            self.fail("nothing to repeat")
        return self.lit(c)

    @staticmethod
    def _escape_set(letter: int):
        if letter == 0x64: return set(range(0x30, 0x3A))                       # \d
        if letter == 0x77:                                                      # \w
            return set(range(0x30, 0x3A)) | set(range(0x61, 0x7B)) | set(range(0x41, 0x5B)) | {0x5F}
        if letter == 0x73: return {0x20, 0x09, 0x0A, 0x0D, 0x0C, 0x0B}         # \s
        return None

    def escape(self):
        if self.pos >= len(self.p):
            self.fail("pattern ends with a backslash")
        letter = self.p[self.pos]
        self.pos += 1
        base = self._escape_set(letter)
        if base is not None:
            return ("class", frozenset(base))
        if letter in (0x44, 0x57, 0x53):                # \D \W \S
            return ("class", frozenset(set(range(256)) - self._escape_set(letter + 0x20)))
        if letter == 0x6E: return self.lit(0x0A)
        if letter == 0x74: return self.lit(0x09)
        if letter == 0x72: return self.lit(0x0D)
        return self.lit(letter)

    def char_class(self):
        negate = False
        members: set[int] = set()
        any_member = False
        if self.pos < len(self.p) and self.p[self.pos] == 0x5E:
            negate = True
            self.pos += 1

        def add(lo, hi):
            for v in range(lo, hi + 1):
                members.add(v)
                if self.icase and (65 <= v <= 90 or 97 <= v <= 122):
                    members.add(v ^ 0x20)

        while self.pos < len(self.p) and self.p[self.pos] != 0x5D:
            lo = self.p[self.pos]
            self.pos += 1
            if lo == 0x5C:
                if self.pos >= len(self.p):
                    self.fail("unterminated character class")
                letter = self.p[self.pos]
                self.pos += 1
                base = self._escape_set(letter)
                if base is not None:
                    members |= base
                    any_member = True
                    continue
                lo = {0x6E: 0x0A, 0x74: 0x09, 0x72: 0x0D}.get(letter, letter)
            if self.pos + 1 < len(self.p) and self.p[self.pos] == 0x2D and self.p[self.pos + 1] != 0x5D:
                hi = self.p[self.pos + 1]
                self.pos += 2
                if hi < lo:
                    self.fail("character range is reversed")
                add(lo, hi)
            else:
                add(lo, lo)
            any_member = True
        if self.pos >= len(self.p):
            self.fail("unterminated character class")
        self.pos += 1
        if not any_member:
            self.fail("empty character class")
        if negate:
            members = set(range(256)) - members
        return ("class", frozenset(members))


def _re_step(node, text: bytes, positions: set) -> set:
    n = len(text)
    kind = node[0]
    if kind == "empty":
        return positions
    if kind == "char":
        return {p + 1 for p in positions if p < n and text[p] == node[1]}
    if kind == "any":
        return {p + 1 for p in positions if p < n}
    if kind == "class":
        return {p + 1 for p in positions if p < n and text[p] in node[1]}
    if kind == "bol":
        return {p for p in positions if p == 0}
    if kind == "eol":
        return {p for p in positions if p == n}
    if kind == "cat":
        return _re_step(node[2], text, _re_step(node[1], text, positions))
    if kind == "alt":
        return _re_step(node[1], text, positions) | _re_step(node[2], text, positions)
    if kind == "quest":
        return positions | _re_step(node[1], text, positions)
    if kind in ("star", "plus"):
        reached = set(positions) if kind == "star" else _re_step(node[1], text, positions)
        frontier = set(reached)
        while frontier:
            fresh = _re_step(node[1], text, frontier) - reached
            reached |= fresh
            frontier = fresh
        return reached
    raise YogError("matches: internal error")


def _matches(text: str, pattern: str) -> bool:
    t, p = _bytes(text), _bytes(pattern)
    if len(p) > MAX_PATTERN:
        raise YogError(f"matches: pattern is longer than {MAX_PATTERN} bytes")
    if len(t) > MAX_TEXT:
        raise YogError(f"matches: text is longer than {MAX_TEXT} bytes")
    root = _RegexParser(p).parse()
    return any(_re_step(root, t, {start}) for start in range(len(t) + 1))


# ---- glob, path and CIDR

def _glob(text: str, pattern: str) -> bool:
    t, p = _bytes(text), _bytes(pattern)
    if len(t) > MAX_TEXT or len(p) > MAX_PATTERN:
        raise YogError("glob: input is over the size limit")
    from functools import lru_cache

    @lru_cache(maxsize=None)
    def go(i: int, j: int) -> bool:
        if j == len(p):
            return i == len(t)
        if p[j] == 0x2A:                                # *
            return any(go(k, j + 1) for k in range(i, len(t) + 1))
        if i < len(t) and (p[j] == 0x3F or p[j] == t[i]):
            return go(i + 1, j + 1)
        return False
    return go(0, 0)


def _normalise(path: str):
    raw = _bytes(path)
    absolute = raw.startswith(b"/")
    segs: list[bytes] = []
    for part in raw.split(b"/"):
        if part in (b"", b"."):
            continue
        if part == b"..":
            if segs and segs[-1] != b"..":
                segs.pop()
            elif not absolute:
                segs.append(b"..")
            continue
        segs.append(part)
        if len(segs) > MAX_PATH_SEGMENTS:
            raise YogError(f"under: path has more than {MAX_PATH_SEGMENTS} segments")
    return absolute, segs


def _under(path: str, prefix: str) -> bool:
    if len(_bytes(path)) > MAX_TEXT or len(_bytes(prefix)) > MAX_TEXT:
        raise YogError(f"under: path is longer than {MAX_TEXT} bytes")
    pa, ps = _normalise(path)
    qa, qs = _normalise(prefix)
    return pa == qa and len(qs) <= len(ps) and ps[:len(qs)] == qs


_IPV4 = _re.compile(r"(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}\Z", _re.ASCII)


def _ipv4(text: str) -> Optional[int]:
    if not _IPV4.match(text):
        return None
    parts = [int(x) for x in text.split(".")]
    if any(x > 255 for x in parts):
        return None
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def _cidr(ip: str, net: str) -> bool:
    if len(_bytes(ip)) > 64 or len(_bytes(net)) > 64:
        return False
    address = _ipv4(ip)
    if address is None:
        return False
    head, slash, bits_text = net.partition("/")
    network = _ipv4(head)
    if network is None or not slash:
        raise YogError("cidr: invalid network (expected a.b.c.d/n)")
    if not (1 <= len(bits_text) <= 2) or not all(c in "0123456789" for c in bits_text):
        raise YogError("cidr: invalid network (bad prefix length)")
    bits = int(bits_text)
    if bits > 32:
        raise YogError("cidr: invalid network (prefix over 32)")
    mask = 0 if bits == 0 else (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    return (address & mask) == (network & mask)


def eval_builtin(name: str, args: list) -> bool:
    if name == "in":
        return any(same_value(args[0], a) for a in args[1:])
    if not all(isinstance(a, str) for a in args):
        raise YogError(f"{name} expects text arguments")
    a, b = args
    if name == "matches": return _matches(a, b)
    if name == "glob": return _glob(a, b)
    if name == "under": return _under(a, b)
    if name == "starts_with": return _bytes(a).startswith(_bytes(b))
    if name == "ends_with": return _bytes(a).endswith(_bytes(b))
    if name == "contains": return _bytes(b) in _bytes(a)
    if name == "cidr": return _cidr(a, b)
    raise YogError(f"unknown built-in {name}")


# ============================================================ 5. SEMANTIC CHECKER
# This is what keeps facts / rules / decisions from blurring into each other.

def _type_of(const: Const) -> str:
    return "bool" if isinstance(const.val, bool) else ("int" if isinstance(const.val, int) else "text")


def _fits(const: Const, declared: str) -> bool:
    return declared == "any" or _type_of(const) == declared


def check_program(p: Program) -> None:
    base = {f.key for f in p.facts}
    derived = {c.head.key for c in p.clauses if c.kind == "rule"}
    decision = {c.head.key for c in p.clauses if c.kind in ("allow", "deny", "require_approval")}
    inputs = set(p.inputs)

    # Built-in names cannot be redefined.
    for key in sorted(base | derived | decision | inputs):
        if is_builtin(key):
            raise YogError(f"{key[0]}/{key[1]} is a built-in predicate and cannot be redefined")

    # C1: a predicate has exactly one role in the program.
    for bad, msg in ((inputs & base, "is an input (supplied with each request) and cannot also be a fact"),
                     (inputs & derived, "is an input (supplied with each request) and cannot also be a rule head"),
                     (inputs & decision, "is an input (supplied with each request) and cannot also be a decision head"),
                     (base & derived, "is both a fact and a rule head"),
                     (base & decision, "is both a fact and a decision head"),
                     (derived & decision, "is both a rule and a decision head")):
        if bad:
            k = sorted(bad)[0]
            raise YogError(f"predicate {k[0]}/{k[1]} {msg}; pick one role for it")

    known = base | derived | inputs
    for c in p.clauses:
        head_vars = {a.name for a in c.head.args if isinstance(a, Var)}
        # C2: range restriction -- every head variable of a *rule* must be bound
        # by its body. Decision heads are exempt: their args are always supplied
        # ground by yog.check(), so they act as inputs, not outputs.
        if c.kind == "rule":
            bound = set()
            for g in c.body:
                if isinstance(g, Atom) and not is_builtin(g.key):
                    bound |= {a.name for a in g.args if isinstance(a, Var)}
            for a in c.head.args:
                if isinstance(a, Var) and a.name not in bound:
                    raise YogError(f"line {c.line}: variable {a.name} in head of "
                                   f"{c.head.pred} is never bound by the body")
        # C3/C7: safe negation, comparison and built-in arguments -- operands must be bound *earlier*.
        seen = set() if c.kind == "rule" else set(head_vars)
        for g in c.body:
            if isinstance(g, Obl):
                # C9: annotations belong to allow / require_approval clauses only, and
                # may use any variable the body binds (they are read once the clause matched).
                if c.kind not in ("allow", "require_approval"):
                    raise YogError(f"line {g.line}: obligation is only allowed in allow "
                                   f"and require_approval clauses")
                final = set(head_vars)
                for h in c.body:
                    if isinstance(h, Atom) and not is_builtin(h.key):
                        final |= {a.name for a in h.args if isinstance(a, Var)}
                for a in g.goal.args:
                    if isinstance(a, Var) and a.name not in final:
                        raise YogError(f"line {g.line}: variable {a.name} is not bound by the "
                                       f"clause body, so it cannot be used in an obligation")
                continue
            if isinstance(g, Atom):
                if is_builtin(g.key):
                    free = {a.name for a in g.args if isinstance(a, Var)} - seen
                    if free:
                        raise YogError(f"line {c.line}: variable {sorted(free)[0]} is not bound "
                                       f"before built-in {g.pred}")
                else:
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
                if (any(isinstance(t, Const) and isinstance(t.val, bool) for t in (g.lhs, g.rhs))
                        and g.op not in ("==", "!=")):
                    raise YogError(f"line {c.line}: booleans can only be compared with == and !=")
            # C4: no calls to undefined predicates (built-ins are always defined)
            tgt = g.goal if isinstance(g, Neg) else g
            if isinstance(tgt, Atom) and not is_builtin(tgt.key):
                if tgt.key not in known:
                    raise YogError(f"line {c.line}: {tgt.pred}/{len(tgt.args)} is not "
                                   f"defined by any fact or rule")
                # C6: constants given to an input predicate must have its declared type
                if tgt.key in p.inputs:
                    for n, (arg, declared) in enumerate(zip(tgt.args, p.inputs[tgt.key][0]), 1):
                        if isinstance(arg, Const) and not _fits(arg, declared):
                            raise YogError(f"line {c.line}: argument {n} of input "
                                           f"{tgt.pred}/{len(tgt.args)} must be {declared}")

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


# ============================================================ 6. ENGINE (backward chaining)

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
    return s if same_value(a.val, b.val) else None


def fmt(a: Atom, s: dict) -> str:
    """Render a goal with current bindings applied -- readable explanations."""
    def one(t):
        t = walk(t, s)
        return repr(t) if not isinstance(t, Var) else "?"
    return f"{a.pred}({', '.join(one(x) for x in a.args)})"


def compare(op: str, a: Any, b: Any) -> bool:
    ta, tb = type(a), type(b)
    if ta is bool and tb is bool:
        if op not in ("==", "!="):
            raise YogError("booleans can only be compared with == and !=")
        return (a == b) if op == "==" else (a != b)
    if (ta is int and tb is int) or (ta is str and tb is str):
        if ta is str:                                  # the C engine compares UTF-8 bytes
            a, b = _bytes(a), _bytes(b)
        return {"==": a == b, "!=": a != b, "<": a < b, "<=": a <= b,
                ">": a > b, ">=": a >= b}[op]
    if {ta, tb} == {int, str}:
        raise YogError("cannot compare a string with an integer")
    raise YogError("cannot compare values of different types")


class Engine:
    def __init__(self, prog: Program):
        check_program(prog)
        self.version = prog.version
        self.inputs = prog.inputs
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
            if isinstance(g, Obl):  return Obl(rg(g.goal), g.line)
            return Cmp(g.op, rt(g.lhs), rt(g.rhs), g.line)
        return Clause(clause.kind, rg(clause.head), [rg(g) for g in clause.body], clause.line)

    # -- the AST walk --------------------------------------------------------
    def solve(self, goal, s: dict, trace: list, depth: int = 0) -> Iterator[dict]:
        """Yields one substitution per proof of `goal`. Appends to `trace`."""
        pad = "  " * depth

        if isinstance(goal, Obl):                      # an annotation, never a condition
            yield s
            return

        if isinstance(goal, Cmp):
            l, r = walk(goal.lhs, s), walk(goal.rhs, s)
            ok = compare(goal.op, l.val, r.val)
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

        if is_builtin(goal.key):
            values = []
            for a in goal.args:
                a = walk(a, s)
                if isinstance(a, Var):
                    raise YogError("built-in argument is not bound")
                values.append(a.val)
            ok = eval_builtin(goal.pred, values)
            trace.append(f"{pad}{fmt(goal, s)} -> {ok}")
            if ok:
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

    def _validate_context(self, context) -> None:
        """A context fact for an `input` predicate must have the declared types."""
        for f in context:
            if f.key not in self.inputs:
                continue
            for n, (arg, declared) in enumerate(zip(f.args, self.inputs[f.key][0]), 1):
                if not _fits(arg, declared):
                    raise YogError(f"context fact {f.pred}/{len(f.args)}: argument {n} must be {declared}")

    def check(self, actor: str, action: str, resource: str,
              context: Optional[list[Atom]] = None) -> dict:
        """The runtime wrapper.  DENY > REQUIRE_APPROVAL > ALLOW > default DENY.

        Returns {"decision", "reason", "trace", "obligations"}; obligations come only from
        the winning kind, in clause order, without duplicates.
        """
        context = context or []
        self._validate_context(context)
        added = []
        for f in context:                              # per-request facts
            self.facts.setdefault(f.key, []).append(f); added.append(f)
        try:
            goal = Atom(action, [Const(actor), Const(resource)])
            if goal.key not in self.decisions:
                return {"decision": "DENY", "reason":
                        f"no allow/deny clause defines action {action}/2", "trace": [],
                        "obligations": []}

            for kind in ("deny", "require_approval", "allow"):
                first_line = 0
                obligations: list = []
                trace: list = []
                for clause in [c for c in self.decisions[goal.key] if c.kind == kind]:
                    has_obligations = any(isinstance(g, Obl) for g in clause.body)
                    if first_line and not has_obligations:
                        continue                        # later clauses only matter for obligations
                    c = self.rename(clause)
                    s = self.unify_atom(goal, c.head, {})
                    if s is None:
                        continue
                    t: list = []
                    solution = next(iter(self.conj(c.body, s, t, 0)), None)
                    if solution is None:
                        continue
                    if not first_line:
                        first_line = clause.line
                        trace = t
                    if kind == "deny":
                        break
                    for g in c.body:
                        if isinstance(g, Obl):
                            args = []
                            for a in g.goal.args:
                                a = walk(a, solution)
                                args.append(a.val)
                            entry = {"name": g.goal.pred, "args": args}
                            if not any(o["name"] == entry["name"] and len(o["args"]) == len(entry["args"])
                                       and all(same_value(x, y) for x, y in zip(o["args"], entry["args"]))
                                       for o in obligations):
                                obligations.append(entry)
                if first_line:
                    return {"decision": kind.upper(),
                            "reason": f"{kind} clause at line {first_line} matched",
                            "trace": trace, "obligations": obligations if kind != "deny" else []}
            return {"decision": "DENY",
                    "reason": "default deny: no allow clause was satisfied", "trace": [],
                    "obligations": []}
        finally:
            for f in added:
                self.facts[f.key].remove(f)


# ============================================================ 6b. JSON REQUESTS
# A mirror of the C loader (yog/src/api/request.c, docs/INTERFACES.md section 1): the same strictness and the
# same flattening into typed facts, so the two can be compared.

INT64_MIN, INT64_MAX = -(2 ** 63), 2 ** 63 - 1
_REQUEST_FIELDS = {"actor", "action", "resource", "args", "env", "state", "now", "facts", "request_id"}
_IDENT = re.compile(r"[a-z][A-Za-z0-9_]*\Z")


def _strict_loads(text) -> Any:
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise YogError("json: duplicate object key")
            out[key] = value
        return out

    def reject(name):
        raise YogError(f"json: {name} is not supported")

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=reject)
    except json.JSONDecodeError as exc:
        raise YogError(f"json: {exc.msg}") from exc
    return value


def _scalar(value: Any, where: str):
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not INT64_MIN <= value <= INT64_MAX:
            raise YogError("json: integer is out of range")
        return value
    if isinstance(value, str):
        if "\x00" in value:
            raise YogError("json: NUL character in string")
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise YogError("json: lone surrogate") from exc
        return value
    if isinstance(value, float):
        raise YogError(f"{where}: numbers with a fraction or exponent are not supported")
    if value is None:
        raise YogError(f"{where}: null is not supported")
    raise YogError(f"{where}: expected a string, integer or boolean")


def _flatten(predicate: str, obj: dict, prefix: str, depth: int, where: str, out: list) -> None:
    if depth > 8:
        raise YogError(f"{where}: objects are nested too deeply")
    for key, value in obj.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            _flatten(predicate, value, path, depth + 1, where, out)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, (list, dict)):
                    raise YogError(f"{where}: arrays may only contain strings, integers or booleans")
                out.append(Atom(predicate, [Const(path), Const(_scalar(item, where))]))
        else:
            out.append(Atom(predicate, [Const(path), Const(_scalar(value, where))]))


def request_to_facts(request) -> tuple:
    """Returns ``(actor, action, resource, [Atom])`` for a JSON request (dict, str or bytes)."""
    if isinstance(request, (str, bytes)):
        request = _strict_loads(request)
    if not isinstance(request, dict):
        raise YogError("request must be a JSON object")
    for key in request:
        if key not in _REQUEST_FIELDS:
            raise YogError(f'unknown request field "{key}"')
    strings = []
    for name in ("actor", "action", "resource"):
        value = request.get(name)
        if not isinstance(value, str):
            raise YogError(f'request needs a string field "{name}"')
        strings.append(_scalar(value, name))
    atoms: list = []
    for field, predicate in (("args", "arg"), ("env", "env")):
        if field in request:
            if not isinstance(request[field], dict):
                raise YogError(f'"{field}" must be an object')
            _flatten(predicate, request[field], "", 0, field, atoms)
    state = request.get("state")
    if "state" in request:
        if not isinstance(state, dict):
            raise YogError('"state" must be an object')
        for key in state:
            if key not in ("version", "values"):
                raise YogError(f'unknown field "{key}" in state')
        if "version" in state:
            if isinstance(state["version"], bool) or not isinstance(state["version"], int):
                raise YogError("state.version must be an integer")
            atoms.append(Atom("state_version", [Const(_scalar(state["version"], "state.version"))]))
        if "values" in state:
            if not isinstance(state["values"], dict):
                raise YogError('"state.values" must be an object')
            _flatten("state", state["values"], "", 0, "state.values", atoms)
    if "now" in request:
        if isinstance(request["now"], bool) or not isinstance(request["now"], int):
            raise YogError('"now" must be an integer')
        atoms.append(Atom("now", [Const(_scalar(request["now"], "now"))]))
    if "facts" in request:
        if not isinstance(request["facts"], list):
            raise YogError('"facts" must be an array')
        for entry in request["facts"]:
            if (not isinstance(entry, dict) or not isinstance(entry.get("predicate"), str)
                    or not isinstance(entry.get("args"), list)):
                raise YogError('each fact needs a "predicate" string and an "args" array')
            if set(entry) - {"predicate", "args"}:
                raise YogError("unknown field in a fact")
            if not _IDENT.match(entry["predicate"]) or len(entry["predicate"]) > 64:
                raise YogError(f'invalid predicate name "{entry["predicate"]}"')
            if not 1 <= len(entry["args"]) <= 16:
                raise YogError("a fact needs between 1 and 16 arguments")
            if is_builtin((entry["predicate"], len(entry["args"]))):
                raise YogError(f'{entry["predicate"]}/{len(entry["args"])} is a built-in predicate and cannot be redefined')
            atoms.append(Atom(entry["predicate"], [Const(_scalar(a, "facts")) for a in entry["args"]]))
    if "request_id" in request and not isinstance(request["request_id"], str):
        raise YogError('"request_id" must be a string')
    if len(atoms) > 4096:
        raise YogError("request has more than 4096 facts")
    return strings[0], strings[1], strings[2], atoms


def check_json(engine: "Engine", request) -> dict:
    """Checks a JSON request the way ``yogc check-json`` does and returns the result dict.

    A request or evaluation error is returned as ``{"error": {...}}`` (callers must treat it as DENY).
    """
    try:
        actor, action, resource, atoms = request_to_facts(request)
        result = engine.check(actor, action, resource, atoms)
    except YogError as exc:
        return {"error": {"message": str(exc), "line": 0, "column": 0}}
    return {"decision": result["decision"], "reason": result["reason"],
            "matched_line": _line_of(result["reason"]), "policy_version": engine.version,
            "obligations": result["obligations"]}


def _line_of(reason: str) -> int:
    match = re.search(r"at line (\d+) matched", reason)
    return int(match.group(1)) if match else 0


def load_policy(path: str) -> Engine:
    with open(path) as fh:
        return Engine(Parser(tokenize(fh.read())).parse())


# ============================================================ 7. CLI

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: yog_ref.py <policy.yog> [--trace]")
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
