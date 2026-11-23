"""Import a subset of Cedar into YOG v2.

Cedar and YOG share the decision model that matters here: a request is denied unless some ``permit`` matches, and
any matching ``forbid`` wins.  This converter handles the part of Cedar that maps onto YOG without guessing, and
refuses (``ConversionError`` with the line) everything else, so a condition is never silently dropped.

Supported::

    permit (principal == User::"alice", action == Action::"read", resource == File::"report")
      when { context.n < 5 && context.stage == "prod" && context has reason }
      unless { context.region like "eu-*" };
    forbid (principal, action in [Action::"a", Action::"b"], resource) when { [ "x", "y" ].contains(context.k) };

* scope: ``principal`` / ``resource`` bare or ``== Type::"id"``; ``action == Action::"x"`` or ``in [..]``
  (a bare ``action`` needs ``all_actions``);
* conditions: ``&&``, ``||``, ``!``, parentheses, ``==  !=  <  <=  >  >=`` between ``context.attr`` (dotted paths ok) and a
  string / integer / boolean literal, ``context has attr``, ``context.attr like "pat*"`` (``*`` only), and
  ``[literals].contains(context.attr)``.

Mapping: the YOG actor is the text ``Type::id`` (``User::alice``), the resource likewise, the action name becomes the
decision predicate (lower-cased first letter, other characters replaced by ``_``), and ``context.x`` becomes
``arg("x", V)``.

Semantics kept: default deny, forbid beats permit, and Cedar's rule that a policy whose condition *errors* (an
attribute is missing) does not apply, including short-circuit ``&&`` / ``||``: they are translated through "true
without error" and "false without error" forms so the two engines agree on missing attributes.  Not kept: Cedar
errors on a type mismatch (``context.n < 5`` when ``n`` is text) skip the policy, whereas YOG treats it as an
evaluation error and denies the whole request.  YOG is the stricter of the two; keep request types consistent.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

MAX_CLAUSES_PER_POLICY = 64


class ConversionError(Exception):
    def __init__(self, line: int, construct: str, message: str = ""):
        self.line, self.construct = line, construct
        super().__init__(f"line {line}: {construct}" + (f": {message}" if message else ""))


# ------------------------------------------------------------------------------------------------ tokens
_TOKEN = re.compile(r'''\s+|//[^\n]*|(?P<str>"(?:[^"\\]|\\.)*")|(?P<int>-?\d+)|(?P<id>[A-Za-z_][A-Za-z0-9_]*)'''
                    r'''|(?P<op>::|==|!=|<=|>=|&&|\|\||[(){}\[\],;.<>!=@])''')


@dataclass
class Tok:
    kind: str
    val: object
    line: int


def tokenize(text: str) -> list:
    out, pos, line = [], 0, 1
    while pos < len(text):
        match = _TOKEN.match(text, pos)
        if not match:
            raise ConversionError(line, "unexpected character", repr(text[pos]))
        chunk = match.group(0)
        if match.lastgroup == "str":
            out.append(Tok("str", _unescape(chunk[1:-1], line), line))
        elif match.lastgroup == "int":
            out.append(Tok("int", int(chunk), line))
        elif match.lastgroup == "id":
            out.append(Tok("id", chunk, line))
        elif match.lastgroup == "op":
            out.append(Tok("op", chunk, line))
        line += chunk.count("\n")
        pos = match.end()
    out.append(Tok("eof", None, line))
    return out


def _unescape(raw: str, line: int) -> str:
    out, i = [], 0
    while i < len(raw):
        if raw[i] == "\\":
            nxt = raw[i + 1]
            if nxt not in '"\\*nrt0':
                raise ConversionError(line, "string escape", f"\\{nxt}")
            out.append({"n": "\n", "r": "\r", "t": "\t", "0": "\0"}.get(nxt, nxt) if nxt != "*" else "\\*")
            i += 2
        else:
            out.append(raw[i])
            i += 1
    return "".join(out)


# -------------------------------------------------------------------------------------------------- AST
@dataclass
class Lit:                       # context.attr OP const | has | like | contains
    attr: str
    kind: str                    # "cmp" | "has" | "like" | "in"
    op: str = ""
    value: object = None


@dataclass
class Not:
    inner: object


@dataclass
class And:
    left: object
    right: object


@dataclass
class Or:
    left: object
    right: object


@dataclass
class Const:
    value: bool


@dataclass
class Policy:
    effect: str
    principal: Optional[str]
    actions: Optional[list]
    resource: Optional[str]
    conditions: list = field(default_factory=list)       # [("when"|"unless", expr)]
    line: int = 0


class _Parser:
    def __init__(self, tokens):
        self.t, self.i = tokens, 0

    def peek(self, k=0):
        return self.t[self.i + k]

    def next(self):
        self.i += 1
        return self.t[self.i - 1]

    def accept(self, kind, val=None):
        tok = self.peek()
        if tok.kind == kind and (val is None or tok.val == val):
            return self.next()
        return None

    def expect(self, kind, val=None):
        tok = self.accept(kind, val)
        if tok is None:
            got = self.peek()
            raise ConversionError(got.line, f"expected {val or kind}", f"found {got.val!r}")
        return tok

    # ------------------------------------------------------------------ policies
    def policies(self) -> list:
        out = []
        while self.peek().kind != "eof":
            while self.accept("op", "@"):                        # annotations are ignored
                self.expect("id")
                self.expect("op", "(")
                self.expect("str")
                self.expect("op", ")")
            out.append(self.policy())
        return out

    def policy(self) -> Policy:
        head = self.expect("id")
        if head.val not in ("permit", "forbid"):
            raise ConversionError(head.line, "policy effect", f"expected permit or forbid, found {head.val!r}")
        self.expect("op", "(")
        principal = self.scope("principal")
        self.expect("op", ",")
        actions = self.action_scope()
        self.expect("op", ",")
        resource = self.scope("resource")
        self.expect("op", ")")
        policy = Policy(head.val, principal, actions, resource, line=head.line)
        while self.peek().kind == "id" and self.peek().val in ("when", "unless"):
            kind = self.next().val
            self.expect("op", "{")
            policy.conditions.append((kind, self.expr()))
            self.expect("op", "}")
        self.expect("op", ";")
        return policy

    def entity(self) -> str:
        parts = [self.expect("id").val]
        while self.accept("op", "::"):
            if self.peek().kind == "str":
                return "::".join(parts) + "::" + self.next().val
            parts.append(self.expect("id").val)
        raise ConversionError(self.peek().line, "entity reference", 'expected Type::"id"')

    def scope(self, name: str) -> Optional[str]:
        tok = self.expect("id", name)
        if self.accept("op", "=="):
            return self.entity()
        nxt = self.peek()
        if (nxt.kind == "id" and nxt.val in ("in", "is")) or (nxt.kind == "op" and nxt.val == "in"):
            raise ConversionError(tok.line, f"{name} {nxt.val}", "entity hierarchies and types are not supported")
        return None

    def action_scope(self) -> Optional[list]:
        tok = self.expect("id", "action")
        if self.accept("op", "=="):
            return [self.entity()]
        if self.accept("id", "in"):
            self.expect("op", "[")
            names = [self.entity()]
            while self.accept("op", ","):
                names.append(self.entity())
            self.expect("op", "]")
            return names
        return None

    # ---------------------------------------------------------------- conditions
    def expr(self):
        left = self.and_expr()
        while self.accept("op", "||"):
            left = Or(left, self.and_expr())
        return left

    def and_expr(self):
        left = self.unary()
        while self.accept("op", "&&"):
            left = And(left, self.unary())
        return left

    def unary(self):
        if self.accept("op", "!"):
            return Not(self.unary())
        return self.relation()

    def attr_path(self) -> str:
        tok = self.expect("id", "context")
        parts = []
        while self.accept("op", "."):
            if self.peek().kind != "id" or self.peek().val == "contains":
                break
            parts.append(self.next().val)
        if not parts:
            raise ConversionError(tok.line, "context", "use context.<attribute>")
        return ".".join(parts)

    def literal(self):
        tok = self.next()
        if tok.kind in ("str", "int"):
            return tok.val
        if tok.kind == "id" and tok.val in ("true", "false"):
            return tok.val == "true"
        raise ConversionError(tok.line, "operand", f"only string, integer and boolean literals are supported, found {tok.val!r}")

    def relation(self):
        tok = self.peek()
        if self.accept("op", "("):
            inner = self.expr()
            self.expect("op", ")")
            return inner
        if tok.kind == "id" and tok.val in ("true", "false"):
            self.next()
            return Const(tok.val == "true")
        if tok.kind == "op" and tok.val == "[":                  # [ literals ].contains(context.attr)
            self.next()
            values = [self.literal()]
            while self.accept("op", ","):
                values.append(self.literal())
            self.expect("op", "]")
            self.expect("op", ".")
            self.expect("id", "contains")
            self.expect("op", "(")
            attr = self.attr_path()
            self.expect("op", ")")
            return Lit(attr, "in", value=values)
        if tok.kind == "id" and tok.val == "context":
            if self.peek(1).kind == "id" and self.peek(1).val == "has":
                self.next(); self.next()
                return Lit(self.expect("id").val, "has")
            attr = self.attr_path()
            if self.accept("id", "like"):
                pattern = self.expect("str").val
                if re.search(r"[?\[\\]", pattern.replace("\\*", "")) or "\\*" in pattern:
                    raise ConversionError(tok.line, "like pattern", "only the * wildcard is supported")
                return Lit(attr, "like", value=pattern)
            nxt = self.peek()
            if nxt.kind == "op" and nxt.val in ("==", "!=", "<", "<=", ">", ">="):
                self.next()
                value = self.literal()
                if nxt.val in ("<", "<=", ">", ">=") and (isinstance(value, bool) or not isinstance(value, int)):
                    raise ConversionError(nxt.line, "ordering", "Cedar orders integers only")
                return Lit(attr, "cmp", nxt.val, value)
            raise ConversionError(tok.line, "condition", "context.<attr> must be compared, tested with has or like")
        raise ConversionError(tok.line, "expression", f"unsupported construct near {tok.val!r}")


# ---------------------------------------------------------------------------------------- translation
FLIP = {"==": "!=", "!=": "==", "<": ">=", "<=": ">", ">": "<=", ">=": "<"}


def _t_f(node):
    """(T, F): lists of conjunctions of literals; T = 'evaluates to true without error', F = '... false ...'.
    A conjunction is a list of (attr, kind, op, value, positive)."""
    if isinstance(node, Const):
        return ([[]], []) if node.value else ([], [[]])
    if isinstance(node, Lit):
        if node.kind == "has":
            return [[(node.attr, "has", "", None, True)]], [[(node.attr, "has", "", None, False)]]
        present = (node.attr, "has", "", None, True)
        if node.kind == "cmp":
            return ([[present, (node.attr, "cmp", node.op, node.value, True)]],
                    [[present, (node.attr, "cmp", FLIP[node.op], node.value, True)]])
        return ([[present, (node.attr, node.kind, "", node.value, True)]],
                [[present, (node.attr, node.kind, "", node.value, False)]])
    if isinstance(node, Not):
        t, f = _t_f(node.inner)
        return f, t
    ta, fa = _t_f(node.left)
    tb, fb = _t_f(node.right)
    if isinstance(node, And):
        return _times(ta, tb), fa + _times(ta, fb)             # A false -> false; A true then B decides
    return ta + _times(fa, tb), _times(fa, fb)                  # A true -> true; A false then B decides


def _times(left, right):
    return [a + b for a in left for b in right]


def _render_conjunction(conj, line: int):
    """YOG body goals for one conjunction, or None when it is contradictory."""
    present, absent = set(), set()
    for attr, kind, _, _, positive in conj:
        if kind == "has":
            (present if positive else absent).add(attr)
    for attr, kind, _, _, positive in conj:
        if kind != "has" and positive is not None:
            present.add(attr)
    if present & absent:
        return None
    variables = {attr: f"V{i}" for i, attr in enumerate(sorted(present))}
    goals = [f'arg("{_q(attr)}", {variables[attr]})' for attr in sorted(present)]
    goals += [f'not cedar_has("{_q(attr)}")' for attr in sorted(absent)]
    seen = set()
    for attr, kind, op, value, positive in conj:
        if kind == "has":
            continue
        key = (attr, kind, op, repr(value), positive)
        if key in seen:
            continue
        seen.add(key)
        var = variables[attr]
        if kind == "cmp":
            goals.append(f"{var} {op} {_lit(value)}")
        elif kind == "like":
            goals.append(("" if positive else "not ") + f'glob({var}, "{_q(value)}")')
        else:
            goals.append(("" if positive else "not ") + f"in({var}, {', '.join(_lit(v) for v in value)})")
    return goals


def _q(text: str) -> str:
    if '"' in text or "\n" in text or "\\" in text:
        raise ConversionError(0, "string", "quotes, newlines and backslashes cannot be written in a YOG string")
    return text


def _lit(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return f'"{_q(value)}"'


def _pred(entity: str, line: int) -> str:
    name = entity.split("::")[-1]
    name = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if not name or not name[0].isalpha():
        raise ConversionError(line, "action name", f"cannot make a predicate from {entity!r}")
    return name[0].lower() + name[1:]


def convert(text: str, *, all_actions: Optional[list] = None) -> tuple:
    """Returns ``(yog_source, mapping)`` where mapping lists each generated clause's Cedar line.  Raises
    :class:`ConversionError` on anything outside the supported subset."""
    policies = _Parser(tokenize(text)).policies()
    out = ["version 2", "", "input arg(text, any)", ""]
    header_len = len(out)
    mapping = []
    for policy in policies:
        if policy.actions is None:
            if not all_actions:
                raise ConversionError(policy.line, "unconstrained action",
                                      "list the actions (all_actions / --actions) the policy should cover")
            actions = [_pred(f"Action::{a}", policy.line) for a in all_actions]
        else:
            actions = [_pred(a, policy.line) for a in policy.actions]
        conjunctions = [[]]
        for kind, expression in policy.conditions:
            t, f = _t_f(expression)
            conjunctions = _times(conjunctions, t if kind == "when" else f)
            if len(conjunctions) > MAX_CLAUSES_PER_POLICY:
                raise ConversionError(policy.line, "condition", f"expands to more than {MAX_CLAUSES_PER_POLICY} clauses")
        effect = "allow" if policy.effect == "permit" else "deny"
        actor = f'"{_q(policy.principal)}"' if policy.principal else "Actor"
        resource = f'"{_q(policy.resource)}"' if policy.resource else "Resource"
        for conj in conjunctions:
            goals = _render_conjunction(conj, policy.line)
            if goals is None:
                continue
            for action in actions:
                body = "\n".join("    " + g for g in goals) if goals else "    true == true"
                out.append(f"# cedar line {policy.line}")
                out.append(f"{effect} {action}({actor}, {resource}):\n{body}\n")
                mapping.append({"cedar_line": policy.line, "effect": effect, "action": action})
    if "not cedar_has(" in "\n".join(out):
        out[header_len:header_len] = ["# true when the request has an argument with this name", "rule cedar_has(K):",
                                      "    arg(K, V)", ""]
    return "\n".join(out).rstrip() + "\n", mapping
