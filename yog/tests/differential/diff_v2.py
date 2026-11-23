#!/usr/bin/env python3
"""Differential test for language version 2.

Runs the same policies and requests through two independent implementations:
  * the C engine, driven through `yogc batch`, and
  * the Python reference interpreter (reference/yog_ref.py),
and requires identical results: decision, reason (which clause won), the
ordered obligation list, and which requests are evaluation errors.

It has two parts:
  1. a curated corpus that exercises each v2 feature and each built-in, and
  2. a seeded random generator of policies and requests (the property test).

Usage:
    python yog/tests/differential/diff_v2.py [--yogc PATH] [--seed N] [--policies N]
"""
from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "reference"))
import yog_ref  # noqa: E402

DEFAULT_YOGC = ROOT / "yog" / "build" / ("yogc.exe" if os.name == "nt" else "yogc")


# ------------------------------------------------------------------ plumbing

def render_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    assert '"' not in value and ";" not in value and "\n" not in value, value
    return f'"{value}"'


def render_context(facts) -> str:
    return "; ".join(f"fact {pred}({', '.join(render_value(a) for a in args)})" for pred, args in facts)


def run_yogc(yogc: Path, policy: str, requests) -> list:
    """Returns one result per request: ("ERROR", message) or (decision, reason, obligations)."""
    with tempfile.TemporaryDirectory(prefix="yog-v2-") as tmp:
        path = Path(tmp) / "policy.yog"
        path.write_text(policy, encoding="utf-8")
        compile_check = subprocess.run([str(yogc), "validate", str(path)], capture_output=True, text=True)
        if compile_check.returncode != 0:
            return [("COMPILE_ERROR", compile_check.stderr.strip())] * len(requests)
        lines = []
        for actor, action, resource, facts in requests:
            ctx = render_context(facts)
            lines.append(f"{actor} {action} {resource}" + (f" | {ctx}" if ctx else ""))
        proc = subprocess.run([str(yogc), "batch", str(path)], input="\n".join(lines) + "\n",
                              capture_output=True, text=True)
    results, current = [], []
    for line in proc.stdout.splitlines():
        if line == "--":
            results.append(current)
            current = []
        else:
            current.append(line)
    out = []
    for block in results:
        head = block[0]
        if head.startswith("ERROR|"):
            out.append(("ERROR", head[6:]))
            continue
        decision, _, reason = head.partition("|")
        obligations = [json.loads(b[len("OBLIGATION|"):]) for b in block[1:] if b.startswith("OBLIGATION|")]
        out.append((decision, reason, obligations))
    return out


def run_reference(policy: str, requests) -> list:
    try:
        engine = yog_ref.Engine(yog_ref.Parser(yog_ref.tokenize(policy)).parse())
    except yog_ref.YogError as exc:
        return [("COMPILE_ERROR", str(exc))] * len(requests)
    out = []
    for actor, action, resource, facts in requests:
        atoms = [yog_ref.Atom(pred, [yog_ref.Const(a) for a in args]) for pred, args in facts]
        try:
            r = engine.check(actor, action, resource, atoms)
        except yog_ref.YogError as exc:
            out.append(("ERROR", str(exc)))
            continue
        out.append((r["decision"], r["reason"], r["obligations"]))
    return out


def canonical(obligations):
    return [{"name": o["name"], "args": o["args"]} for o in obligations]


def compare(label: str, policy: str, requests, yogc: Path, failures: list) -> int:
    c = run_yogc(yogc, policy, requests)
    r = run_reference(policy, requests)
    compared = 0
    for request, got, want in zip(requests, c, r):
        compared += 1
        kind_c, kind_r = got[0], want[0]
        if kind_c in ("COMPILE_ERROR", "ERROR") or kind_r in ("COMPILE_ERROR", "ERROR"):
            if kind_c != kind_r:
                failures.append(f"{label} {request}: C says {got}, reference says {want}")
            continue
        if got[0] != want[0] or got[1] != want[1] or canonical(got[2]) != canonical(want[2]):
            failures.append(f"{label} {request}:\n    C:         {got}\n    reference: {want}")
    return compared


# ------------------------------------------------------------- curated corpus

CURATED = []


def case(name, policy, *requests):
    CURATED.append((name, policy.strip() + "\n", list(requests)))


def req(actor, action, resource, *facts):
    return (actor, action, resource, list(facts))


case("lattice", """
input flag(text)
allow act(U, R):
    flag("allow")
require_approval act(U, R):
    flag("approve")
deny act(U, R):
    flag("deny")
""",
     req("u", "act", "r"),
     req("u", "act", "r", ("flag", ["allow"])),
     req("u", "act", "r", ("flag", ["approve"])),
     req("u", "act", "r", ("flag", ["deny"])),
     req("u", "act", "r", ("flag", ["allow"]), ("flag", ["approve"])),
     req("u", "act", "r", ("flag", ["approve"]), ("flag", ["deny"])),
     req("u", "act", "r", ("flag", ["allow"]), ("flag", ["approve"]), ("flag", ["deny"])),
     req("u", "other", "r"))

case("obligations", """
input role(text)
input owner(text, text)
allow act(U, R):
    role("a")
    obligation audit("first", U)
    obligation tag(7)
allow act(U, R):
    role("a")
    obligation audit("first", U)
allow act(U, R):
    role("b")
    owner(R, O)
    obligation notify(O, true)
require_approval act(U, R):
    role("c")
    obligation audit("approval", R)
allow act(U, R):
    role("c")
    obligation from_allow(1)
""",
     req("al", "act", "doc", ("role", ["a"])),
     req("al", "act", "doc", ("role", ["b"]), ("owner", ["doc", "carol"])),
     req("al", "act", "doc", ("role", ["b"]), ("owner", ["other", "carol"])),
     req("al", "act", "doc", ("role", ["c"])),
     req("al", "act", "doc", ("role", ["a"]), ("role", ["b"]), ("owner", ["doc", "dave"])))

case("typed inputs", """
input limit(text, int)
input flag(text, bool)
input anything(any)
allow act(U, R):
    limit(R, N)
    N > 5
    flag(R, F)
    F == true
deny act(U, R):
    anything(X)
    X == 13
""",
     req("u", "act", "r", ("limit", ["r", 9]), ("flag", ["r", True])),
     req("u", "act", "r", ("limit", ["r", 3]), ("flag", ["r", True])),
     req("u", "act", "r", ("limit", ["r", 9]), ("flag", ["r", False])),
     req("u", "act", "r", ("limit", ["r", "nine"]), ("flag", ["r", True])),       # wrong type: error
     req("u", "act", "r", ("limit", ["r", 9]), ("flag", ["r", 1])),               # int is not bool: error
     req("u", "act", "r", ("limit", ["r", 9]), ("flag", ["r", True]), ("anything", [13])),
     req("u", "act", "r", ("limit", ["r", 9]), ("flag", ["r", True]), ("anything", ["13"])),
     req("u", "act", "r", ("limit", ["r", 9]), ("flag", ["r", True]), ("anything", [True])))

case("strings and strict equality", """
input v(any)
allow act(U, R):
    v(X)
    X == "1"
allow act(U, R):
    v(X)
    X == true
deny act(U, R):
    v(X)
    X == 1
""",
     req("u", "act", "r", ("v", ["1"])),
     req("u", "act", "r", ("v", [1])),
     req("u", "act", "r", ("v", [True])),
     req("u", "act", "r", ("v", [False])),
     req("u", "act", "r", ("v", ["x"])))

case("mixed-type comparison is an error", """
input v(any)
allow act(U, R):
    v(X)
    X > 3
""",
     req("u", "act", "r", ("v", [5])),
     req("u", "act", "r", ("v", ["five"])),
     req("u", "act", "r", ("v", [True])))

case("built-ins: strings", """
input s(text)
allow act(U, R):
    s(X)
    starts_with(X, "git ")
    not contains(X, "--force")
allow act(U, R):
    s(X)
    ends_with(X, ".log")
allow act(U, R):
    s(X)
    in(X, "ls", "cat", "pwd")
deny act(U, R):
    s(X)
    contains(X, "rm -rf")
""",
     req("u", "act", "r", ("s", ["git status"])),
     req("u", "act", "r", ("s", ["git push --force"])),
     req("u", "act", "r", ("s", ["app.log"])),
     req("u", "act", "r", ("s", ["ls"])),
     req("u", "act", "r", ("s", ["lsx"])),
     req("u", "act", "r", ("s", ["rm -rf /"])),
     req("u", "act", "r", ("s", [""])))

case("built-ins: glob", """
input s(text)
allow act(U, R):
    s(X)
    glob(X, "*.csv")
allow act(U, R):
    s(X)
    glob(X, "a?c")
allow act(U, R):
    s(X)
    glob(X, "*b*c*")
""",
     req("u", "act", "r", ("s", ["report.csv"])),
     req("u", "act", "r", ("s", [".csv"])),
     req("u", "act", "r", ("s", ["abc"])),
     req("u", "act", "r", ("s", ["ac"])),
     req("u", "act", "r", ("s", ["xxbxxcxx"])),
     req("u", "act", "r", ("s", ["xxcxxbxx"])),
     req("u", "act", "r", ("s", [""])))

case("built-ins: under (path traversal)", """
input p(text)
allow act(U, R):
    p(X)
    under(X, "/work")
deny act(U, R):
    p(X)
    under(X, "/work/secret")
""",
     req("u", "act", "r", ("p", ["/work/a/b"])),
     req("u", "act", "r", ("p", ["/work"])),
     req("u", "act", "r", ("p", ["/work/"])),
     req("u", "act", "r", ("p", ["/workshop"])),
     req("u", "act", "r", ("p", ["/work/../etc/passwd"])),
     req("u", "act", "r", ("p", ["/etc/../work/x"])),
     req("u", "act", "r", ("p", ["/work/./secret/x"])),
     req("u", "act", "r", ("p", ["/work/a/../secret"])),
     req("u", "act", "r", ("p", ["work/a"])),
     req("u", "act", "r", ("p", ["/../work/a"])),
     req("u", "act", "r", ("p", ["//work//a"])))

case("built-ins: cidr", """
input ip(text)
allow act(U, R):
    ip(X)
    cidr(X, "10.0.0.0/8")
deny act(U, R):
    ip(X)
    cidr(X, "10.9.0.0/16")
allow act(U, R):
    ip(X)
    cidr(X, "192.168.1.7/32")
""",
     req("u", "act", "r", ("ip", ["10.1.2.3"])),
     req("u", "act", "r", ("ip", ["10.9.2.3"])),
     req("u", "act", "r", ("ip", ["11.1.2.3"])),
     req("u", "act", "r", ("ip", ["192.168.1.7"])),
     req("u", "act", "r", ("ip", ["192.168.1.8"])),
     req("u", "act", "r", ("ip", ["10.0.0.256"])),
     req("u", "act", "r", ("ip", ["010.0.0.1"])),
     req("u", "act", "r", ("ip", ["not-an-ip"])),
     req("u", "act", "r", ("ip", [""])))

case("built-ins: bad cidr network is an error", """
input ip(text)
allow act(U, R):
    ip(X)
    cidr(X, "10.0.0.0/33")
""",
     req("u", "act", "r", ("ip", ["10.0.0.1"])))

case("built-ins: regex", """
input s(text)
deny act(U, R):
    s(X)
    matches(X, "(?i)drop\\\\s+table")
allow act(U, R):
    s(X)
    matches(X, "^[a-z]+[0-9]*$")
allow act(U, R):
    s(X)
    matches(X, "^(ab)+c?$")
allow act(U, R):
    s(X)
    matches(X, "colou?r|gr[ae]y")
""",
     req("u", "act", "r", ("s", ["DROP   TABLE users"])),
     req("u", "act", "r", ("s", ["please drop table x"])),
     req("u", "act", "r", ("s", ["abc123"])),
     req("u", "act", "r", ("s", ["ABC123"])),
     req("u", "act", "r", ("s", ["ababc"])),
     req("u", "act", "r", ("s", ["aba"])),
     req("u", "act", "r", ("s", ["my colour"])),
     req("u", "act", "r", ("s", ["grey"])),
     req("u", "act", "r", ("s", ["gruy"])),
     req("u", "act", "r", ("s", [""])))

case("built-ins: invalid regex is an error", """
input s(text)
allow act(U, R):
    s(X)
    matches(X, "(open")
""",
     req("u", "act", "r", ("s", ["x"])))

case("built-ins: wrong kind is an error", """
input n(int)
allow act(U, R):
    n(X)
    contains(X, "1")
""",
     req("u", "act", "r", ("n", [5])))

case("rules and negation with inputs", """
input member(text, text)
fact admin_team(ops)
rule is_admin(U):
    member(U, T)
    admin_team(T)
allow act(U, R):
    is_admin(U)
deny act(U, R):
    member(U, "banned")
allow act(U, R):
    not is_admin(U)
    member(U, "guests")
    starts_with(R, "public/")
""",
     req("al", "act", "r", ("member", ["al", "ops"])),
     req("al", "act", "r", ("member", ["al", "ops"]), ("member", ["al", "banned"])),
     req("al", "act", "public/x", ("member", ["al", "guests"])),
     req("al", "act", "private/x", ("member", ["al", "guests"])),
     req("al", "act", "r"))


# ------------------------------------------------------------- random corpus

TEXT_POOL = ["ls", "cat file", "rm -rf /", "git status", "git push --force", "/work/a", "/work/../etc",
             "/prod/db", "10.1.2.3", "8.8.8.8", "a/b", "", "Drop Table", "app.log", "x1", "abab"]
INT_POOL = [0, 1, 5, 9, 13, 100]
REGEXES = ["drop|rm", "^[a-z]+$", "(?i)table", "^/work", "[0-9]+", "a.c|ab+", "^(ab)+$", "x?1"]
GLOBS = ["*.log", "*a*", "?s", "git*", "*"]
PREFIXES = ["/work", "/prod", "/", "a"]
NETS = ["10.0.0.0/8", "8.8.8.0/24", "0.0.0.0/0"]


class Generator:
    def __init__(self, rng: random.Random):
        self.rng = rng

    def policy(self):
        rng = self.rng
        lines = ["version 2",
                 "input a(text)", "input b(text)", "input n(int)", "input f(bool)", "input t(text, int)"]
        text_vars = ["X", "Y"]
        for _ in range(rng.randint(2, 6)):
            kind = rng.choice(["allow", "allow", "deny", "require_approval", "allow"])
            body = []
            bound_text, bound_int = [], []
            for _ in range(rng.randint(1, 4)):
                choice = rng.random()
                if choice < 0.35:
                    pred = rng.choice(["a", "b"])
                    v = rng.choice(text_vars)
                    body.append(f"{pred}({v})" if rng.random() < 0.7 else f'{pred}({render_value(rng.choice(TEXT_POOL))})')
                    if body[-1].endswith(f"({v})"):
                        bound_text.append(v)
                elif choice < 0.5:
                    body.append(f"n(N)")
                    bound_int.append("N")
                elif choice < 0.6:
                    body.append("f(F)")
                    body.append(f"F {rng.choice(['==', '!='])} {rng.choice(['true', 'false'])}")
                elif choice < 0.7:
                    body.append(f"t(Z, M)")
                    bound_text.append("Z")
                    bound_int.append("M")
                elif bound_text:
                    body.append(self.builtin(rng.choice(bound_text)))
                elif bound_int:
                    body.append(f"{rng.choice(bound_int)} {rng.choice(['<', '>=', '==', '!='])} {rng.choice(INT_POOL)}")
            if bound_int and rng.random() < 0.4:
                body.append(f"{rng.choice(bound_int)} {rng.choice(['<', '<=', '>', '>=', '==', '!='])} {rng.choice(INT_POOL)}")
            if bound_text and rng.random() < 0.3:
                body.append("not " + self.builtin(rng.choice(bound_text)))
            if kind != "deny":
                for _ in range(rng.choice([0, 0, 1, 2])):
                    args = []
                    for _ in range(rng.randint(1, 2)):
                        pool = ["U", "R", render_value(rng.choice(TEXT_POOL)), str(rng.choice(INT_POOL)),
                                rng.choice(["true", "false"])] + bound_text + bound_int
                        args.append(rng.choice(pool))
                    body.append(f"obligation {rng.choice(['audit', 'tag', 'notify'])}({', '.join(args)})")
            if not body:
                body.append("a(X)")
            lines.append(f"{kind} act(U, R):")
            lines.extend("    " + g for g in body)
        return "\n".join(lines) + "\n"

    def builtin(self, var):
        rng = self.rng
        name = rng.choice(["contains", "starts_with", "ends_with", "glob", "matches", "under", "cidr", "in"])
        if name == "glob": return f'glob({var}, "{rng.choice(GLOBS)}")'
        if name == "matches": return f'matches({var}, "{rng.choice(REGEXES)}")'
        if name == "under": return f'under({var}, "{rng.choice(PREFIXES)}")'
        if name == "cidr": return f'cidr({var}, "{rng.choice(NETS)}")'
        if name == "in": return f'in({var}, {", ".join(render_value(t) for t in rng.sample(TEXT_POOL, 3))})'
        return f'{name}({var}, {render_value(rng.choice(TEXT_POOL))})'

    def request(self):
        rng = self.rng
        facts = []
        for _ in range(rng.randint(0, 5)):
            pred = rng.choice(["a", "b", "n", "f", "t"])
            if pred in ("a", "b"):
                facts.append((pred, [rng.choice(TEXT_POOL)]))
            elif pred == "n":
                facts.append((pred, [rng.choice(INT_POOL)]))
            elif pred == "f":
                facts.append((pred, [rng.choice([True, False])]))
            else:
                facts.append((pred, [rng.choice(TEXT_POOL), rng.choice(INT_POOL)]))
        if rng.random() < 0.05:                              # occasionally violate an input type
            facts.append(("n", [rng.choice(TEXT_POOL)]))
        return ("u", "act", rng.choice(["r", "doc", "/work/x"]), facts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yogc", type=Path, default=DEFAULT_YOGC)
    parser.add_argument("--seed", type=int, default=20261123)
    parser.add_argument("--policies", type=int, default=60)
    parser.add_argument("--requests", type=int, default=25)
    args = parser.parse_args()
    if not args.yogc.exists():
        print(f"yogc not found at {args.yogc}; pass --yogc", file=sys.stderr)
        return 2

    failures: list[str] = []
    compared = 0
    for name, policy, requests in CURATED:
        compared += compare(f"[{name}]", policy, requests, args.yogc, failures)
    curated_count = compared

    gen = Generator(random.Random(args.seed))
    rejected = 0
    for n in range(args.policies):
        policy = gen.policy()
        requests = [gen.request() for _ in range(args.requests)]
        before = len(failures)
        compared += compare(f"[random #{n} seed {args.seed}]\n{policy}", policy, requests, args.yogc, failures)
        if run_reference(policy, requests[:1])[0][0] == "COMPILE_ERROR":
            rejected += 1
        if len(failures) > before and len(failures) > 20:
            break

    for message in failures[:20]:
        print("MISMATCH", message)
    if failures:
        print(f"{len(failures)} mismatch(es) in {compared} comparisons")
        return 1
    print(f"all {compared} comparisons agree ({curated_count} curated, "
          f"{compared - curated_count} random over {args.policies} policies, "
          f"{rejected} random policies rejected by both)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
