"""Cedar to YOG: golden conversions, refusals, and a differential test against an independent Cedar-subset evaluator."""
import fnmatch
import random

import pytest

from yog_platform.cedar_import import ConversionError, convert
from yog_platform.pdp import ReferencePDP

SIMPLE = """
// read access for alice, but only for small requests
permit (principal == User::"alice", action == Action::"read", resource == File::"report")
  when { context.n < 5 && context.stage == "prod" }
  unless { context.region like "eu-*" };

forbid (principal, action in [Action::"read", Action::"write"], resource == File::"secret");
"""


def decide(source, actor, action, resource, **context):
    request = {"actor": actor, "action": action, "resource": resource}
    if context:
        request["args"] = context
    return ReferencePDP(source).check(request)["decision"]


def test_a_simple_policy_converts_and_behaves():
    source, mapping = convert(SIMPLE)
    assert source.startswith("version 2") and "input arg(text, any)" in source
    assert [m["effect"] for m in mapping].count("deny") == 2
    assert decide(source, "User::alice", "read", "File::report", n=3, stage="prod", region="us-1") == "ALLOW"
    assert decide(source, "User::alice", "read", "File::report", n=3, stage="prod") == "DENY"             # region missing: unless errors
    assert decide(source, "User::alice", "read", "File::report", n=3, stage="prod", region="eu-1") == "DENY"
    assert decide(source, "User::alice", "read", "File::report", n=9, stage="prod", region="us-1") == "DENY"
    assert decide(source, "User::bob", "read", "File::report", n=3, stage="prod", region="us-1") == "DENY"
    assert decide(source, "User::alice", "write", "File::secret") == "DENY"


def test_forbid_wins_over_permit():
    source, _ = convert('permit (principal, action == Action::"read", resource);\n'
                        'forbid (principal == User::"eve", action == Action::"read", resource);')
    assert decide(source, "User::bob", "read", "File::x") == "ALLOW"
    assert decide(source, "User::eve", "read", "File::x") == "DENY"


def test_cedar_error_semantics_for_missing_attributes_are_kept():
    # Cedar: `a || b` with `a` missing is an error, so the policy does not apply even though `b` is true
    source, _ = convert('permit (principal, action == Action::"read", resource) when { context.a == 1 || context.b == 2 };')
    assert decide(source, "U::x", "read", "R::x", b=2) == "DENY"
    assert decide(source, "U::x", "read", "R::x", a=1) == "ALLOW"
    assert decide(source, "U::x", "read", "R::x", a=0, b=2) == "ALLOW"          # a is false, so b decides
    assert decide(source, "U::x", "read", "R::x", a=0, b=0) == "DENY"


@pytest.mark.parametrize("cedar,construct", [
    ('permit (principal in Group::"g", action == Action::"a", resource);', "principal in"),
    ('permit (principal is User, action == Action::"a", resource);', "principal is"),
    ('permit (principal, action, resource);', "unconstrained action"),
    ('permit (principal, action == Action::"a", resource) when { principal.admin };', "expression"),
    ('permit (principal, action == Action::"a", resource) when { context.x + 1 == 2 };', "unexpected character"),
    ('permit (principal, action == Action::"a", resource) when { context.s like "a?b" };', "like pattern"),
    ('permit (principal, action == Action::"a", resource) when { context.s < "b" };', "ordering"),
    ('permit (principal, action == Action::"a", resource) when { context.a == context.b };', "operand"),
    ('permit (principal, action == Action::"a", resource) when { if true then true else false };', "expression"),
    ('allow (principal, action == Action::"a", resource);', "policy effect"),
])
def test_unsupported_constructs_are_refused_with_a_line(cedar, construct):
    with pytest.raises(ConversionError) as info:
        convert("\n" + cedar)
    assert construct in str(info.value) and info.value.line == 2


def test_all_actions_expands_an_unconstrained_action():
    source, mapping = convert('permit (principal, action, resource);', all_actions=["read", "write"])
    assert {m["action"] for m in mapping} == {"read", "write"}
    assert decide(source, "U::x", "write", "R::x") == "ALLOW"


def test_a_bad_string_cannot_break_out_of_the_generated_policy():
    with pytest.raises(ConversionError):
        convert('permit (principal == User::"a\\"b", action == Action::"read", resource);')


# ------------------------------------------------ differential test against an independent evaluator

ATTRS = {"n": "int", "stage": "text", "flag": "bool", "tag": "text"}


class Missing(Exception):
    pass


def need(c, name):
    if name not in c:
        raise Missing(name)
    return c[name]


def gen_expr(rng, depth=0):
    """Returns (cedar text, evaluator(context) -> bool); the evaluator follows Cedar: a missing attribute raises."""
    if depth < 2 and rng.random() < 0.55:
        kind = rng.choice(["and", "or", "not"])
        if kind == "not":
            t, f = gen_expr(rng, depth + 1)
            return f"!({t})", lambda c, f=f: not f(c)
        (t1, f1), (t2, f2) = gen_expr(rng, depth + 1), gen_expr(rng, depth + 1)
        if kind == "and":
            return f"({t1} && {t2})", lambda c, f1=f1, f2=f2: f1(c) and f2(c)       # short-circuit like Cedar
        return f"({t1} || {t2})", lambda c, f1=f1, f2=f2: f1(c) or f2(c)
    leaf = rng.choice(["n<", "n<=", "n==", "n>", "stage==", "stage!=", "flag==", "has", "like", "in"])
    if leaf.startswith("n"):
        op, v = leaf[1:], rng.randint(0, 4)
        fn = {"<": lambda a: a < v, "<=": lambda a: a <= v, "==": lambda a: a == v, ">": lambda a: a > v}[op]
        return f"context.n {op} {v}", lambda c, fn=fn: fn(need(c, "n"))
    if leaf.startswith("stage"):
        op, v = leaf[5:], rng.choice(["prod", "dev"])
        return f'context.stage {op} "{v}"', lambda c, op=op, v=v: (need(c, "stage") == v) == (op == "==")
    if leaf == "flag==":
        v = rng.choice([True, False])
        return f"context.flag == {str(v).lower()}", lambda c, v=v: need(c, "flag") == v
    if leaf == "has":
        name = rng.choice(list(ATTRS))
        return f"context has {name}", lambda c, name=name: name in c
    if leaf == "like":
        pat = rng.choice(["eu-*", "*-2", "*", "us-1"])
        return f'context.tag like "{pat}"', lambda c, pat=pat: fnmatch.fnmatchcase(need(c, "tag"), pat)
    values = rng.sample(["prod", "dev", "qa"], 2)
    return "[" + ", ".join(f'"{v}"' for v in values) + "].contains(context.stage)", lambda c, values=values: need(c, "stage") in values


def gen_policy(rng):
    effect = rng.choice(["permit", "permit", "forbid"])
    principal = rng.choice(["principal", 'principal == User::"alice"', 'principal == User::"bob"'])
    actions = rng.choice(['action == Action::"read"', 'action == Action::"write"', 'action in [Action::"read", Action::"write"]'])
    resource = rng.choice(["resource", 'resource == File::"a"', 'resource == File::"b"'])
    conditions, evaluators = [], []
    for _ in range(rng.randint(0, 2)):
        kind = rng.choice(["when", "unless"])
        text, fn = gen_expr(rng)
        conditions.append(f"{kind} {{ {text} }}")
        evaluators.append((kind, fn))
    text = f"{effect} ({principal}, {actions}, {resource}) " + " ".join(conditions) + ";"

    def entity(scope):
        return scope.split("== ")[1].replace('::"', "::").rstrip('"')

    def applies(actor, action, res, ctx):
        if principal != "principal" and actor != entity(principal):
            return False
        wanted = {"read", "write"} if "[" in actions else {actions.split('"')[1]}
        if action not in wanted:
            return False
        if resource != "resource" and res != entity(resource):
            return False
        try:
            for kind, fn in evaluators:
                if fn(ctx) != (kind == "when"):
                    return False
        except Missing:
            return False                                           # an error: the policy does not apply
        return True
    return effect, text, applies


def random_context(rng):
    ctx = {}
    if rng.random() < 0.7:
        ctx["n"] = rng.randint(0, 5)
    if rng.random() < 0.7:
        ctx["stage"] = rng.choice(["prod", "dev", "qa"])
    if rng.random() < 0.5:
        ctx["flag"] = rng.choice([True, False])
    if rng.random() < 0.6:
        ctx["tag"] = rng.choice(["eu-1", "us-2", "us-1", "ap-2"])
    return ctx


@pytest.mark.parametrize("seed", range(120))
def test_converted_policies_agree_with_an_independent_cedar_evaluator(seed):
    rng = random.Random(seed)
    policies = [gen_policy(rng) for _ in range(rng.randint(1, 4))]
    cedar_text = "\n".join(p[1] for p in policies)
    source, _ = convert(cedar_text)
    pdp = ReferencePDP(source)
    for _ in range(40):
        actor = rng.choice(["User::alice", "User::bob", "User::eve"])
        action = rng.choice(["read", "write"])
        res = rng.choice(["File::a", "File::b", "File::c"])
        ctx = random_context(rng)
        applicable = [effect for effect, _, applies in policies if applies(actor, action, res, ctx)]
        expected = "DENY" if "forbid" in applicable else ("ALLOW" if "permit" in applicable else "DENY")
        request = {"actor": actor, "action": action, "resource": res}
        if ctx:
            request["args"] = ctx
        got = pdp.check(request)["decision"]
        assert got == expected, (cedar_text, request, got, expected)


def test_cli_import_cedar(tmp_path, capsys):
    from yog_platform import cli
    src, out = tmp_path / "p.cedar", tmp_path / "p.yog"
    src.write_text(SIMPLE, encoding="utf-8")
    assert cli.main(["import-cedar", str(src), "-o", str(out)]) == 0
    assert out.read_text(encoding="utf-8").startswith("version 2")
    src.write_text('permit (principal in Group::"g", action == Action::"a", resource);', encoding="utf-8")
    assert cli.main(["import-cedar", str(src)]) == 1
    assert "principal in" in capsys.readouterr().err
