"""Schema-driven checks A009-A013 (see :mod:`yog_platform.analysis`)."""
from __future__ import annotations

_TEXT_BUILTINS = ("contains", "starts_with", "ends_with", "glob", "matches", "under", "cidr")


def _kind(value) -> str:
    return "bool" if isinstance(value, bool) else ("int" if isinstance(value, int) else "text")


def schema_checks(ref, program, schema, add) -> None:
    fields = schema.all_fields()
    for clause in program.clauses:
        head_tool = clause.head.args[1] if len(clause.head.args) > 1 else None
        tool_var = head_tool.name if isinstance(head_tool, ref.Var) else None
        scoped = None                                           # the one tool this clause is for, if it names one
        if isinstance(head_tool, ref.Const) and isinstance(head_tool.val, str):
            scoped = head_tool.val
            if scoped not in schema.tools and clause.kind != "rule":
                add("A013", clause.line, f"{clause.kind} clause is for tool {scoped!r}, which is not in the schema, "
                                         "so it can never match", "error")
        bound: dict = {}                                        # variable -> declared type of the field it holds
        for goal in clause.body:
            if isinstance(goal, ref.Obl):
                name, arity = goal.goal.pred, len(goal.goal.args)
                if name not in schema.obligations:
                    add("A012", goal.line, f"obligation {name!r} is not in the schema")
                elif schema.obligations[name] != arity:
                    add("A012", goal.line, f"obligation {name!r} takes {schema.obligations[name]} argument(s), not {arity}")
                continue
            target = goal.goal if isinstance(goal, ref.Neg) else goal
            line = getattr(target, "line", 0) or clause.line
            if isinstance(target, ref.Atom) and target.pred == "arg" and len(target.args) == 2 \
                    and isinstance(target.args[0], ref.Const) and isinstance(target.args[0].val, str):
                key = target.args[0].val
                if not key.startswith("input."):
                    continue
                name = key[len("input."):]
                if scoped in schema.tools:
                    candidates = dict(schema.tools[scoped]["args"])
                else:
                    candidates = {n: (next(iter(k)) if len(k) == 1 else "any") for n, k in fields.items()}
                if name not in candidates:
                    where = f"tool {scoped!r}" if scoped in schema.tools else "any tool"
                    add("A010", line, f"argument {name!r} is not declared by {where} in the schema")
                    continue
                declared = candidates[name]
                value = target.args[1]
                if isinstance(value, ref.Var):
                    bound[value.name] = declared
                elif declared != "any" and _kind(value.val) != declared:
                    add("A011", line, f"{key} is {declared} in the schema but is matched with a {_kind(value.val)} literal")
            elif isinstance(target, ref.Atom) and target.pred in _TEXT_BUILTINS and target.args \
                    and isinstance(target.args[0], ref.Var) and bound.get(target.args[0].name) in ("int", "bool"):
                add("A011", line, f"{target.pred} is applied to a {bound[target.args[0].name]} field")
            elif isinstance(target, ref.Cmp):
                for var, const in ((target.lhs, target.rhs), (target.rhs, target.lhs)):
                    if isinstance(var, ref.Var) and isinstance(const, ref.Const):
                        declared = bound.get(var.name)
                        if declared in ("text", "int", "bool") and _kind(const.val) != declared:
                            add("A011", line, f"a {declared} field is compared with a {_kind(const.val)} literal")
                        if var.name == tool_var and isinstance(const.val, str) and const.val not in schema.tools \
                                and target.op == "==":
                            add("A009", line, f"tool {const.val!r} is not in the schema")
            if isinstance(target, ref.Atom) and target.pred == "in" and target.args \
                    and isinstance(target.args[0], ref.Var) and target.args[0].name == tool_var:
                for name in target.args[1:]:
                    if isinstance(name, ref.Const) and isinstance(name.val, str) and name.val not in schema.tools:
                        add("A009", line, f"tool {name.val!r} is not in the schema")
