"""A schema for the tools an agent may call: their argument names and types, and the obligations a policy may use.

::

    {"tools": {"read_file": {"args": {"path": "text"}, "required": ["path"]},
               "Bash":      {"args": {"command": "text"}, "required": ["command"]}},
     "obligations": {"audit": 1, "rate_limit": 2},
     "env": {"stage": "text"}}

Types are ``text``, ``int``, ``bool`` and ``any``.  The gateway refuses a call whose tool is not listed, that
has an argument the schema does not know, that misses a required argument, or whose value has the wrong type;
the static analysis (codes A009-A013) uses the same schema to find clauses that can never match.
"""
from __future__ import annotations

import json
from typing import Optional

TYPES = ("text", "int", "bool", "any")


class SchemaError(Exception):
    pass


def _type_ok(kind: str, value) -> bool:
    if kind == "any":
        return True
    if kind == "bool":
        return isinstance(value, bool)
    if kind == "int":
        return isinstance(value, int) and not isinstance(value, bool)
    return isinstance(value, str)


class Schema:
    def __init__(self, document: dict):
        if not isinstance(document, dict):
            raise SchemaError("a schema is a JSON object")
        unknown = set(document) - {"tools", "obligations", "env"}
        if unknown:
            raise SchemaError(f"unknown schema section(s): {sorted(unknown)}")
        self.tools: dict = {}
        for name, spec in (document.get("tools") or {}).items():
            if not isinstance(spec, dict):
                raise SchemaError(f"tool {name!r}: expected an object")
            args = spec.get("args", {})
            for field, kind in args.items():
                if kind not in TYPES:
                    raise SchemaError(f"tool {name!r}, argument {field!r}: type must be one of {TYPES}")
            required = list(spec.get("required", []))
            missing = [r for r in required if r not in args]
            if missing:
                raise SchemaError(f"tool {name!r}: required argument(s) {missing} are not declared")
            self.tools[name] = {"args": dict(args), "required": required}
        self.obligations: dict = dict(document.get("obligations") or {})
        for name, arity in self.obligations.items():
            if not isinstance(arity, int) or isinstance(arity, bool) or arity < 0:
                raise SchemaError(f"obligation {name!r}: arity must be a non-negative integer")
        self.env: dict = dict(document.get("env") or {})
        for key, kind in self.env.items():
            if kind not in TYPES:
                raise SchemaError(f"env {key!r}: type must be one of {TYPES}")

    @classmethod
    def load(cls, path: str) -> "Schema":
        with open(path, encoding="utf-8") as handle:
            return cls(json.load(handle))

    def all_fields(self) -> dict:
        """field name -> set of declared types, across every tool."""
        out: dict = {}
        for spec in self.tools.values():
            for field, kind in spec["args"].items():
                out.setdefault(field, set()).add(kind)
        return out

    def validate_call(self, tool: str, arguments: dict) -> list:
        """Problems with one tool call; an empty list means it conforms."""
        spec: Optional[dict] = self.tools.get(tool)
        if spec is None:
            return [f"unknown tool {tool!r}"]
        problems = []
        for field, value in arguments.items():
            kind = spec["args"].get(field)
            if kind is None:
                problems.append(f"unknown argument {field!r}")
            elif not _type_ok(kind, value):
                problems.append(f"argument {field!r} must be {kind}")
        problems += [f"missing required argument {f!r}" for f in spec["required"] if f not in arguments]
        return problems
