"""SQL extractor: what does this statement do, to which tables?

Not a full SQL parser.  It tokenizes (handling quotes and comments so nothing hides inside them), splits
statements, and reports the statement types, tables, whether there is a WHERE clause, and whether the
input contains several statements or comments.  Anything it cannot tokenize cleanly is reported as
``parsed: false`` so a policy can deny it instead of guessing.
"""
from __future__ import annotations

import re

_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*")
_STATEMENTS = {"select", "insert", "update", "delete", "drop", "truncate", "alter", "create", "grant",
               "revoke", "replace", "merge", "call", "exec", "execute", "pragma", "set", "show", "explain",
               "with", "begin", "commit", "rollback", "copy", "vacuum", "attach", "detach"}
_CLAUSE_END = {"where", "group", "order", "having", "limit", "offset", "union", "intersect", "except", "returning",
               "on", "using", "set", "values", "select", "window", "fetch", "for", "join", "inner", "left", "right",
               "full", "cross", "natural", "outer", "straight_join"}
_TABLE_AFTER = {"from", "join", "into", "update", "table", "truncate"}


class _Unparseable(Exception):
    pass


def _tokenize(sql: str):
    """Yields ('word', text) / ('quoted', text) / ('punct', char); sets flags for comments."""
    tokens, comments, i, n = [], False, 0, len(sql)
    while i < n:
        c = sql[i]
        if c.isspace():
            i += 1
        elif sql.startswith("--", i) or c == "#":
            comments = True
            j = sql.find("\n", i)
            i = n if j < 0 else j + 1
        elif sql.startswith("/*", i):
            comments = True
            j = sql.find("*/", i + 2)
            if j < 0:
                raise _Unparseable("unterminated comment")
            i = j + 2
        elif c in ("'", '"', "`"):
            j = i + 1
            while True:
                if j >= n:
                    raise _Unparseable("unterminated quote")
                if sql[j] == c:
                    if j + 1 < n and sql[j + 1] == c:        # doubled quote is an escape
                        j += 2
                        continue
                    break
                if sql[j] == "\\" and c == "'" and j + 1 < n:
                    j += 2
                    continue
                j += 1
            kind = "string" if c == "'" else "quoted"
            tokens.append((kind, sql[i + 1:j].replace(c + c, c)))
            i = j + 1
        elif c == "[":
            j = sql.find("]", i + 1)
            if j < 0:
                raise _Unparseable("unterminated bracket")
            tokens.append(("quoted", sql[i + 1:j]))
            i = j + 1
        else:
            m = _WORD.match(sql, i)
            if m:
                tokens.append(("word", m.group(0)))
                i = m.end()
            elif c.isdigit():
                j = i
                while j < n and (sql[j].isalnum() or sql[j] == "."):
                    j += 1
                tokens.append(("number", sql[i:j]))
                i = j
            else:
                tokens.append(("punct", c))
                i += 1
    return tokens, comments


def _name(tokens, i):
    """Reads a possibly schema-qualified name starting at i; returns (name, next_index) or (None, i)."""
    parts = []
    while i < len(tokens) and tokens[i][0] in ("word", "quoted"):
        parts.append(tokens[i][1].lower())
        if i + 1 < len(tokens) and tokens[i + 1] == ("punct", ".") and i + 2 < len(tokens):
            i += 2
            continue
        i += 1
        break
    return (".".join(parts), i) if parts else (None, i)


def inner_modifies(stmt) -> set:
    return {t[1].lower() for t in stmt if t[0] == "word"} & {"update", "delete"}


def extract(arguments: dict, field: str = "query") -> dict:
    sql = arguments.get(field)
    if not isinstance(sql, str) or not sql.strip() or len(sql) > 100_000:
        return {"sql": {"parsed": False}}
    try:
        tokens, comments = _tokenize(sql)
    except _Unparseable:
        return {"sql": {"parsed": False}}

    statements, current = [], []
    for token in tokens:
        if token == ("punct", ";"):
            if current:
                statements.append(current)
            current = []
        else:
            current.append(token)
    if current:
        statements.append(current)
    if not statements:
        return {"sql": {"parsed": False}}

    kinds, tables, has_where = [], [], []
    for stmt in statements:
        first = stmt[0][1].lower() if stmt[0][0] == "word" else "other"
        kind = first if first in _STATEMENTS else "other"
        kinds.append(kind)
        if kind == "with":
            # a data-modifying CTE (WITH x AS (DELETE ...)) must not hide behind the WITH keyword
            inner = {t[1].lower() for t in stmt if t[0] == "word"} & {"delete", "update", "insert", "drop", "truncate"}
            kinds.extend(sorted(inner))
        where = False
        depth = 0
        i = 0
        while i < len(stmt):
            kind_t, text = stmt[i]
            low = text.lower() if kind_t == "word" else ""
            if kind_t == "punct" and text == "(":
                depth += 1
            elif kind_t == "punct" and text == ")":
                depth -= 1
            if low == "where":
                where = True
            if low in _TABLE_AFTER:
                j = i + 1
                if low == "table" and j < len(stmt) and stmt[j][0] == "word" and stmt[j][1].lower() in ("if", "only"):
                    if stmt[j][1].lower() == "only":
                        j += 1
                    else:                                  # IF EXISTS / IF NOT EXISTS
                        j += 1
                        while j < len(stmt) and stmt[j][0] == "word" and stmt[j][1].lower() in ("not", "exists"):
                            j += 1
                if low == "truncate" and j < len(stmt) and stmt[j][0] == "word" and stmt[j][1].lower() == "table":
                    j += 1
                while True:
                    name, j = _name(stmt, j)
                    if name and name not in _CLAUSE_END:
                        tables.append(name)
                    if low != "from":
                        break
                    # skip an alias, then continue through a comma-separated FROM list
                    if j < len(stmt) and stmt[j][0] == "word" and stmt[j][1].lower() == "as":
                        j += 2
                    elif j < len(stmt) and stmt[j][0] == "word" and stmt[j][1].lower() not in _CLAUSE_END:
                        j += 1
                    if j < len(stmt) and stmt[j] == ("punct", ","):
                        j += 1
                        continue
                    break
            i += 1
        modifies = kind in ("update", "delete") or (kind == "with" and bool(inner_modifies(stmt)))
        has_where.append(where or not modifies)

    return {"sql": {
        "parsed": True,
        "statement": sorted(set(kinds)),
        "statement_count": len(statements),
        "table": sorted(set(tables)),
        # True when every UPDATE/DELETE statement has a WHERE clause (vacuously true when there is none)
        "has_where": all(has_where),
        "has_comment": comments,
    }}
