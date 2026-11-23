"""Canonical formatter for YOG policies.

Conservative by design: it changes only whitespace, never tokens, and keeps every comment.  Rules:

* LF line endings, no trailing whitespace, one trailing newline, no leading blank lines, at most one
  consecutive blank line;
* clause bodies are indented four spaces;
* no space after ``(`` or before ``)`` or ``,``; one space after ``,``; no space before ``:``;
* comparison operators have one space on each side;
* a trailing comment is separated from code by two spaces.

``format_source`` is idempotent, and :func:`same_meaning` confirms (via the reference parser) that formatting
did not change the program.
"""
from __future__ import annotations

import re

_OPERATORS = ("<=", ">=", "==", "!=", "<", ">")


def _split_code_and_comment(line: str):
    """Returns (code, comment) honouring quotes; comment includes the leading '#'."""
    in_string = False
    for i, c in enumerate(line):
        if c == '"':
            in_string = not in_string
        elif c == "#" and not in_string:
            return line[:i], line[i:]
    return line, ""


def _format_code(code: str) -> str:
    """Normalises spacing in one line of code, leaving string literals untouched."""
    # split into alternating code / string-literal pieces
    pieces, current, in_string = [], [], False
    for c in code:
        if c == '"':
            if in_string:
                current.append(c)
                pieces.append((True, "".join(current)))
                current = []
            else:
                if current:
                    pieces.append((False, "".join(current)))
                current = [c]
            in_string = not in_string
        else:
            current.append(c)
    if current:
        pieces.append((in_string, "".join(current)))

    out = []
    for is_string, text in pieces:
        if not is_string:
            text = re.sub(r"[ \t]+", " ", text)
            text = re.sub(r"\s*(<=|>=|==|!=|<|>)\s*", r" \1 ", text)
            text = re.sub(r"\(\s+", "(", text)
            text = re.sub(r"\s+\)", ")", text)
            text = re.sub(r"\s+,", ",", text)
            text = re.sub(r"\s+:", ":", text)
        out.append((is_string, text))

    # commas: exactly one space after, none before; applied across piece boundaries
    joined = "".join(text for _, text in out)
    result = []
    in_string = False
    for i, c in enumerate(joined):
        if c == '"':
            in_string = not in_string
        result.append(c)
        if c == "," and not in_string:
            j = i + 1
            if j < len(joined) and joined[j] not in " \t":
                result.append(" ")
    text = "".join(result)
    text = re.sub(r",[ \t]{2,}(?=[^ \t])", ", ", text) if '"' not in text else text
    return text.strip()


def format_source(source: str) -> str:
    lines = source.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out: list[str] = []
    in_body = False
    for raw in lines:
        stripped = raw.strip()
        if not stripped:
            if out and out[-1] != "":
                out.append("")
            continue
        code, comment = _split_code_and_comment(raw)
        indented = raw[:1] in (" ", "\t")
        if not code.strip():                                   # a comment-only line
            out.append(("    " if indented and in_body else "") + comment.rstrip())
            continue
        text = _format_code(code)
        if comment:
            text += "  " + comment.rstrip()
        if indented:
            out.append("    " + text)
        else:
            out.append(text)
            in_body = code.rstrip().endswith(":")
    while out and out[-1] == "":
        out.pop()
    return "\n".join(out) + "\n" if out else ""


def same_meaning(before: str, after: str) -> bool:
    """True when both sources parse to the same program (comments and whitespace aside)."""
    import os
    import sys
    reference = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reference")
    if reference not in sys.path:
        sys.path.insert(0, reference)
    import yog_ref

    def shape(text):
        program = yog_ref.Parser(yog_ref.tokenize(text)).parse()
        # the parser numbers each `_` wildcard (_G1, _G2, ...); those numbers differ between parses
        plain = lambda value: re.sub(r"_G\d+", "_", repr(value))
        return (program.version, [plain(f) for f in program.facts], sorted(program.inputs.items()),
                [(c.kind, plain(c.head), [plain(g) for g in c.body]) for c in program.clauses],
                [plain(q) for q in program.queries])

    return shape(before) == shape(after)
