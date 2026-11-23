"""Shell command extractor.

Reports which programs a command line would run, dangerous flag combinations, pipes into a shell, command
substitution and the paths it touches.  The scanner understands single and double quotes, backslashes and
the operators ``; & && || | > >> <``.  Anything it cannot read cleanly (an unterminated quote, an
unterminated ``$(``) is reported as ``parsed: false`` so a policy can deny it.

It is deliberately conservative: constructs it does not model (here-docs, aliases, functions, ``eval``) are
surfaced as flags (``has_eval``, ``has_heredoc``) rather than silently ignored.
"""
from __future__ import annotations

import posixpath

_WRAPPERS = {"sudo", "doas", "env", "nohup", "time", "nice", "ionice", "xargs", "exec", "command", "timeout", "stdbuf", "setsid"}
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "python", "python3", "perl", "ruby", "node"}
_FETCHERS = {"curl", "wget", "fetch"}
_OPERATORS = (";", "&&", "||", "|&", "|", "&", ">>", ">", "<")


class _Unparseable(Exception):
    pass


def _scan(command: str):
    """Splits into words and operators.  Returns (tokens, flags) where a token is ('word', text) or ('op', text)."""
    tokens, i, n = [], 0, len(command)
    flags = {"subshell": False, "heredoc": False}
    word, in_word = [], False

    def flush():
        nonlocal word, in_word
        if in_word:
            tokens.append(("word", "".join(word)))
        word, in_word = [], False

    while i < n:
        c = command[i]
        if c in " \t\n\r":
            flush(); i += 1
        elif c == "\\":
            if i + 1 >= n:
                raise _Unparseable("trailing backslash")
            word.append(command[i + 1]); in_word = True; i += 2
        elif c == "'":
            j = command.find("'", i + 1)
            if j < 0:
                raise _Unparseable("unterminated quote")
            word.append(command[i + 1:j]); in_word = True; i = j + 1
        elif c == '"':
            j = i + 1
            while j < n and command[j] != '"':
                if command[j] == "\\" and j + 1 < n:
                    j += 1
                elif command[j] == "$" and command[j + 1:j + 2] == "(":
                    flags["subshell"] = True
                elif command[j] == "`":
                    flags["subshell"] = True
                word.append(command[j]); j += 1
            if j >= n:
                raise _Unparseable("unterminated quote")
            in_word = True; i = j + 1
        elif c == "$" and command[i + 1:i + 2] == "(":
            flags["subshell"] = True
            depth, j = 1, i + 2
            while j < n and depth:
                depth += (command[j] == "(") - (command[j] == ")")
                j += 1
            if depth:
                raise _Unparseable("unterminated $(")
            word.append(command[i:j]); in_word = True; i = j
        elif c == "`":
            flags["subshell"] = True
            j = command.find("`", i + 1)
            if j < 0:
                raise _Unparseable("unterminated backtick")
            word.append(command[i:j + 1]); in_word = True; i = j + 1
        elif command.startswith("<<", i):
            flags["heredoc"] = True
            flush(); tokens.append(("op", "<<")); i += 2
        else:
            op = next((o for o in _OPERATORS if command.startswith(o, i)), None)
            if op:
                flush(); tokens.append(("op", op)); i += len(op)
            else:
                word.append(c); in_word = True; i += 1
    flush()
    return tokens, flags


def _base(name: str) -> str:
    return posixpath.basename(name).lower()


def _normalise(path: str) -> str:
    absolute = path.startswith("/")
    out = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if out and out[-1] != "..":
                out.pop()
            elif not absolute:
                out.append("..")
            continue
        out.append(part)
    return ("/" if absolute else "") + "/".join(out) if (out or absolute) else "."


def _is_pathlike(word: str) -> bool:
    return word.startswith(("/", "./", "../", "~/")) or word in (".", "..", "~")


def extract(arguments: dict, field: str = "command") -> dict:
    command = arguments.get(field)
    if not isinstance(command, str) or not command.strip() or len(command) > 100_000:
        return {"shell": {"parsed": False}}
    try:
        tokens, flags = _scan(command)
    except _Unparseable:
        return {"shell": {"parsed": False}}

    # split into pipelines of simple commands
    commands, pipeline, simple, redirect = [], [], [], False
    has_redirect = False
    for kind, text in tokens:
        if kind == "word":
            if redirect:                 # the target of > >> < is a file, not an argument
                simple.append(("redirect", text)); redirect = False
            else:
                simple.append(("word", text))
            continue
        if text in (">", ">>", "<", "<<"):
            has_redirect = True; redirect = True; continue
        if simple:
            pipeline.append(simple); simple = []
        if text in ("|", "|&"):
            continue
        if pipeline:
            commands.append(pipeline); pipeline = []
    if simple:
        pipeline.append(simple)
    if pipeline:
        commands.append(pipeline)

    programs, all_flags, paths = [], [], []
    rm_rf = sudo = eval_used = pipe_to_shell = False
    for pipeline in commands:
        names = []
        for simple in pipeline:
            words = [t for k, t in simple if k == "word"]
            targets = [t for k, t in simple if k == "redirect"]
            paths += [_normalise(t) for t in targets if _is_pathlike(t)]
            idx = 0
            while idx < len(words) and (_base(words[idx]) in _WRAPPERS or "=" in words[idx].split("/")[0]):
                if _base(words[idx]) in ("sudo", "doas"):
                    sudo = True
                idx += 1
                if idx < len(words) and words[idx - 1] in ("timeout", "nice", "ionice") and not words[idx].startswith("-"):
                    idx += 1                                   # skip the numeric argument
                while idx < len(words) and words[idx].startswith("-") and _base(words[idx - 1]) in _WRAPPERS:
                    idx += 1
            if idx >= len(words):
                continue
            name = _base(words[idx])
            args = words[idx + 1:]
            names.append(name)
            programs.append(name)
            all_flags += [a for a in args if a.startswith("-") and a != "-"]
            paths += [_normalise(a) for a in args if _is_pathlike(a)]
            if name == "eval" or (name in _SHELLS and "-c" in args):
                eval_used = True          # the string it runs is not analysed: a policy should deny or ask
            if name == "rm":
                short = "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--"))
                longs = {a for a in args if a.startswith("--")}
                recursive = "r" in short.lower() or "--recursive" in longs
                force = "f" in short or "--force" in longs
                rm_rf = rm_rf or (recursive and force)
        if len(names) > 1 and names[-1] in _SHELLS and any(x in _FETCHERS for x in names[:-1]):
            pipe_to_shell = True

    return {"shell": {
        "parsed": True,
        "program": sorted(set(programs)),
        "flag": sorted(set(all_flags)),
        "path": sorted(set(paths)),
        "rm_rf": rm_rf,
        "sudo": sudo,
        "pipe_to_shell": pipe_to_shell,
        "has_subshell": flags["subshell"],
        "has_redirect": has_redirect,
        "has_eval": eval_used or any(p in ("eval",) for p in programs),
        "has_heredoc": flags["heredoc"],
        "command_count": len(programs),
    }}
