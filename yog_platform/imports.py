"""Import expansion for multi-file policies.

``import "other.yog"`` (at the start of a line) is replaced by the contents of that file.  This is done by
the loader, not the engine, so the C core stays free of file access.  Rules:

* paths are relative to the importing file and use ``/``;
* absolute paths, ``..`` segments that leave the bundle, and backslashes are rejected;
* cycles are rejected, each file is included at most once, and depth/size are capped;
* ``source_map[i]`` gives ``(file, line)`` for line ``i`` of the expanded text, so an engine error that
  names a line can be mapped back to the file the author wrote.
"""
from __future__ import annotations

import posixpath
import re
from typing import Mapping

MAX_DEPTH = 8
MAX_FILES = 64
MAX_TOTAL_BYTES = 1 << 20

_IMPORT = re.compile(r'^import\s+"([^"\n]*)"\s*(#.*)?$')


class ImportError_(Exception):
    pass


def _resolve(base: str, target: str) -> str:
    if not target or target.startswith("/") or "\\" in target or "\x00" in target:
        raise ImportError_(f"bad import path {target!r}")
    joined = posixpath.normpath(posixpath.join(posixpath.dirname(base), target))
    if joined.startswith("..") or joined == ".":
        raise ImportError_(f"import {target!r} leaves the policy directory")
    return joined


def expand_imports(files: Mapping[str, str], entry: str):
    """Returns ``(expanded_text, source_map)``."""
    out: list[str] = []
    source_map: list[tuple[str, int]] = []
    done: set[str] = set()
    total = [0]

    def visit(name: str, stack: tuple) -> None:
        if name in stack:
            raise ImportError_("import cycle: " + " -> ".join(stack + (name,)))
        if len(stack) >= MAX_DEPTH:
            raise ImportError_(f"imports are nested more than {MAX_DEPTH} deep")
        if name in done:
            return
        if name not in files:
            raise ImportError_(f"imported file {name!r} is not in the bundle")
        if len(done) >= MAX_FILES:
            raise ImportError_(f"more than {MAX_FILES} files")
        done.add(name)
        for number, line in enumerate(files[name].splitlines(), 1):
            match = _IMPORT.match(line)
            if match:
                visit(_resolve(name, match.group(1)), stack + (name,))
                continue
            total[0] += len(line) + 1
            if total[0] > MAX_TOTAL_BYTES:
                raise ImportError_("policy is larger than 1 MiB after expanding imports")
            out.append(line)
            source_map.append((name, number))

    visit(entry, ())
    return "\n".join(out) + "\n", source_map
